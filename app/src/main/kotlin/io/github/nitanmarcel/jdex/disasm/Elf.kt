package io.github.nitanmarcel.jdex.disasm

import java.nio.ByteBuffer
import java.nio.ByteOrder

enum class ElfArch(val display: String) {
    ARM("ARM"),
    ARM64("AArch64"),
    X86("x86"),
    X86_64("x86-64"),
    MIPS("MIPS"),
    MIPS64("MIPS64"),
    UNKNOWN("unknown"),
}

class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val entsize: Long = 0,
) {
    val isExecutable get() = flags and 0x4L != 0L
    val hasBits get() = type != 8
}

class ElfSymbol(val name: String, val address: Long, val thumb: Boolean)

class ElfFile(
    val arch: ElfArch,
    val is64: Boolean,
    val littleEndian: Boolean,
    val entry: Long,
    val sections: List<ElfSection>,
    val functions: List<ElfSymbol>,
    val relocs: Map<Long, String>,
    private val armMap: LongArray,
    private val armMapKind: IntArray,
    val maxVtableOffset: Long,
    private val relocPtrs: Map<Long, Long>,
    private val bytes: ByteArray,
) {
    val textSections get() = sections.filter { it.isExecutable && it.hasBits && it.size > 0 }

    val dataSections get() = sections.filter {
        !it.isExecutable && it.hasBits && it.size > 0 && (
            it.name.startsWith(".rodata") || it.name.startsWith(".data") || it.name.startsWith(".got") ||
                it.name == ".init_array" || it.name == ".fini_array" || it.name == ".dynstr" ||
                it.name.startsWith(".eh_frame"))
    }

    fun relocatedPointerAt(vaddr: Long): Long? {
        relocPtrs[vaddr]?.let { return it }
        val v = if (is64) readLong(vaddr) else readInt(vaddr)?.toLong()?.and(0xFFFFFFFFL)
        return v?.takeIf { it != 0L }
    }

    fun relocatedPointers(): Map<Long, Long> = relocPtrs

    class MipsGpRef(val localAddr: Long?, val symbol: String?)

    private class MipsGot(
        val gotAddr: Long, val gp: Long, val gotEnd: Long, val ptr: Int,
        val localGotno: Long, val gotsym: Long, val symtab: Long, val strtab: Long, val syment: Long, val symCount: Long,
    )

    private val mipsGot: MipsGot? by lazy {
        if (arch != ElfArch.MIPS && arch != ElfArch.MIPS64) return@lazy null
        val dyn = sections.firstOrNull { it.name == ".dynamic" } ?: return@lazy null
        val tags = HashMap<Long, Long>()
        val step = if (is64) 16 else 8
        var a = dyn.addr; val end = dyn.addr + dyn.size
        while (a < end) {
            val tag = if (is64) readLong(a) else readInt(a)?.toLong()?.and(0xFFFFFFFFL)
            val v = if (is64) readLong(a + 8) else readInt(a + 4)?.toLong()?.and(0xFFFFFFFFL)
            if (tag == null || v == null || tag == 0L) break
            tags[tag] = v; a += step
        }
        val got = tags[3L] ?: sections.firstOrNull { it.name == ".got" }?.addr ?: return@lazy null
        val localGotno = tags[0x7000000aL] ?: return@lazy null
        val gotsym = tags[0x70000013L] ?: return@lazy null
        val symtab = tags[6L] ?: return@lazy null
        val strtab = tags[5L] ?: return@lazy null
        val ptr = if (is64) 8 else 4
        val syment = tags[11L] ?: (if (is64) 24L else 16L)
        val symCount = tags[0x70000011L] ?: Long.MAX_VALUE
        val gotSize = sections.firstOrNull { it.name == ".got" }?.size
            ?: ((localGotno + (if (symCount == Long.MAX_VALUE) 0 else symCount - gotsym)) * ptr)
        MipsGot(got, got + 0x7ff0, got + gotSize, ptr, localGotno, gotsym, symtab, strtab, syment, symCount)
    }

    class Dynamic(val needed: List<String>, val soname: String?)

    fun dynamic(): Dynamic = runCatching {
        val dyn = sections.firstOrNull { it.name == ".dynamic" && it.size > 0 } ?: return Dynamic(emptyList(), null)
        val dynstr = sections.firstOrNull { it.name == ".dynstr" } ?: return Dynamic(emptyList(), null)
        val ptr = if (is64) 8 else 4
        val needed = ArrayList<String>()
        var soname: String? = null
        var off = 0L
        while (off + 2 * ptr <= dyn.size) {
            val tag = (if (is64) readLong(dyn.addr + off) else readInt(dyn.addr + off)?.toLong()?.and(0xFFFFFFFFL)) ?: break
            val v = (if (is64) readLong(dyn.addr + off + ptr) else readInt(dyn.addr + off + ptr)?.toLong()?.and(0xFFFFFFFFL)) ?: break
            if (tag == 0L) break
            when (tag) {
                1L -> cStringAt(dynstr.addr + v)?.let { needed.add(it) }
                14L -> soname = cStringAt(dynstr.addr + v)
            }
            off += 2 * ptr
        }
        Dynamic(needed, soname)
    }.getOrDefault(Dynamic(emptyList(), null))

    fun mipsGpTarget(off: Long): MipsGpRef? {
        val g = mipsGot ?: return null
        val addr = g.gp + off
        if (addr < g.gotAddr || addr >= g.gotEnd || (addr - g.gotAddr) % g.ptr != 0L) return null
        val idx = (addr - g.gotAddr) / g.ptr
        if (idx < g.localGotno) {
            val v = if (is64) readLong(addr) else readInt(addr)?.toLong()?.and(0xFFFFFFFFL)
            return v?.takeIf { it != 0L }?.let { MipsGpRef(it, null) }
        }
        val di = g.gotsym + (idx - g.localGotno)
        if (di < 0 || di >= g.symCount) return null
        val nameOff = readInt(g.symtab + di * g.syment)?.toLong()?.and(0xFFFFFFFFL) ?: return null
        val name = stringAt(g.strtab + nameOff)?.takeIf { it.isNotEmpty() } ?: return null
        return MipsGpRef(null, name)
    }

    private fun mapFloor(addr: Long): Int {
        if (armMap.isEmpty()) return -1
        var lo = 0; var hi = armMap.size - 1; var idx = -1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            if (armMap[mid] <= addr) { idx = mid; lo = mid + 1 } else hi = mid - 1
        }
        return idx
    }

    var defaultThumb: Boolean = true

    fun armThumbAt(addr: Long): Boolean {
        val idx = mapFloor(addr)
        return if (idx < 0) defaultThumb else armMapKind[idx] == MAP_THUMB
    }

    fun dataRegionEnd(addr: Long): Long? {
        val idx = mapFloor(addr)
        if (idx < 0 || armMapKind[idx] != MAP_DATA) return null
        return if (idx + 1 < armMap.size) armMap[idx + 1] else Long.MAX_VALUE
    }

    private val order = if (littleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN

    private fun fileOffset(vaddr: Long, size: Int): Int? {
        val sec = sections.firstOrNull { it.hasBits && it.size > 0 && vaddr >= it.addr && vaddr + size <= it.addr + it.size } ?: return null
        val off = (sec.offset + (vaddr - sec.addr)).toInt()
        return if (off >= 0 && off + size <= bytes.size) off else null
    }

    fun readByte(vaddr: Long): Int? = fileOffset(vaddr, 1)?.let { bytes[it].toInt() and 0xFF }

    fun readShort(vaddr: Long): Int? = fileOffset(vaddr, 2)?.let { ByteBuffer.wrap(bytes).order(order).getShort(it).toInt() and 0xFFFF }

    fun readInt(vaddr: Long): Int? = fileOffset(vaddr, 4)?.let { ByteBuffer.wrap(bytes).order(order).getInt(it) }

    fun readLong(vaddr: Long): Long? = fileOffset(vaddr, 8)?.let { ByteBuffer.wrap(bytes).order(order).getLong(it) }

    fun sectionBytes(section: ElfSection): ByteArray {
        if (!section.hasBits) return ByteArray(section.size.toInt().coerceAtLeast(0))
        val start = section.offset.toInt().coerceIn(0, bytes.size)
        val end = (section.offset + section.size).toInt().coerceIn(start, bytes.size)
        return bytes.copyOfRange(start, end)
    }

    fun stringAt(vaddr: Long): String? {
        val sec = sections.firstOrNull { it.hasBits && it.size > 0 && vaddr >= it.addr && vaddr < it.addr + it.size } ?: return null
        var i = (sec.offset + (vaddr - sec.addr)).toInt()
        val end = (sec.offset + sec.size).toInt().coerceAtMost(bytes.size)
        if (i < 0 || i >= end) return null
        val sb = StringBuilder()
        while (i < end && sb.length < 64) {
            val c = bytes[i].toInt() and 0xFF
            if (c == 0) break
            if (c < 0x20 || c > 0x7E) return null
            sb.append(c.toChar()); i++
        }
        return if (sb.length >= 3) sb.toString() else null
    }

    fun cStringAt(vaddr: Long, max: Int = 255): String? {
        val sec = sections.firstOrNull { it.hasBits && it.size > 0 && vaddr >= it.addr && vaddr < it.addr + it.size } ?: return null
        var i = (sec.offset + (vaddr - sec.addr)).toInt()
        val end = (sec.offset + sec.size).toInt().coerceAtMost(bytes.size)
        if (i < 0 || i >= end) return null
        val sb = StringBuilder()
        while (i < end && sb.length < max) {
            val c = bytes[i].toInt() and 0xFF
            if (c == 0) return sb.toString()
            if (c < 0x20 || c > 0x7E) return null
            sb.append(c.toChar()); i++
        }
        return null
    }

    companion object {
        private const val SHT_SYMTAB = 2
        private const val SHT_DYNSYM = 11
        private const val STT_FUNC = 2
        const val MAP_ARM = 0
        const val MAP_THUMB = 1
        const val MAP_DATA = 2
        private const val SHT_ANDROID_REL = 0x60000001
        private const val SHT_ANDROID_RELA = 0x60000002
        private const val SHT_RELR = 19

        private const val GROUPED_BY_INFO = 1L
        private const val GROUPED_BY_OFFSET_DELTA = 2L
        private const val GROUPED_BY_ADDEND = 4L
        private const val GROUP_HAS_ADDEND = 8L

        internal fun parsePackedRelocs(bytes: ByteArray, start: Int, size: Int, is64: Boolean, emit: (Long, Int, Long) -> Unit) {
            if (size < 4 || start < 0 || start + size > bytes.size) return
            if (bytes[start] != 'A'.code.toByte() || bytes[start + 1] != 'P'.code.toByte() ||
                bytes[start + 2] != 'S'.code.toByte() || bytes[start + 3] != '2'.code.toByte()
            ) return
            val end = start + size
            var pos = start + 4
            fun sleb(): Long {
                var result = 0L; var shift = 0; var b: Int
                do {
                    if (pos >= end) return result
                    b = bytes[pos++].toInt() and 0xFF
                    result = result or ((b.toLong() and 0x7F) shl shift)
                    shift += 7
                } while (b and 0x80 != 0)
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                return result
            }
            var remaining = sleb()
            var offset = sleb()
            var addend = 0L
            while (remaining > 0 && pos < end) {
                val groupSize = sleb()
                val groupFlags = sleb()
                val groupedByOffset = groupFlags and GROUPED_BY_OFFSET_DELTA != 0L
                val groupedByInfo = groupFlags and GROUPED_BY_INFO != 0L
                val hasAddend = groupFlags and GROUP_HAS_ADDEND != 0L
                val groupedByAddend = groupFlags and GROUPED_BY_ADDEND != 0L
                val groupOffsetDelta = if (groupedByOffset) sleb() else 0L
                var groupInfo = if (groupedByInfo) sleb() else 0L
                if (hasAddend && groupedByAddend) addend += sleb()
                var i = 0L
                while (i < groupSize && remaining > 0) {
                    offset += if (groupedByOffset) groupOffsetDelta else sleb()
                    val info = if (groupedByInfo) groupInfo else sleb()
                    if (hasAddend && !groupedByAddend) addend += sleb()
                    val symIdx = if (is64) (info ushr 32).toInt() else (info ushr 8).toInt()
                    emit(offset, symIdx, addend)
                    i++; remaining--
                }
            }
        }

        internal fun parseRelr(bytes: ByteArray, start: Int, size: Int, little: Boolean, emit: (Long) -> Unit) {
            val buf = ByteBuffer.wrap(bytes).order(if (little) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)
            var b = start; val end = start + size
            var where = 0L
            while (b + 8 <= end && b + 8 <= bytes.size) {
                val e = buf.getLong(b); b += 8
                if (e and 1L == 0L) { where = e; emit(where); where += 8 }
                else {
                    var bits = e ushr 1
                    var p = where
                    while (bits != 0L) { if (bits and 1L != 0L) emit(p); bits = bits ushr 1; p += 8 }
                    where += 63 * 8
                }
            }
        }

        fun parse(bytes: ByteArray): ElfFile? {
            if (bytes.size < 64) return null
            if (bytes[0] != 0x7F.toByte() || bytes[1] != 'E'.code.toByte() ||
                bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
            ) return null

            val is64 = bytes[4].toInt() == 2
            val little = bytes[5].toInt() == 1
            val buf = ByteBuffer.wrap(bytes).order(if (little) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)

            val machine = buf.getShort(18).toInt() and 0xFFFF
            val arch = when (machine) {
                40 -> ElfArch.ARM
                183 -> ElfArch.ARM64
                3 -> ElfArch.X86
                62 -> ElfArch.X86_64
                8 -> if (is64) ElfArch.MIPS64 else ElfArch.MIPS
                else -> ElfArch.UNKNOWN
            }

            fun addr(off: Int): Long = if (is64) buf.getLong(off) else buf.getInt(off).toLong() and 0xFFFFFFFFL
            fun u32(off: Int): Int = buf.getInt(off)
            fun u16(off: Int): Int = buf.getShort(off).toInt() and 0xFFFF

            val entry = addr(24)
            val shoff = if (is64) buf.getLong(40) else (buf.getInt(32).toLong() and 0xFFFFFFFFL)
            val shentsize = u16(if (is64) 58 else 46)
            val shnum = u16(if (is64) 60 else 48)
            val shstrndx = u16(if (is64) 62 else 50)
            if (shoff <= 0 || shnum == 0) return ElfFile(arch, is64, little, entry, emptyList(), emptyList(), emptyMap(), LongArray(0), IntArray(0), 0L, emptyMap(), bytes)

            data class Raw(val nameOff: Int, val type: Int, val flags: Long, val addr: Long, val offset: Long, val size: Long, val link: Int, val entsize: Long)
            val raws = ArrayList<Raw>(shnum)
            for (i in 0 until shnum) {
                val b = (shoff + i.toLong() * shentsize).toInt()
                if (b + shentsize > bytes.size) break
                if (is64) raws.add(Raw(u32(b), u32(b + 4), buf.getLong(b + 8), buf.getLong(b + 16), buf.getLong(b + 24), buf.getLong(b + 32), u32(b + 40), buf.getLong(b + 56)))
                else raws.add(Raw(u32(b), u32(b + 4), u32(b + 8).toLong() and 0xFFFFFFFFL, addr(b + 12), buf.getInt(b + 16).toLong() and 0xFFFFFFFFL, buf.getInt(b + 20).toLong() and 0xFFFFFFFFL, u32(b + 24), buf.getInt(b + 36).toLong() and 0xFFFFFFFFL))
            }

            fun stringAt(tableOff: Long, tableSize: Long, strOff: Int): String {
                val start = (tableOff + strOff).toInt()
                if (strOff < 0 || start < 0 || start >= bytes.size || strOff >= tableSize) return ""
                var end = start
                while (end < bytes.size && bytes[end].toInt() != 0) end++
                return String(bytes, start, end - start, Charsets.UTF_8)
            }

            val shstr = raws.getOrNull(shstrndx)
            val sections = raws.map {
                val nm = if (shstr != null) stringAt(shstr.offset, shstr.size, it.nameOff) else ""
                ElfSection(nm, it.type, it.flags, it.addr, it.offset, it.size, it.entsize)
            }

            val functions = ArrayList<ElfSymbol>()
            val seen = HashSet<Long>()
            val mapping = ArrayList<Pair<Long, Int>>()
            val wantsMapping = arch == ElfArch.ARM || arch == ElfArch.ARM64
            for (i in raws.indices) {
                val sec = raws[i]
                if (sec.type != SHT_SYMTAB && sec.type != SHT_DYNSYM) continue
                val str = raws.getOrNull(sec.link) ?: continue
                val entsize = if (sec.entsize > 0) sec.entsize.toInt() else if (is64) 24 else 16
                val count = (sec.size / entsize).toInt()
                for (s in 0 until count) {
                    val b = (sec.offset + s.toLong() * entsize).toInt()
                    if (b + entsize > bytes.size) break
                    val nameOff: Int; val value: Long; val info: Int
                    if (is64) {
                        nameOff = u32(b); info = bytes[b + 4].toInt() and 0xFF; value = buf.getLong(b + 8)
                    } else {
                        nameOff = u32(b); value = addr(b + 4); info = bytes[b + 12].toInt() and 0xFF
                    }
                    if (wantsMapping && (info and 0xF) == 0 && value != 0L) {
                        val nm = stringAt(str.offset, str.size, nameOff)
                        val a = value and 1L.inv()
                        when {
                            nm.startsWith("\$t") -> mapping.add(a to MAP_THUMB)
                            nm.startsWith("\$a") || nm.startsWith("\$x") -> mapping.add(a to MAP_ARM)
                            nm.startsWith("\$d") -> mapping.add(a to MAP_DATA)
                        }
                    }
                    if (info and 0xF != STT_FUNC || value == 0L) continue
                    val nm = stringAt(str.offset, str.size, nameOff)
                    val thumb = arch == ElfArch.ARM && value and 1L == 1L
                    val address = if (thumb) value and 1L.inv() else value
                    if (arch == ElfArch.ARM) mapping.add(address to if (thumb) MAP_THUMB else MAP_ARM)
                    if (nm.isEmpty() || !seen.add(address)) continue
                    functions.add(ElfSymbol(nm, address, thumb))
                }
            }
            functions.sortBy { it.address }
            mapping.sortBy { it.first }
            val armMap = LongArray(mapping.size) { mapping[it].first }
            val armMapKind = IntArray(mapping.size) { mapping[it].second }

            val relocs = HashMap<Long, String>()
            fun symEntry(symtab: Raw, idx: Int): Int {
                val ent = if (symtab.entsize > 0) symtab.entsize.toInt() else if (is64) 24 else 16
                return (symtab.offset + idx.toLong() * ent).toInt()
            }
            fun symName(symtab: Raw, idx: Int): String {
                val str = raws.getOrNull(symtab.link) ?: return ""
                val b = symEntry(symtab, idx)
                if (idx <= 0 || b + 4 > bytes.size) return ""
                return stringAt(str.offset, str.size, u32(b))
            }
            fun symValue(symtab: Raw, idx: Int): Long {
                val b = symEntry(symtab, idx)
                return if (idx <= 0 || b + (if (is64) 16 else 8) > bytes.size) 0L
                else if (is64) buf.getLong(b + 8) else (u32(b + 4).toLong() and 0xFFFFFFFFL)
            }
            val ro = sections.filter { it.name == ".data.rel.ro" || it.name == ".data.rel.ro.local" }
            val exec = sections.filter { it.isExecutable && it.hasBits && it.size > 0 }
            fun inRo(a: Long) = ro.any { a >= it.addr && a < it.addr + it.size }
            fun inExec(a: Long) = exec.any { a >= it.addr && a < it.addr + it.size }
            fun relTarget(symtab: Raw, symIdx: Int, addend: Long) = if (symIdx == 0) addend else symValue(symtab, symIdx) + addend
            val vtSlots = ArrayList<Long>()
            val relocPtrs = HashMap<Long, Long>()
            for (sec in raws) {
                val rela = sec.type == 4
                val packed = sec.type == SHT_ANDROID_RELA || sec.type == SHT_ANDROID_REL
                if (!rela && sec.type != 9 && !packed) continue
                val symtab = raws.getOrNull(sec.link) ?: continue
                if (packed) {
                    parsePackedRelocs(bytes, sec.offset.toInt(), sec.size.toInt(), is64) { rOffset, symIdx, addend ->
                        if (symIdx != 0) symName(symtab, symIdx).takeIf { it.isNotEmpty() }?.let { relocs[rOffset] = it }
                        val target = relTarget(symtab, symIdx, addend)
                        if (target != 0L) relocPtrs[rOffset] = target
                        if (ro.isNotEmpty() && inRo(rOffset) && inExec(target)) vtSlots.add(rOffset)
                    }
                    continue
                }
                val recSize = if (is64) (if (rela) 24 else 16) else (if (rela) 12 else 8)
                if (recSize <= 0) continue
                val count = (sec.size / recSize).toInt()
                for (j in 0 until count) {
                    val b = (sec.offset + j.toLong() * recSize).toInt()
                    if (b + recSize > bytes.size) break
                    val rOffset = addr(b)
                    val rInfo = if (is64) buf.getLong(b + 8) else (u32(b + 4).toLong() and 0xFFFFFFFFL)
                    val symIdx = if (is64) (rInfo ushr 32).toInt() else (rInfo ushr 8).toInt()
                    val rAddend = if (rela) addr(b + (if (is64) 16 else 8)) else 0L
                    val target = if (symIdx == 0) rAddend else symValue(symtab, symIdx) + rAddend
                    if (target != 0L) relocPtrs[rOffset] = target
                    if (ro.isNotEmpty() && inRo(rOffset) && inExec(target)) vtSlots.add(rOffset)
                    if (symIdx == 0) continue
                    val nm = symName(symtab, symIdx)
                    if (nm.isNotEmpty()) relocs[rOffset] = nm
                }
            }
            if (is64 && ro.isNotEmpty()) {
                fun roSlotValue(vaddr: Long): Long? {
                    val sec = ro.firstOrNull { vaddr >= it.addr && vaddr < it.addr + it.size } ?: return null
                    val fo = (sec.offset + (vaddr - sec.addr)).toInt()
                    return if (fo < 0 || fo + 8 > bytes.size) null else buf.getLong(fo)
                }
                for (sec in raws) {
                    if (sec.type != SHT_RELR) continue
                    parseRelr(bytes, sec.offset.toInt(), sec.size.toInt(), little) { vaddr ->
                        roSlotValue(vaddr)?.let { v ->
                            if (v != 0L) relocPtrs[vaddr] = v
                            if (inExec(v)) vtSlots.add(vaddr)
                        }
                    }
                }
            }
            var maxVtableOffset = 0L
            if (vtSlots.isNotEmpty()) {
                vtSlots.sort()
                var run = 1
                for (i in 1 until vtSlots.size) {
                    if (vtSlots[i] == vtSlots[i - 1] + 8) run++ else run = 1
                    if ((run - 1) * 8L > maxVtableOffset) maxVtableOffset = (run - 1) * 8L
                }
            }

            return ElfFile(arch, is64, little, entry, sections, functions, relocs, armMap, armMapKind, maxVtableOffset, relocPtrs, bytes)
        }
    }
}
