package io.github.nitanmarcel.jdex.disasm

import java.nio.ByteBuffer
import java.nio.ByteOrder

object NativeFunctions {

    private val PLT_SECS = setOf(".plt", ".iplt", ".plt.sec", ".plt.got")

    private val ARM_IMPLAUSIBLE = listOf(
        "svc", "rfe", "srs", "setend", "hvc", "smc",
        "bkpt", "cps", "dbg", "stmda", "ldmda", "stmib", "ldmib", "stmed", "ldmed", "stmfa", "ldmfa",
        "ldrbt", "strbt", "ldrt", "strt", "trap", "udf",
    )

    fun detectArmMode(elf: ElfFile, disassembler: Disassembler, littleEndian: Boolean) {
        if (elf.arch != ElfArch.ARM || !disassembler.available()) return
        val thumbFns = elf.functions.count { it.thumb }; val armFns = elf.functions.count { !it.thumb }
        if (thumbFns + armFns >= 4) { elf.defaultThumb = thumbFns > armFns; return }
        val sec = elf.textSections.firstOrNull { it.name == ".text" } ?: elf.textSections.firstOrNull() ?: return
        val bytes = elf.sectionBytes(sec)
        var armBad = 0; var thumbBad = 0; var armCov = 0L; var thumbCov = 0L; var off = 0; var samples = 0
        fun bad(insns: List<Insn>) = insns.count { i -> ARM_IMPLAUSIBLE.any { i.mnemonic.startsWith(it) } }
        while (off + 0x40 <= bytes.size && samples < 64) {
            val window = bytes.copyOfRange(off, off + 0x40)
            val a = runCatching { disassembler.disassemble(window, sec.addr + off, ElfArch.ARM, false, littleEndian) }.getOrDefault(emptyList())
            val t = runCatching { disassembler.disassemble(window, sec.addr + off, ElfArch.ARM, true, littleEndian) }.getOrDefault(emptyList())
            armBad += bad(a); thumbBad += bad(t); armCov += a.sumOf { it.size.toLong() }; thumbCov += t.sumOf { it.size.toLong() }
            off += 0x100; samples++
        }
        elf.defaultThumb = when {
            armBad > thumbBad + 2 -> true
            thumbBad > armBad + 2 -> false
            else -> thumbCov >= armCov
        }
    }

    fun discover(elf: ElfFile, disassembler: Disassembler? = null, arch: ElfArch = elf.arch, littleEndian: Boolean = elf.littleEndian): LongArray {
        val starts = sortedSetOf<Long>()
        for (f in elf.functions) starts.add(f.address)
        ehFrameStarts(elf, starts)
        val text = elf.textSections.filter { it.name == ".text" || it.isExecutable }
        if (disassembler != null && disassembler.available()) callTargets(elf, disassembler, arch, littleEndian, text, starts)
        if (arch == ElfArch.ARM64) pacScan(elf, text, starts)
        if (starts.count { addr -> text.any { addr >= it.addr && addr < it.addr + it.size } } < 8) {
            prologueScan(elf, text, starts)
        }
        val inText = starts.filter { addr -> text.any { addr >= it.addr && addr < it.addr + it.size } }
        val coalesced = ArrayList<Long>(inText.size)
        for (a in inText) if (coalesced.isEmpty() || a - coalesced.last() >= 8) coalesced.add(a)
        return coalesced.toLongArray()
    }

    private fun callTargets(elf: ElfFile, disassembler: Disassembler, arch: ElfArch, littleEndian: Boolean, text: List<ElfSection>, out: MutableSet<Long>) {
        val callMnems = when (arch) {
            ElfArch.X86, ElfArch.X86_64 -> setOf("call")
            ElfArch.ARM, ElfArch.ARM64 -> setOf("bl")
            ElfArch.MIPS, ElfArch.MIPS64 -> setOf("jal")
            else -> return
        }
        val codeSecs = text.filter { it.name !in PLT_SECS }
        val stride = if (arch == ElfArch.X86 || arch == ElfArch.X86_64) 1 else 4
        for (sec in codeSecs) {
            val bytes = elf.sectionBytes(sec)
            val end = sec.addr + sec.size
            var pos = sec.addr
            while (pos < end) {
                val from = (pos - sec.addr).toInt()
                if (from >= bytes.size) break
                val code = bytes.copyOfRange(from, minOf(from + 4096, bytes.size))
                val thumb = arch == ElfArch.ARM && elf.armThumbAt(pos)
                val insns = runCatching { disassembler.disassemble(code, pos, arch, thumb, littleEndian) }.getOrDefault(emptyList())
                if (insns.isEmpty()) { pos += stride; continue }
                for (ins in insns) {
                    if (ins.mnemonic.lowercase().substringAfterLast(' ') in callMnems) {
                        val op = ins.operands.trim().removePrefix("#")
                        val t = if (op.startsWith("0x")) op.substring(2).toLongOrNull(16) else null
                        if (t != null && t != ins.address + ins.size && codeSecs.any { t >= it.addr && t < it.addr + it.size }) out.add(t)
                    }
                }
                pos = maxOf(insns.last().address + insns.last().size, pos + stride)
            }
        }
    }

    private fun ehFrameStarts(elf: ElfFile, out: MutableSet<Long>) {
        val hdr = elf.sections.firstOrNull { it.name == ".eh_frame_hdr" && it.size > 4 } ?: return
        val bytes = elf.sectionBytes(hdr)
        val buf = ByteBuffer.wrap(bytes).order(if (elf.littleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)
        if (bytes[0].toInt() != 1) return
        val fdeCountEnc = bytes[2].toInt() and 0xFF
        val tableEnc = bytes[3].toInt() and 0xFF
        var pos = 4
        fun read(enc: Int): Long? {
            val fieldVaddr = hdr.addr + pos
            val raw: Long = when (enc and 0x0F) {
                0x02 -> { if (pos + 2 > bytes.size) return null; (buf.getShort(pos).toLong() and 0xFFFFL).also { pos += 2 } }
                0x0A -> { if (pos + 2 > bytes.size) return null; (buf.getShort(pos).toLong()).also { pos += 2 } }
                0x03 -> { if (pos + 4 > bytes.size) return null; (buf.getInt(pos).toLong() and 0xFFFFFFFFL).also { pos += 4 } }
                0x0B -> { if (pos + 4 > bytes.size) return null; (buf.getInt(pos).toLong()).also { pos += 4 } }
                0x04, 0x0C -> { if (pos + 8 > bytes.size) return null; buf.getLong(pos).also { pos += 8 } }
                0x00 -> { val n = if (elf.is64) 8 else 4; if (pos + n > bytes.size) return null; (if (elf.is64) buf.getLong(pos) else buf.getInt(pos).toLong() and 0xFFFFFFFFL).also { pos += n } }
                else -> return null
            }
            return when (enc and 0x70) {
                0x10 -> fieldVaddr + raw
                0x30 -> hdr.addr + raw
                0x00 -> raw
                else -> null
            }
        }
        read(bytes[1].toInt() and 0xFF) ?: return
        val count = (read(fdeCountEnc) ?: return).let { if (it < 0 || it > 2_000_000) return else it.toInt() }
        for (i in 0 until count) {
            val loc = read(tableEnc) ?: return
            read(tableEnc) ?: return
            if (loc > 0) out.add(loc)
        }
    }

    private fun pacScan(elf: ElfFile, text: List<ElfSection>, out: MutableSet<Long>) {
        for (sec in text) {
            if (sec.name in PLT_SECS) continue
            val b = elf.sectionBytes(sec)
            var i = 0
            while (i + 4 <= b.size) {
                val word = word32(b, i, elf.littleEndian)
                if (word == 0xD503233FL || word == 0xD503237FL) {
                    val backUp = i >= 4 && word32(b, i - 4, elf.littleEndian) == 0xD503245FL
                    out.add(sec.addr + i - if (backUp) 4 else 0)
                }
                i += 4
            }
        }
    }

    private fun prologueScan(elf: ElfFile, text: List<ElfSection>, out: MutableSet<Long>) {
        val little = elf.littleEndian
        for (sec in text) {
            val b = elf.sectionBytes(sec)
            when (elf.arch) {
                ElfArch.ARM64 -> {
                    var i = 0
                    while (i + 4 <= b.size) {
                        val w = word32(b, i, little)
                        if (w == 0xD503233FL || w == 0xD503237FL || w == 0xD503245FL || (w and 0xFFC07FFFL) == 0xA9807BFDL) {
                            out.add(sec.addr + i)
                        }
                        i += 4
                    }
                }
                ElfArch.X86_64, ElfArch.X86 -> {
                    var i = 0
                    while (i + 4 <= b.size) {
                        val endbr = b[i].toInt() and 0xFF == 0xF3 && b[i + 1].toInt() and 0xFF == 0x0F &&
                            b[i + 2].toInt() and 0xFF == 0x1E && b[i + 3].toInt() and 0xFF == 0xFA
                        val frame = b[i].toInt() and 0xFF == 0x55 && b[i + 1].toInt() and 0xFF == 0x48 &&
                            b[i + 2].toInt() and 0xFF == 0x89 && b[i + 3].toInt() and 0xFF == 0xE5
                        val frame32 = b[i].toInt() and 0xFF == 0x55 && b[i + 1].toInt() and 0xFF == 0x89 && b[i + 2].toInt() and 0xFF == 0xE5
                        if (endbr || frame || frame32) out.add(sec.addr + i)
                        i++
                    }
                }
                else -> {}
            }
        }
    }

    private fun word32(b: ByteArray, i: Int, little: Boolean): Long {
        val b0 = b[i].toLong() and 0xFF; val b1 = b[i + 1].toLong() and 0xFF
        val b2 = b[i + 2].toLong() and 0xFF; val b3 = b[i + 3].toLong() and 0xFF
        return if (little) b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)
        else b3 or (b2 shl 8) or (b1 shl 16) or (b0 shl 24)
    }
}
