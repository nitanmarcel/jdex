package io.github.nitanmarcel.jdex.disasm

import io.github.nitanmarcel.jdex.project.DiskLineSource
import io.github.nitanmarcel.jdex.project.GenerationCancelled
import io.github.nitanmarcel.jdex.project.LabeledChunk
import io.github.nitanmarcel.jdex.project.LineSource

object NativeListing {

    private const val WINDOW = 0x4000

    fun build(
        elf: ElfFile,
        disassembler: Disassembler,
        arch: ElfArch,
        littleEndian: Boolean,
        progress: (Int, Int) -> Unit,
        cancel: () -> Boolean,
        header: List<String> = emptyList(),
    ): LineSource? {
        val sections = (elf.textSections + elf.dataSections).sortedBy { it.addr }
        if (sections.isEmpty()) return null
        check(disassembler.available()) {
            "${disassembler.displayName} native library is not available for this platform " +
                "(${System.getProperty("os.name")}/${System.getProperty("os.arch")})"
        }
        val symbols = elf.functions.associateBy { it.address }
        NativeFunctions.detectArmMode(elf, disassembler, littleEndian)
        val discovered = NativeFunctions.discover(elf, disassembler, arch, littleEndian)
        val jni = NativeJni.analyze(elf, disassembler, arch, littleEndian, discovered)
        val starts = (discovered.toList() + jni.envFns.keys).distinct().sorted().toLongArray()
        val names = HashMap<Long, String>(starts.size * 2)
        for (s in starts) names[s] = symbols[s]?.name ?: jni.registered[s]?.name ?: "sub_${s.toString(16)}"
        val pltNames = buildPltNames(elf, disassembler, arch, littleEndian)
        val stride = when (arch) { ElfArch.X86, ElfArch.X86_64 -> 1; ElfArch.ARM -> 2; else -> 4 }
        val totalBytes = sections.sumOf { it.size }.coerceAtLeast(1)
        var done = 0L
        val usedLabels = HashSet<String>()
        val (literalData, armBounds) = if (arch == ElfArch.ARM) armPrePass(elf, disassembler, littleEndian, starts)
            else emptyMap<Long, Int>() to emptySet<Long>()

        val chunks = sequence {
            if (header.isNotEmpty()) {
                val buf = StringBuilder()
                for (line in header) buf.append("; ").append(line).append('\n')
                buf.append('\n')
                yield(LabeledChunk("; header", buf.toString()))
            }
            for (sec in sections) {
                val base = sec.addr
                val secEnd = sec.addr + sec.size
                val bytes = elf.sectionBytes(sec)
                val secSyms = starts.asSequence().filter { it in (base + 1) until secEnd }.toList()
                var symPtr = 0
                var pos = base
                val sname = sec.name.ifEmpty { "text" }
                var header: String? = "\n; $sname\n"
                while (pos < secEnd) {
                    if (cancel()) throw GenerationCancelled()
                    while (symPtr < secSyms.size && secSyms[symPtr] <= pos) symPtr++
                    val nextSym = secSyms.getOrNull(symPtr) ?: secEnd
                    val winEnd = minOf(pos + WINDOW, secEnd, nextSym)
                    val buf = StringBuilder()
                    header?.let { buf.append(it); header = null }
                    var label = names[pos] ?: "loc_${pos.toString(16)}"
                    if (!usedLabels.add(label)) { label = "${label}_${pos.toString(16)}"; usedLabels.add(label) }
                    var p = pos
                    val hasMapping = arch == ElfArch.ARM || arch == ElfArch.ARM64
                    if (!sec.isExecutable) {
                        p = (if (sec.name == ".eh_frame_hdr" && pos == base && secSyms.isEmpty()) appendEhFrameHdr(buf, sec, bytes, names, elf, secEnd) else null)
                            ?: appendData(buf, base, bytes, pos, winEnd, elf, names)
                    }
                    while (p < winEnd) {
                        val from = (p - base).toInt()
                        if (from >= bytes.size) break
                        if (hasMapping) {
                            val dataEnd = elf.dataRegionEnd(p)
                            if (dataEnd != null && dataEnd > p) {
                                val to = minOf(dataEnd, winEnd)
                                while (p < to && (p - base).toInt() < bytes.size) {
                                    val step = minOf(4L, to - p).toInt()
                                    dataLine(buf, p, bytes, (p - base).toInt(), step, elf.littleEndian)
                                    p += step
                                }
                                continue
                            }
                        }
                        val litSize = literalData[p]
                        if (litSize != null) {
                            var n = 0
                            while (n < litSize && (p - base).toInt() < bytes.size && p < winEnd) {
                                val step = minOf(4, litSize - n)
                                dataLine(buf, p, bytes, (p - base).toInt(), step, elf.littleEndian)
                                p += step; n += step
                            }
                            continue
                        }
                        val readTo = minOf(from + 1024, (winEnd - base).toInt() + 16, bytes.size)
                        val code = bytes.copyOfRange(from, readTo)
                        val thumb = arch == ElfArch.ARM && elf.armThumbAt(p)
                        val insns = runCatching { disassembler.disassemble(code, p, arch, thumb, littleEndian) }.getOrDefault(emptyList())
                        val kept = insns.takeWhile { it.address < winEnd }
                        if (kept.isEmpty()) {
                            dataLine(buf, p, bytes, from, stride, elf.littleEndian)
                            p += stride
                        } else {
                            val envSeed = if (jni.enabled) jni.envFns[pos] ?: emptyMap() else emptyMap()
                            appendInsns(buf, kept, names, elf, pltNames, arch, jni, pos, envSeed, armBounds)
                            val newP = kept.last().address + kept.last().size
                            p = if (newP > p) newP else p + stride
                        }
                    }
                    if (buf.isNotEmpty()) yield(LabeledChunk(label, buf.toString()))
                    val next = maxOf(winEnd, p)
                    done += (next - pos)
                    progress(done.coerceAtMost(totalBytes).toInt(), totalBytes.toInt())
                    pos = next
                }
            }
        }
        return try {
            DiskLineSource.build(chunks)
        } catch (e: GenerationCancelled) {
            null
        }
    }

    private fun appendInsns(buf: StringBuilder, insns: List<Insn>, names: Map<Long, String>, elf: ElfFile, pltNames: Map<Long, String>, arch: ElfArch, jni: NativeJni.Analysis, funcStart: Long, envSeed: Map<Int, NativeJni.Tag>, armBounds: Set<Long>) {
        val lo = insns.first().address
        val hi = insns.last().address + insns.last().size
        val targets = HashSet<Long>()
        val switches = HashMap<Long, NativeJumpTable.Result>()
        for (idx in insns.indices) {
            val insn = insns[idx]
            if (isBranchOrCall(insn.mnemonic)) {
                val t = lastHex(insn.operands)
                if (t != null && t in lo until hi && t != insn.address && (arch != ElfArch.ARM || t in armBounds)) targets.add(t)
            }
            if (isIndirectBranch(insn)) {
                NativeJumpTable.resolve(insns, idx, elf, arch)?.let { res ->
                    switches[insn.address] = res
                    res.targets.forEach { targets.add(it) }
                }
            }
        }
        fun nameFor(a: Long): String? = pltNames[a] ?: names[a]
        val adrp = HashMap<String, Long>()
        val env = if (jni.enabled) NativeJni.newEnvTrack(arch) else null
        if (env != null && insns.first().address == funcStart) env.seed(envSeed)
        for (insn in insns) {
            val name = names[insn.address]
            if (name != null) {
                buf.append('\n')
                if (name.startsWith("_Z")) CppDemangler.demangle(name)?.let { buf.append("; ").append(it).append('\n') }
                buf.append(name).append(":\n")
                jni.registered[insn.address]?.let { buf.append("; Java native: ").append(it.name).append(' ').append(it.signature).append('\n') }
            } else if (insn.address in targets) buf.append("loc_").append(insn.address.toString(16)).append(":\n")
            buf.append("%08x: ".format(insn.address))
            val hex = insn.bytes.joinToString("") { "%02x".format(it) }
            buf.append(hex.padEnd(11)).append(' ')
            if (insn.operands.isEmpty()) buf.append(insn.mnemonic)
            else buf.append(insn.mnemonic.padEnd(7)).append(' ').append(resolveOperands(insn, targets, ::nameFor, elf))
            val sw = switches[insn.address]
            val call = env?.step(insn)
            val jniName = when {
                env == null -> null
                insn.address in jni.registerCalls -> "JNIEnv->RegisterNatives"
                call == null -> null
                call.first == NativeJni.Tag.ENV -> JniAbi.envFunction(call.second, jni.ptrSize)?.let { "JNIEnv->$it" }
                else -> JniAbi.vmFunction(call.second, jni.ptrSize)?.let { "JavaVM->$it" }
            }
            when {
                sw != null -> buf.append("  ; switch (").append(sw.indexReg).append("): ")
                    .append(sw.targets.joinToString(", ") { "loc_${it.toString(16)}" })
                jniName != null -> buf.append("  ; ").append(jniName)
                else -> dataComment(insn, adrp, names, elf)?.let { buf.append("  ; ").append(it) }
            }
            buf.append('\n')
        }
    }

    private fun splitOps(s: String): List<String> {
        val out = ArrayList<String>(); var depth = 0; val sb = StringBuilder()
        for (c in s) when (c) {
            '[' -> { depth++; sb.append(c) }
            ']' -> { depth--; sb.append(c) }
            ',' -> if (depth == 0) { out.add(sb.toString().trim()); sb.clear() } else sb.append(c)
            else -> sb.append(c)
        }
        if (sb.isNotBlank()) out.add(sb.toString().trim())
        return out
    }

    private fun dataComment(insn: Insn, adrp: HashMap<String, Long>, names: Map<Long, String>, elf: ElfFile): String? {
        val m = insn.mnemonic.lowercase()
        val ops = splitOps(insn.operands).map { it.removePrefix("#") }
        fun hex(s: String) = s.removePrefix("0x").toLongOrNull(16)
        when {
            m == "adrp" && ops.size == 2 -> { hex(ops[1])?.let { adrp[ops[0]] = it }; return null }
            m == "adr" && ops.size == 2 -> { adrp.remove(ops[0]); return hex(ops[1])?.let { resolveData(it, names, elf) } }
            m == "add" && ops.size == 3 -> {
                val page = adrp[ops[1]] ?: run { adrp.remove(ops[0]); return null }
                val off = hex(ops[2]) ?: run { adrp.remove(ops[0]); return null }
                adrp.remove(ops[0])
                return resolveData(page + off, names, elf)
            }
            m == "ldr" && ops.size == 2 && ops[1].startsWith("[") -> {
                val parts = ops[1].removePrefix("[").removeSuffix("]").split(",").map { it.trim().removePrefix("#") }
                val page = adrp[parts.first()]
                adrp.remove(ops[0])
                if (page == null) return null
                return resolveData(page + (hex(parts.getOrElse(1) { "0" }) ?: 0), names, elf)
            }
            m == "lea" && ops.size == 2 && ops[1].contains("rip") ->
                return ripTarget(insn, ops[1])?.let { resolveData(it, names, elf) }
            (elf.arch == ElfArch.MIPS || elf.arch == ElfArch.MIPS64) && ops.size == 2 &&
                (ops[1].endsWith("(\$gp)") || ops[1].endsWith("(gp)")) -> {
                val paren = ops[1].indexOf('(')
                val off = signedHex(ops[1].substring(0, paren))
                if (off != null) elf.mipsGpTarget(off)?.let { ref ->
                    ref.symbol?.let { return it }
                    ref.localAddr?.let { addr ->
                        names[addr]?.let { return it }
                        if (elf.textSections.any { addr >= it.addr && addr < it.addr + it.size }) return "sub_${addr.toString(16)}"
                        return resolveData(addr, names, elf) ?: "off_${addr.toString(16)}"
                    }
                }
            }
            ops.isNotEmpty() && m in WRITES_DEST -> adrp.remove(ops[0])
        }
        return null
    }

    private val WRITES_DEST = setOf(
        "mov", "movz", "movn", "movk", "mvn", "neg", "and", "orr", "eor", "sub", "mul",
        "lsl", "lsr", "asr", "ror", "ldp", "ldur", "ldrb", "ldrh", "ldrsw", "csel", "cset",
    )

    private fun signedHex(s: String): Long? {
        val t = s.trim()
        if (t.isEmpty()) return 0L
        val neg = t.startsWith("-")
        val body = t.removePrefix("-").removePrefix("+")
        val v = if (body.startsWith("0x")) body.removePrefix("0x").toLongOrNull(16) else body.toLongOrNull()
        return v?.let { if (neg) -it else it }
    }

    private fun resolveData(addr: Long, names: Map<Long, String>, elf: ElfFile): String? {
        elf.stringAt(addr)?.let { return "\"" + it.replace("\\", "\\\\").replace("\"", "\\\"") + "\"" }
        elf.relocs[addr]?.let { return it }
        return names[addr]
    }

    private fun resolveOperands(insn: Insn, targets: Set<Long>, nameFor: (Long) -> String?, elf: ElfFile): String {
        val operands = insn.operands
        if (!isBranchOrCall(insn.mnemonic)) return operands
        if (operands.contains("[rip")) {
            ripTarget(insn, operands)?.let { got -> elf.relocs[got]?.let { return it } }
            return operands
        }
        if (operands.contains("[")) return operands
        val m = TARGET.findAll(operands).lastOrNull() ?: return operands
        val v = m.value.removePrefix("#").removePrefix("0x").toLongOrNull(16) ?: return operands
        val repl = nameFor(v) ?: if (v in targets) "loc_${v.toString(16)}" else "0x${v.toString(16)}"
        return operands.substring(0, m.range.first) + repl + operands.substring(m.range.last + 1)
    }

    internal fun buildPltNames(elf: ElfFile, disassembler: Disassembler, arch: ElfArch, littleEndian: Boolean): Map<Long, String> {
        if (elf.relocs.isEmpty()) return emptyMap()
        val out = HashMap<Long, String>()
        val gotPlt = (elf.sections.firstOrNull { it.name == ".got.plt" } ?: elf.sections.firstOrNull { it.name == ".got" })?.addr
        val pltSecs = setOf(".plt", ".iplt", ".plt.sec", ".plt.got")
        for (sec in elf.textSections) {
            if (sec.name !in pltSecs) continue
            val defaultEnt = if (arch == ElfArch.ARM) 12 else 16
            val entsize = (if (sec.entsize > 0) sec.entsize.toInt() else defaultEnt).coerceAtLeast(1)
            val insns = runCatching { disassembler.disassemble(elf.sectionBytes(sec), sec.addr, arch, false, littleEndian) }.getOrDefault(emptyList())
            val pages = HashMap<String, Long>()
            for (ins in insns) {
                val m = ins.mnemonic.lowercase()
                val ops = splitOps(ins.operands)
                var got: Long? = null
                when {
                    m == "adrp" && ops.size == 2 -> { ops[1].removePrefix("#").removePrefix("0x").toLongOrNull(16)?.let { pages[ops[0]] = it }; continue }
                    m == "ldr" && ops.size == 2 && ops[1].startsWith("[") -> {
                        val parts = ops[1].removePrefix("[").removeSuffix("]").split(",").map { it.trim().removePrefix("#") }
                        val page = pages[parts.first()] ?: continue
                        got = page + (parts.getOrElse(1) { "0" }.removePrefix("0x").toLongOrNull(16) ?: 0)
                    }
                    m.endsWith("jmp") && ops.size == 1 && ops[0].contains("rip") -> got = ripTarget(ins, ops[0])
                    m.endsWith("jmp") && ops.size == 1 && ops[0].contains("ebx") && gotPlt != null -> {
                        val inner = ops[0].substringAfter('[').substringBefore(']')
                        val disp = Regex("0x[0-9a-fA-F]+").find(inner)?.value?.substring(2)?.toLongOrNull(16) ?: 0
                        got = gotPlt + (if (Regex("-\\s*0x").containsMatchIn(inner)) -disp else disp)
                    }
                }
                got?.let { g -> elf.relocs[g]?.let { name -> out[sec.addr + ((ins.address - sec.addr) / entsize) * entsize] = name } }
            }
        }
        return out
    }

    private fun ripTarget(insn: Insn, operand: String): Long? {
        val rest = operand.substringAfter("rip")
        val off = TARGET.find(rest)?.value?.removePrefix("#")?.removePrefix("0x")?.toLongOrNull(16) ?: return null
        val signed = if (Regex("-\\s*0x").containsMatchIn(rest)) -off else off
        return insn.address + insn.size + signed
    }

    private fun appendData(buf: StringBuilder, base: Long, bytes: ByteArray, from0: Long, to: Long, elf: ElfFile, names: Map<Long, String>): Long {
        val ptrSize = if (elf.is64) 8 else 4
        val relocPtrs = elf.relocatedPointers()
        var p = from0
        while (p < to) {
            val off = (p - base).toInt()
            if (off < 0 || off >= bytes.size) break
            val name = elf.relocs[p]
            if (name != null && (p - base).toInt() + ptrSize <= bytes.size) {
                buf.append("%08x: ".format(p)).append(dataHex(bytes, off, ptrSize).padEnd(20)).append(if (ptrSize == 8) "  dq " else "  dd ").append(name).append('\n')
                p += ptrSize
                continue
            }
            if (name == null && off + ptrSize <= bytes.size) {
                val ptr = relocPtrs[p]
                if (ptr != null) {
                    val target = resolveData(ptr, names, elf) ?: "off_${ptr.toString(16)}"
                    buf.append("%08x: ".format(p)).append(dataHex(bytes, off, ptrSize).padEnd(20)).append(if (ptrSize == 8) "  dq " else "  dd ").append(target).append('\n')
                    p += ptrSize
                    continue
                }
            }
            val str = readString(bytes, off)
            if (str != null) {
                buf.append("%08x: ".format(p)).append(dataHex(bytes, off, 8).padEnd(20)).append("  \"").append(escape(str)).append("\"\n")
                p += str.length + 1
                continue
            }
            if (bytes[off].toInt() == 0) {
                var z = 1
                while (p + z < to && off + z < bytes.size && bytes[off + z].toInt() == 0 &&
                    !elf.relocs.containsKey(p + z) && !relocPtrs.containsKey(p + z)) z++
                buf.append("%08x: ".format(p)).append("".padEnd(20)).append("  .skip 0x%x\n".format(z))
                p += z
                continue
            }
            val step = if (to - p >= 4) 4 else (to - p).toInt()
            dataLine(buf, p, bytes, off, step, elf.littleEndian)
            p += step
        }
        return p
    }

    private fun readString(bytes: ByteArray, off: Int): String? {
        var i = off; val end = minOf(off + 4096, bytes.size); val sb = StringBuilder()
        while (i < end) {
            val c = bytes[i].toInt() and 0xFF
            if (c == 0) return if (sb.length >= 4) sb.toString() else null
            if (c < 0x20 || c > 0x7E) return null
            sb.append(c.toChar()); i++
        }
        return null
    }

    private fun dataHex(bytes: ByteArray, off: Int, n: Int): String =
        (0 until minOf(n, bytes.size - off)).joinToString("") { "%02x".format(bytes[off + it]) }

    private fun escape(s: String): String =
        s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\t", "\\t")

    private fun dataLine(buf: StringBuilder, addr: Long, bytes: ByteArray, from: Int, stride: Int, little: Boolean) {
        val n = minOf(stride, bytes.size - from)
        val hex = (0 until n).joinToString("") { "%02x".format(bytes[from + it]) }
        buf.append("%08x: ".format(addr)).append(hex.padEnd(20)).append("  ")
        when (n) {
            4 -> buf.append(".word 0x%08x".format(leValue(bytes, from, 4, little)))
            8 -> buf.append(".quad 0x%016x".format(leValue(bytes, from, 8, little)))
            2 -> buf.append(".short 0x%04x".format(leValue(bytes, from, 2, little)))
            else -> buf.append(".byte ").append((0 until n).joinToString(", ") { "0x%02x".format(bytes[from + it]) })
        }
        buf.append('\n')
    }

    private fun appendEhFrameHdr(buf: StringBuilder, sec: ElfSection, bytes: ByteArray, names: Map<Long, String>, elf: ElfFile, secEnd: Long): Long? {
        if (bytes.size < 4 || bytes[0].toInt() != 1) return null
        val base = sec.addr
        val little = elf.littleEndian
        val ptrEnc = bytes[1].toInt() and 0xFF
        val countEnc = bytes[2].toInt() and 0xFF
        val tableEnc = bytes[3].toInt() and 0xFF
        var pos = 4
        fun hex(off: Int, n: Int) = (0 until n).joinToString("") { "%02x".format(bytes[off + it]) }
        fun read(enc: Int): Long? {
            val fieldVaddr = base + pos
            val raw = when (enc and 0x0F) {
                0x02 -> { if (pos + 2 > bytes.size) return null; leValue(bytes, pos, 2, little).also { pos += 2 } }
                0x0A -> { if (pos + 2 > bytes.size) return null; signExtend(leValue(bytes, pos, 2, little), 2).also { pos += 2 } }
                0x03 -> { if (pos + 4 > bytes.size) return null; leValue(bytes, pos, 4, little).also { pos += 4 } }
                0x0B -> { if (pos + 4 > bytes.size) return null; signExtend(leValue(bytes, pos, 4, little), 4).also { pos += 4 } }
                0x04, 0x0C -> { if (pos + 8 > bytes.size) return null; leValue(bytes, pos, 8, little).also { pos += 8 } }
                0x00 -> { val n = if (elf.is64) 8 else 4; if (pos + n > bytes.size) return null; leValue(bytes, pos, n, little).also { pos += n } }
                else -> return null
            }
            return when (enc and 0x70) { 0x10 -> fieldVaddr + raw; 0x30 -> base + raw; 0x00 -> raw; else -> null }
        }
        val out = StringBuilder()
        out.append("%08x: ".format(base)).append(hex(0, 4).padEnd(20))
            .append("  ; eh_frame_hdr  enc=0x%02x/0x%02x/0x%02x\n".format(ptrEnc, countEnc, tableEnc))
        var off = pos
        val ehPtr = read(ptrEnc) ?: return null
        val ehWord = if (elf.is64) "  .quad 0x%x  ; eh_frame\n" else "  .word 0x%08x  ; eh_frame\n"
        out.append("%08x: ".format(base + off)).append(hex(off, pos - off).padEnd(20)).append(ehWord.format(ehPtr))
        off = pos
        val count = read(countEnc) ?: return null
        out.append("%08x: ".format(base + off)).append(hex(off, pos - off).padEnd(20)).append("  .word 0x%x  ; fde_count\n".format(count))
        if (count < 0 || count > 200000) return null
        for (i in 0 until count.toInt()) {
            off = pos
            val loc = read(tableEnc) ?: return null
            read(tableEnc) ?: return null
            if (pos > bytes.size) return null
            out.append("%08x: ".format(base + off)).append(hex(off, pos - off).padEnd(20))
                .append("  unwind ").append(names[loc] ?: "sub_${loc.toString(16)}").append('\n')
        }
        buf.append(out)
        return secEnd
    }

    private fun signExtend(v: Long, n: Int): Long {
        val m = 1L shl (n * 8 - 1)
        return (v xor m) - m
    }

    private fun leValue(bytes: ByteArray, from: Int, n: Int, little: Boolean): Long {
        var v = 0L
        for (i in 0 until n) {
            val b = bytes[from + i].toLong() and 0xFF
            if (little) v = v or (b shl (8 * i)) else v = (v shl 8) or b
        }
        return v
    }

    private val BRANCH = setOf(
        "b", "bl", "bx", "blx", "cbz", "cbnz", "tbz", "tbnz",
        "beq", "bne", "bcs", "bhs", "bcc", "blo", "bmi", "bpl", "bvs", "bvc", "bhi", "bls", "bge", "blt", "bgt", "ble", "bal",
        "call", "loop", "loope", "loopne", "loopz", "loopnz",
        "beqz", "bnez", "bgez", "bgtz", "blez", "bltz", "bgezal", "bltzal",
    )

    private fun armPrePass(elf: ElfFile, disassembler: Disassembler, littleEndian: Boolean, starts: LongArray): Pair<Map<Long, Int>, Set<Long>> {
        val literals = HashMap<Long, Int>(); val bounds = HashSet<Long>()
        fun decode(p: Long, base: Long, bytes: ByteArray) = runCatching {
            disassembler.disassemble(bytes.copyOfRange((p - base).toInt(), minOf((p - base).toInt() + 64, bytes.size)), p, ElfArch.ARM, elf.armThumbAt(p), littleEndian)
        }.getOrDefault(emptyList())
        for (sec in elf.textSections) {
            val base = sec.addr; val bytes = elf.sectionBytes(sec); val secEnd = base + bytes.size
            val chunks = (listOf(base) + starts.filter { it in (base + 1) until secEnd }).distinct().sorted()
            for ((ci, cstart) in chunks.withIndex()) {
                val cend = chunks.getOrElse(ci + 1) { secEnd }
                var p = cstart
                while (p < cend) {
                    if ((p - base).toInt() >= bytes.size) break
                    val insns = decode(p, base, bytes)
                    if (insns.isEmpty()) { p += 4; continue }
                    var adv = false
                    for (ins in insns) {
                        if (ins.address >= cend) break
                        literalTarget(ins, elf.armThumbAt(ins.address))?.let { (a, s) -> if (a in base until secEnd) literals[a] = maxOf(literals[a] ?: 0, s) }
                        val n = ins.address + ins.size; if (n > p) { p = n; adv = true }
                    }
                    if (!adv) p += 4
                }
                p = cstart
                while (p < cend) {
                    if ((p - base).toInt() >= bytes.size) break
                    val de = elf.dataRegionEnd(p); if (de != null && de > p) { p = minOf(de, cend); continue }
                    val lit = literals[p]; if (lit != null) { p += lit; continue }
                    val insns = decode(p, base, bytes)
                    if (insns.isEmpty()) { p += 4; continue }
                    var adv = false
                    for (ins in insns) {
                        if (ins.address >= cend) break
                        bounds.add(ins.address)
                        val n = ins.address + ins.size; if (n > p) { p = n; adv = true }
                    }
                    if (!adv) p += 4
                }
            }
        }
        return literals to bounds
    }

    private fun literalTarget(ins: Insn, thumb: Boolean): Pair<Long, Int>? {
        val size = when (ins.mnemonic) { "ldr", "ldr.w" -> 4; "ldrd", "ldrd.w" -> 8; else -> return null }
        val ops = ins.operands
        val pc = ops.indexOf("[pc"); if (pc < 0) return null
        val close = ops.indexOf(']', pc); if (close < 0) return null
        val inner = ops.substring(pc + 1, close)
        if (inner.contains(",") && !inner.contains("#")) return null
        val off = if (inner.contains("#")) {
            val s = inner.substringAfter("#").trim()
            val v = (if (s.removePrefix("-").startsWith("0x")) s.removePrefix("-").removePrefix("0x").toLongOrNull(16)
                else s.removePrefix("-").toLongOrNull()) ?: return null
            if (s.startsWith("-")) -v else v
        } else 0L
        val base = (ins.address + (if (thumb) 4L else 8L)) and 3L.inv()
        return (base + off) to size
    }

    private fun isBranchOrCall(mnem: String): Boolean {
        val m = mnem.lowercase().let { if (it.endsWith(".w") || it.endsWith(".n")) it.dropLast(2) else it }
        return m in BRANCH || m.startsWith("b.") || (m.startsWith("j") && m != "jr" && m != "jalr")
    }

    private fun isIndirectBranch(insn: Insn): Boolean {
        val m = insn.mnemonic.lowercase().substringAfterLast(' ')
        val ops = insn.operands.trim()
        return when (m) {
            "br" -> ops.isNotEmpty() && '[' !in ops
            "jmp" -> '[' in ops || (ops.isNotEmpty() && lastHex(ops) == null)
            "jr" -> ops.isNotEmpty() && ops != "\$ra" && ops != "ra" && '(' !in ops
            "tbb", "tbh" -> '[' in ops
            else -> false
        }
    }

    private fun lastHex(operands: String): Long? =
        TARGET.findAll(operands).lastOrNull()?.value?.removePrefix("#")?.removePrefix("0x")?.toLongOrNull(16)

    private val TARGET = Regex("#?0x[0-9a-fA-F]+")
}
