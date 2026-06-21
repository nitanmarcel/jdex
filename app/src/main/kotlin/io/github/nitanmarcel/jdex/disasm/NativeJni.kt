package io.github.nitanmarcel.jdex.disasm

object NativeJni {

    enum class Tag { ENV, VM }

    data class JniNative(val name: String, val signature: String)

    class Analysis(
        val registered: Map<Long, JniNative>,
        val registerCalls: Set<Long>,
        val envFns: Map<Long, Map<Int, Tag>>,
        val ptrSize: Int,
        val arch: ElfArch,
        val enabled: Boolean,
    ) {
        companion object { val NONE = Analysis(emptyMap(), emptySet(), emptyMap(), 8, ElfArch.UNKNOWN, false) }
    }

    internal enum class Family { ARM, X86 }

    internal class Cfg(
        val family: Family, val ptrSize: Int, val argRegs: List<String>, val frameRegs: Set<String>,
        val countAlt: String?, val stackArgs: Boolean = false,
    ) {
        val regNativesOff = 215L * ptrSize
        val getEnvOff = JniAbi.getEnvOffset(ptrSize)
        val methodSize = 3L * ptrSize
        val codeAlignMask = if (family == Family.ARM) (ptrSize / 2 - 1).toLong() else 0L
    }

    internal fun newEnvTrack(arch: ElfArch): EnvTrack? = cfgFor(arch)?.let { EnvTrack(it) }

    private fun cfgFor(arch: ElfArch): Cfg? = when (arch) {
        ElfArch.ARM64 -> Cfg(Family.ARM, 8, listOf("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"), setOf("x29", "sp", "fp"), "w3")
        ElfArch.ARM -> Cfg(Family.ARM, 4, listOf("r0", "r1", "r2", "r3"), setOf("r11", "sp", "fp", "r7"), null)
        ElfArch.X86_64 -> Cfg(Family.X86, 8, listOf("rdi", "rsi", "rdx", "rcx", "r8", "r9"), setOf("rbp", "rsp"), "ecx")
        ElfArch.X86 -> Cfg(Family.X86, 4, listOf("ebp,8", "ebp,12", "ebp,16", "ebp,20"), setOf("ebp", "esp"), null, stackArgs = true)
        else -> null
    }

    private val PROPAGATE_BUDGET = 400_000
    private val PLT_SECS = setOf(".plt", ".iplt", ".plt.sec", ".plt.got")
    private const val LDR_6B8 = 0xF9435C00L
    private const val LDR_MASK = 0xFFFFFC00L

    fun analyze(elf: ElfFile, disassembler: Disassembler, arch: ElfArch, littleEndian: Boolean, starts: LongArray): Analysis {
        val cfg = cfgFor(arch) ?: return Analysis.NONE
        if (!disassembler.available()) return Analysis.NONE
        if (elf.functions.none { it.name == "JNI_OnLoad" || it.name == "JNI_OnUnload" || it.name.startsWith("Java_") }) return Analysis.NONE
        if (arch == ElfArch.ARM) NativeFunctions.detectArmMode(elf, disassembler, littleEndian)

        val text = elf.textSections.filter { it.name !in PLT_SECS }
        fun inText(a: Long) = (a and cfg.codeAlignMask) == 0L && text.any { a >= it.addr && a < it.addr + it.size }
        val codeAt = CodeReader(elf, disassembler, arch, littleEndian, starts, text)
        val registered = HashMap<Long, JniNative>()
        val registerCalls = HashSet<Long>()

        fun isRegNativesWrapper(n: String) = n.contains("JNIEnv") && n.contains("RegisterNatives")
        val regWrappers = HashSet<Long>()
        for (f in elf.functions) if (isRegNativesWrapper(f.name)) regWrappers.add(f.address)
        for ((stub, name) in NativeListing.buildPltNames(elf, disassembler, arch, littleEndian)) if (isRegNativesWrapper(name)) regWrappers.add(stub)

        val candidates = if (arch == ElfArch.ARM64) {
            val fns = HashSet<Long>()
            for (sec in text) {
                val bytes = elf.sectionBytes(sec)
                var i = 0
                while (i + 4 <= bytes.size) {
                    if ((word32(bytes, i, littleEndian) and LDR_MASK) == LDR_6B8) fns.add(floorStart(starts, sec.addr + i))
                    i += 4
                }
            }
            fns
        } else starts.toHashSet()
        if (regWrappers.isNotEmpty()) candidates.addAll(starts.toList())
        for (fn in candidates) findRegisterCall(elf, cfg, codeAt.insns(fn), regWrappers, ::inText, registered, registerCalls)

        val envFns = propagateEnv(elf, cfg, starts, registered, codeAt)
        return Analysis(registered, registerCalls, envFns, cfg.ptrSize, arch, true)
    }

    private class CodeReader(
        val elf: ElfFile, val disassembler: Disassembler, val arch: ElfArch, val littleEndian: Boolean,
        val starts: LongArray, val text: List<ElfSection>,
    ) {
        private val cache = HashMap<Long, List<Insn>>()
        private val secBytes = HashMap<ElfSection, ByteArray>()
        fun insns(fn: Long): List<Insn> = cache.getOrPut(fn) {
            val sec = text.firstOrNull { fn >= it.addr && fn < it.addr + it.size } ?: return@getOrPut emptyList()
            val idx = starts.binarySearch(fn)
            val next = if (idx >= 0 && idx + 1 < starts.size) starts[idx + 1] else Long.MAX_VALUE
            val end = minOf(next, sec.addr + sec.size, fn + 0x4000)
            val bytes = secBytes.getOrPut(sec) { elf.sectionBytes(sec) }
            val a = (fn - sec.addr).toInt(); val b = (end - sec.addr).toInt()
            if (a < 0 || b > bytes.size || a >= b) return@getOrPut emptyList()
            val thumb = arch == ElfArch.ARM && elf.armThumbAt(fn)
            runCatching { disassembler.disassemble(bytes.copyOfRange(a, b), fn, arch, thumb, littleEndian) }.getOrDefault(emptyList())
        }
    }

    private fun findRegisterCall(
        elf: ElfFile, cfg: Cfg, insns: List<Insn>, regWrappers: Set<Long>, inText: (Long) -> Boolean,
        registered: HashMap<Long, JniNative>, registerCalls: HashSet<Long>,
    ) {
        if (insns.isEmpty()) return
        val regAddr = HashMap<String, Long>()
        val litVal = HashMap<String, Long>()
        val derefZero = HashSet<String>()
        val vtSlot = HashMap<String, Long>()
        val pushed = ArrayList<Long?>()
        var picReturn = -1L
        val frame = if (cfg.family == Family.ARM) ArmFrame() else null
        for (ins in insns) {
            val m = ins.mnemonic.lowercase()
            val ops = splitOps(ins.operands)
            val eff = decode(ins, cfg)
            val isRegisterCall = when (eff.k) {
                K.CALL_MEM -> eff.base in derefZero && eff.off == cfg.regNativesOff
                K.CALL_REG -> vtSlot[eff.src] == cfg.regNativesOff || regAddr[eff.src] in regWrappers
                K.CALL_DIR -> eff.target != null && eff.target in regWrappers
                else -> false
            }
            if (isRegisterCall) {
                val count: Int?
                val methods: List<Pair<Long, JniNative>>?
                if (cfg.stackArgs) {
                    count = pushed.getOrNull(pushed.size - 4)?.toInt()
                    methods = pushed.getOrNull(pushed.size - 3)?.let { a -> count?.let { validateArray(elf, cfg, a, it, inText) } }
                } else {
                    count = (regAddr[cfg.argRegs[3]] ?: cfg.countAlt?.let { regAddr[it] })?.toInt()
                    val arrayReg = cfg.argRegs[2]
                    methods = when {
                        count == null -> null
                        regAddr[arrayReg] != null -> validateArray(elf, cfg, regAddr[arrayReg]!!, count, inText)
                        frame?.addrReg?.get(arrayReg) != null -> reconstructStackArray(elf, cfg, frame, frame.addrReg[arrayReg]!!, count, inText)
                        else -> null
                    }
                }
                if (methods != null) {
                    registerCalls.add(ins.address)
                    for ((fnPtr, native) in methods) registered.putIfAbsent(fnPtr, native)
                }
            }
            trackRegAddr(regAddr, litVal, ins, eff, cfg, elf, frame)
            applyDeref(derefZero, vtSlot, eff)
            if (cfg.stackArgs) {
                if (m == "call" && eff.k == K.CALL_DIR && eff.target == ins.address + ins.size) picReturn = eff.target
                else if (m == "pop" && ops.size == 1 && ins.address == picReturn) { regAddr[ops[0]] = ins.address; picReturn = -1 }
                if (m == "push" && ops.size == 1) {
                    val v = ops[0]
                    pushed.add(if (v.startsWith("0x")) v.substring(2).toLongOrNull(16) else (v.toLongOrNull() ?: regAddr[v]))
                } else if (eff.k == K.CALL_MEM || eff.k == K.CALL_REG || (eff.k == K.CALL_DIR && eff.target != ins.address + ins.size)) {
                    pushed.clear()
                }
            }
        }
    }

    private fun validateArray(elf: ElfFile, cfg: Cfg, arrayAddr: Long, count: Int, inText: (Long) -> Boolean): List<Pair<Long, JniNative>>? {
        if (count < 1 || count > 4000) return null
        val out = ArrayList<Pair<Long, JniNative>>(count)
        for (i in 0 until count) {
            val base = arrayAddr + i * cfg.methodSize
            val namePtr = elf.relocatedPointerAt(base) ?: return null
            val sigPtr = elf.relocatedPointerAt(base + cfg.ptrSize) ?: return null
            var fnPtr = elf.relocatedPointerAt(base + 2 * cfg.ptrSize) ?: return null
            if (cfg.family == Family.ARM) fnPtr = fnPtr and 1L.inv()

            val name = elf.cStringAt(namePtr) ?: return null
            val sig = elf.cStringAt(sigPtr) ?: return null
            if (!isMethodName(name) || !isSignature(sig) || !inText(fnPtr)) return null
            out.add(fnPtr to JniNative(name, sig))
        }
        return out
    }

    internal class ArmFrame {
        var x29Delta = 0L
        val slotPtr = HashMap<Long, Long>()
        val addrReg = HashMap<String, Long>()
    }

    private fun reconstructStackArray(elf: ElfFile, cfg: Cfg, frame: ArmFrame, baseOff: Long, count: Int, inText: (Long) -> Boolean): List<Pair<Long, JniNative>>? {
        if (count < 1 || count > 4000) return null
        val out = ArrayList<Pair<Long, JniNative>>(count)
        for (i in 0 until count) {
            val e = baseOff + i * cfg.methodSize
            val namePtr = frame.slotPtr[e] ?: return null
            val sigPtr = frame.slotPtr[e + cfg.ptrSize] ?: return null
            val fnPtr = (frame.slotPtr[e + 2 * cfg.ptrSize] ?: return null) and 1L.inv()
            val name = elf.cStringAt(namePtr) ?: return null
            val sig = elf.cStringAt(sigPtr) ?: return null
            if (!isMethodName(name) || !isSignature(sig) || !inText(fnPtr)) return null
            out.add(fnPtr to JniNative(name, sig))
        }
        return out
    }

    private fun propagateEnv(elf: ElfFile, cfg: Cfg, starts: LongArray, registered: Map<Long, JniNative>, codeAt: CodeReader): Map<Long, Map<Int, Tag>> {
        val startSet = starts.toHashSet()
        val envFns = HashMap<Long, HashMap<Int, Tag>>()
        val work = ArrayDeque<Long>()
        fun seed(fn: Long, idx: Int, tag: Tag) {
            val s = envFns.getOrPut(fn) { HashMap() }
            if (s.put(idx, tag) != tag) work.add(fn)
        }
        for (fn in registered.keys) seed(fn, 0, Tag.ENV)
        for (f in elf.functions) when {
            f.name == "JNI_OnLoad" || f.name == "JNI_OnUnload" -> seed(f.address, 0, Tag.VM)
            f.name.startsWith("Java_") -> seed(f.address, 0, Tag.ENV)
        }
        var budget = PROPAGATE_BUDGET
        while (work.isNotEmpty() && budget > 0) {
            val fn = work.removeFirst()
            val argv = envFns[fn] ?: continue
            val env = EnvTrack(cfg)
            env.seed(argv)
            for (ins in codeAt.insns(fn)) {
                budget--
                val eff = decode(ins, cfg)
                if (eff.k == K.CALL_DIR && eff.target != null && eff.target in startSet) {
                    for ((i, tag) in env.argTags()) seed(eff.target, i, tag)
                }
                env.track(ins, eff)
            }
        }
        return envFns
    }

    private fun isMethodName(s: String): Boolean =
        s.isNotEmpty() && s.length <= 200 && !s[0].isDigit() && s.all { it.isLetterOrDigit() || it == '_' || it == '$' }

    private fun isSignature(s: String): Boolean {
        if (!s.startsWith("(")) return false
        val close = s.indexOf(')')
        if (close < 1) return false
        var i = 1
        while (i < close) i = skipType(s, i, close, false) ?: return false
        val r = skipType(s, close + 1, s.length, true) ?: return false
        return r == s.length
    }

    private fun skipType(s: String, start: Int, end: Int, allowVoid: Boolean): Int? {
        var j = start
        while (j < end && s[j] == '[') j++
        if (j >= end) return null
        val arr = j > start
        return when (s[j]) {
            'Z', 'B', 'C', 'S', 'I', 'J', 'F', 'D' -> j + 1
            'V' -> if (allowVoid && !arr) j + 1 else null
            'L' -> s.indexOf(';', j + 1).let { semi -> if (semi in (j + 2) until end) semi + 1 else null }
            else -> null
        }
    }

    internal enum class K { LOAD, STORE, LEA, MOVE, CALL_REG, CALL_MEM, CALL_DIR, CLOBBER, NONE }
    internal class Eff(val k: K, val dst: String? = null, val src: String? = null, val base: String? = null, val off: Long = 0, val target: Long? = null)

    private fun decode(ins: Insn, cfg: Cfg): Eff =
        if (cfg.family == Family.ARM) decodeArm(ins) else decodeX86(ins, cfg)

    private val ARM_MOVS = setOf("mov", "movs", "movw", "mov.w", "movz")

    private fun decodeArm(ins: Insn): Eff {
        val m = ins.mnemonic.lowercase()
        val ops = splitOps(ins.operands)
        fun imm(s: String) = s.removePrefix("#").let { if (it.startsWith("0x")) it.substring(2).toLongOrNull(16) else it.toLongOrNull() }
        return when {
            (m.startsWith("ldr") || m.startsWith("ldur")) && ops.size == 2 && ops[1].startsWith("[") -> {
                val (b, o) = armMem(ops[1]); Eff(K.LOAD, dst = ops[0], base = b, off = o)
            }
            (m.startsWith("str") || m.startsWith("stur")) && ops.size == 2 && ops[1].startsWith("[") -> {
                val (b, o) = armMem(ops[1]); Eff(K.STORE, src = ops[0], base = b, off = o)
            }
            m == "add" && ops.size == 3 -> { val o = imm(ops[2]); if (o != null) Eff(K.LEA, dst = ops[0], base = ops[1], off = o) else Eff(K.CLOBBER, dst = ops[0]) }
            m in ARM_MOVS && ops.size == 2 -> Eff(K.MOVE, dst = ops[0], src = ops[1])
            (m == "blr" || m == "br" || m == "blx" || m == "bx") && ops.size == 1 && '[' !in ops[0] && imm(ops[0]) == null -> Eff(K.CALL_REG, src = ops[0])
            (m == "bl" || m == "blx") && ops.size == 1 -> Eff(K.CALL_DIR, target = imm(ops[0]))
            m == "b" || m.startsWith("b.") || m.startsWith("cb") || m.startsWith("tb") -> Eff(K.NONE)
            ops.isNotEmpty() && '[' !in ops[0] -> Eff(K.CLOBBER, dst = ops[0])
            else -> Eff(K.NONE)
        }
    }

    private fun decodeX86(ins: Insn, cfg: Cfg): Eff {
        val m = ins.mnemonic.lowercase()
        val ops = splitOps(ins.operands)
        if (m == "lea" && ops.size == 2) { val (b, o) = x86Mem(ops[1]); return if (b != null) Eff(K.LEA, dst = ops[0], base = b, off = o) else Eff(K.CLOBBER, dst = ops[0]) }
        if (m == "call" || m == "jmp") {
            val t = ops.firstOrNull() ?: return Eff(K.NONE)
            return when {
                '[' in t -> { val (b, o) = x86Mem(t); if (b != null) Eff(K.CALL_MEM, base = b, off = o) else Eff(K.NONE) }
                isReg(t) -> Eff(K.CALL_REG, src = t)
                t.startsWith("0x") -> if (m == "call") Eff(K.CALL_DIR, target = t.substring(2).toLongOrNull(16)) else Eff(K.NONE)
                else -> Eff(K.NONE)
            }
        }
        if (m == "mov" && ops.size == 2) {
            val dst = ops[0]; val src = ops[1]
            return when {
                '[' in dst -> { val (b, o) = x86Mem(dst); if (isReg(src)) Eff(K.STORE, src = src, base = b, off = o) else Eff(K.STORE, base = b, off = o) }
                '[' in src -> { val (b, o) = x86Mem(src); Eff(K.LOAD, dst = dst, base = b, off = o) }
                isReg(src) -> Eff(K.MOVE, dst = dst, src = src)
                else -> Eff(K.CLOBBER, dst = dst)
            }
        }
        if (ops.isNotEmpty() && isReg(ops[0]) && m !in X86_NON_DEST) return Eff(K.CLOBBER, dst = ops[0])
        return Eff(K.NONE)
    }

    private val X86_NON_DEST = setOf("cmp", "test", "push", "ret", "nop", "jmp", "call", "endbr64", "endbr32")

    private fun isReg(s: String): Boolean = s.isNotEmpty() && s[0].isLetter() && s.none { it == '[' || it == ' ' }

    private fun armMem(operand: String): Pair<String?, Long> {
        val inner = operand.removePrefix("[").substringBefore("]").removeSuffix("!")
        val parts = inner.split(",").map { it.trim() }
        val base = parts[0]
        val offTok = parts.getOrNull(1)?.removePrefix("#") ?: return base to 0L
        val v = parseSignedInt(offTok)
        return if (v == null) (null to 0L) else (base to v)
    }

    private fun parseSignedInt(tok: String): Long? {
        val neg = tok.startsWith("-"); val t = tok.removePrefix("-").removePrefix("+")
        val mag = if (t.startsWith("0x")) t.substring(2).toLongOrNull(16) else t.toLongOrNull()
        return mag?.let { if (neg) -it else it }
    }

    private fun x86Mem(operand: String): Pair<String?, Long> {
        val inner = operand.substringAfter('[', "").substringBefore(']')
        if (inner.isEmpty() || '*' in inner) return null to 0L
        val m = Regex("^(\\w+)\\s*([+-])\\s*(0x[0-9a-fA-F]+|\\d+)$").find(inner.trim())
        if (m != null) {
            val v = m.groupValues[3].let { if (it.startsWith("0x")) it.substring(2).toLong(16) else it.toLong() }
            return m.groupValues[1] to (if (m.groupValues[2] == "-") -v else v)
        }
        return if (Regex("^\\w+$").matches(inner.trim())) inner.trim() to 0L else (null to 0L)
    }

    internal class EnvTrack(private val cfg: Cfg) {
        val typedRegs = HashMap<String, Tag>()
        val typedSlots = HashMap<String, Tag>()
        val frameAddr = HashMap<String, String>()
        val derefTag = HashMap<String, Tag>()
        val vtSlot = HashMap<String, Long>()
        val vtTag = HashMap<String, Tag>()
        private var espDelta = 0L
        private val xpush = ArrayList<String?>()

        fun argTags(): Map<Int, Tag> = cfg.argRegs.indices.mapNotNull { i -> typedRegs[cfg.argRegs[i]]?.let { i to it } }.toMap()

        private fun slotKey(base: String?, off: Long): String? = when {
            base == null -> null
            cfg.stackArgs && base == "esp" -> "@${espDelta + off}"
            base in cfg.frameRegs -> "$base,$off"
            else -> null
        }

        fun seed(args: Map<Int, Tag>) {
            for ((i, t) in args) cfg.argRegs.getOrNull(i)?.let { if (',' in it) typedSlots[it] = t else typedRegs[it] = t }
        }

        fun step(ins: Insn): Pair<Tag, Long>? {
            val eff = decode(ins, cfg)
            val info = when (eff.k) {
                K.CALL_REG -> { val t = vtTag[eff.src]; val o = vtSlot[eff.src]; if (t != null && o != null) t to o else null }
                K.CALL_MEM -> derefTag[eff.base]?.let { it to eff.off }
                else -> null
            }
            track(ins, eff)
            return info
        }

        fun track(ins: Insn, eff: Eff = decode(ins, cfg)) {
            when (eff.k) {
                K.CALL_REG, K.CALL_MEM -> {
                    val info = when (eff.k) {
                        K.CALL_REG -> vtTag[eff.src]?.let { it to (vtSlot[eff.src] ?: -1) }
                        else -> derefTag[eff.base]?.let { it to eff.off }
                    }
                    if (info?.first == Tag.VM && info.second == cfg.getEnvOff) {
                        val slot = if (cfg.stackArgs) xpush.getOrNull(xpush.size - 2) else frameAddr[cfg.argRegs[1]]
                        slot?.let { typedSlots[it] = Tag.ENV }
                    }
                    clearCallerSaved()
                }
                K.CALL_DIR -> clearCallerSaved()
                K.LOAD -> {
                    val dst = eff.dst!!
                    val frame = slotKey(eff.base, eff.off)
                    if (frame != null) { clear(dst); typedSlots[frame]?.let { typedRegs[dst] = it } }
                    else {
                        val baseTag = typedRegs[eff.base]; val baseDeref = derefTag[eff.base]
                        clear(dst)
                        if (eff.off == 0L) { if (baseTag != null) derefTag[dst] = baseTag }
                        else if (baseDeref != null) { vtSlot[dst] = eff.off; vtTag[dst] = baseDeref }
                    }
                }
                K.STORE -> slotKey(eff.base, eff.off)?.let { slot ->
                    val t = eff.src?.let { typedRegs[it] }
                    if (t != null) typedSlots[slot] = t else typedSlots.remove(slot)
                }
                K.LEA -> { val dst = eff.dst!!; clear(dst); slotKey(eff.base, eff.off)?.let { frameAddr[dst] = it } }
                K.MOVE -> {
                    val dst = eff.dst!!; val src = eff.src!!
                    val fa = slotKey(src, 0)
                    if (fa != null) { clear(dst); frameAddr[dst] = fa }
                    else { val t = typedRegs[src]; clear(dst); if (t != null) typedRegs[dst] = t }
                }
                K.CLOBBER -> eff.dst?.let { clear(it) }
                K.NONE -> {}
            }
            if (cfg.stackArgs) updateStack(ins, eff)
        }

        private fun updateStack(ins: Insn, eff: Eff) {
            val m = ins.mnemonic.lowercase()
            val ops = splitOps(ins.operands)
            fun imm(s: String) = if (s.startsWith("0x")) s.substring(2).toLongOrNull(16) else s.toLongOrNull()
            when {
                m == "push" && ops.size == 1 -> { espDelta -= 4; xpush.add(frameAddr[ops[0]]) }
                m == "pop" -> { espDelta += 4; if (xpush.isNotEmpty()) xpush.removeAt(xpush.size - 1) }
                m == "and" && ops.getOrNull(0) == "esp" -> espDelta = 0
                m == "sub" && ops.getOrNull(0) == "esp" -> imm(ops.getOrElse(1) { "" })?.let { espDelta -= it }
                m == "add" && ops.getOrNull(0) == "esp" -> imm(ops.getOrElse(1) { "" })?.let { espDelta += it }
                eff.k == K.CALL_DIR && eff.target == ins.address + ins.size -> espDelta -= 4
                eff.k == K.CALL_REG || eff.k == K.CALL_MEM || eff.k == K.CALL_DIR -> xpush.clear()
            }
        }

        private fun clear(r: String) { typedRegs.remove(r); frameAddr.remove(r); derefTag.remove(r); vtSlot.remove(r); vtTag.remove(r) }

        private fun clearCallerSaved() {
            val caller = if (cfg.family == Family.ARM) ARM_CALLER else X86_CALLER
            for (r in caller) clear(r)
        }
    }

    private val ARM_CALLER = (0..18).map { "x$it" } + (0..3).map { "r$it" } + listOf("r12", "ip", "lr")
    private val X86_CALLER = listOf("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "eax", "ecx", "edx")

    private fun trackRegAddr(regAddr: HashMap<String, Long>, litVal: HashMap<String, Long>, ins: Insn, eff: Eff, cfg: Cfg, elf: ElfFile, frame: ArmFrame?) {
        val m = ins.mnemonic.lowercase()
        val ops = splitOps(ins.operands)
        fun imm(s: String) = s.removePrefix("#").let { if (it.startsWith("0x")) it.substring(2).toLongOrNull(16) else it.toLongOrNull() }
        if (cfg.family == Family.ARM) {
            val thumb = elf.armThumbAt(ins.address)
            fun pcLit() = if (thumb) (ins.address + 4) and 3L.inv() else ins.address + 8
            fun pcReg() = if (thumb) ins.address + 4 else ins.address + 8
            val fpRegs = cfg.frameRegs - "sp"
            fun fOff(base: String, off: Long) = if (base == "sp") off - (frame?.x29Delta ?: 0L) else off
            when {
                frame != null && m == "add" && ops.size == 3 && ops[0] in fpRegs && ops[1] == "sp" -> { imm(ops[2])?.let { frame.x29Delta = it } }
                frame != null && m == "mov" && ops.size == 2 && ops[0] in fpRegs && ops[1] == "sp" -> { frame.x29Delta = 0 }
                frame != null && (m == "add" || m == "sub") && ops.size == 3 && (ops[1] == "sp" || ops[1] in fpRegs) -> {
                    regAddr.remove(ops[0]); val o = imm(ops[2])
                    if (o != null) frame.addrReg[ops[0]] = fOff(ops[1], if (m == "sub") -o else o) else frame.addrReg.remove(ops[0])
                }
                frame != null && m == "mov" && ops.size == 2 && (ops[1] == "sp" || ops[1] in fpRegs) -> { regAddr.remove(ops[0]); frame.addrReg[ops[0]] = fOff(ops[1], 0) }
                frame != null && (m == "str" || m == "stur") && ops.size == 2 && ops[1].startsWith("[") -> {
                    val (b, o) = armMem(ops[1]); if (b == "sp" || b in fpRegs) { val k = fOff(b!!, o); regAddr[ops[0]]?.let { frame.slotPtr[k] = it } ?: frame.slotPtr.remove(k) }
                }
                frame != null && (m == "stp" || m == "stnp") && ops.size == 3 && ops[2].startsWith("[") -> {
                    val (b, o) = armMem(ops[2]); if (b == "sp" || b in fpRegs) { val k = fOff(b!!, o)
                        regAddr[ops[0]]?.let { frame.slotPtr[k] = it } ?: frame.slotPtr.remove(k)
                        regAddr[ops[1]]?.let { frame.slotPtr[k + cfg.ptrSize] = it } ?: frame.slotPtr.remove(k + cfg.ptrSize) }
                }
                frame != null && (m.startsWith("ldr") || m.startsWith("ldur")) && ops.size == 2 && ops[1].startsWith("[") && armMem(ops[1]).first.let { it == "sp" || it in fpRegs } -> {
                    val (b, o) = armMem(ops[1]); val k = fOff(b!!, o); litVal.remove(ops[0]); frame.slotPtr[k]?.let { regAddr[ops[0]] = it } ?: regAddr.remove(ops[0])
                }
                (m == "adrp" || m == "adr") && ops.size == 2 -> { val v = imm(ops[1]); if (v != null) regAddr[ops[0]] = v else regAddr.remove(ops[0]) }
                m.startsWith("ldr") && ops.size == 2 && ops[1].startsWith("[") && "pc" in ops[1] -> {
                    val o = armMem(ops[1]).second; val lit = elf.readInt(pcLit() + o)?.toLong()
                    regAddr.remove(ops[0]); if (lit != null) litVal[ops[0]] = lit else litVal.remove(ops[0])
                }
                m == "add" && ops.size == 3 && ops[1] == "pc" -> { val lv = litVal[ops[2]]; if (lv != null) regAddr[ops[0]] = pcReg() + lv else regAddr.remove(ops[0]); litVal.remove(ops[0]) }
                m == "add" && ops.size == 2 && ops[1] == "pc" -> { val lv = litVal[ops[0]] ?: regAddr[ops[0]]; if (lv != null) regAddr[ops[0]] = pcReg() + lv else regAddr.remove(ops[0]); litVal.remove(ops[0]) }
                m == "add" && ops.size == 3 -> { val b = regAddr[ops[1]]; val o = imm(ops[2]); if (b != null && o != null) regAddr[ops[0]] = b + o else regAddr.remove(ops[0]) }
                m in ARM_MOVS && ops.size == 2 -> { val i = imm(ops[1]); val c = regAddr[ops[1]]; if (i != null) regAddr[ops[0]] = i else if (c != null) regAddr[ops[0]] = c else regAddr.remove(ops[0]) }
                ops.isNotEmpty() && '[' !in ops[0] -> { regAddr.remove(ops[0]); litVal.remove(ops[0]) }
            }
        } else {
            fun hex(s: String) = if (s.startsWith("0x")) s.substring(2).toLongOrNull(16) else s.toLongOrNull()
            when {
                m == "lea" && ops.size == 2 && ops[1].contains("rip") -> { val (_, o) = x86Mem(ops[1]); regAddr[ops[0]] = ins.address + ins.size + o }
                m == "lea" && ops.size == 2 -> { val (b, o) = x86Mem(ops[1]); val base = if (b != null) regAddr[b] else null; if (base != null) regAddr[ops[0]] = base + o else regAddr.remove(ops[0]) }
                m == "add" && ops.size == 2 && isReg(ops[0]) -> { val v = hex(ops[1]); val cur = regAddr[ops[0]]; if (v != null && cur != null) regAddr[ops[0]] = cur + v else regAddr.remove(ops[0]) }
                m == "mov" && ops.size == 2 && '[' !in ops[0] -> { val v = hex(ops[1]); val c = regAddr[ops[1]]; if (v != null) regAddr[ops[0]] = v else if (c != null) regAddr[ops[0]] = c else regAddr.remove(ops[0]) }
                ops.isNotEmpty() && isReg(ops[0]) && m !in X86_NON_DEST -> regAddr.remove(ops[0])
            }
        }
    }

    private fun applyDeref(derefZero: HashSet<String>, vtSlot: HashMap<String, Long>, eff: Eff) {
        when (eff.k) {
            K.LOAD -> {
                val dst = eff.dst!!
                if (eff.off == 0L) { derefZero.add(dst); vtSlot.remove(dst) }
                else { val based = eff.base in derefZero; derefZero.remove(dst); if (based) vtSlot[dst] = eff.off else vtSlot.remove(dst) }
            }
            K.MOVE, K.LEA, K.CLOBBER -> eff.dst?.let { derefZero.remove(it); vtSlot.remove(it) }
            else -> {}
        }
    }

    private fun splitOps(s: String): List<String> {
        val out = ArrayList<String>(); var depth = 0; val sb = StringBuilder()
        for (c in s) when (c) {
            '[', '{' -> { depth++; sb.append(c) }
            ']', '}' -> { depth--; sb.append(c) }
            ',' -> if (depth == 0) { out.add(sb.toString().trim()); sb.clear() } else sb.append(c)
            else -> sb.append(c)
        }
        if (sb.isNotBlank()) out.add(sb.toString().trim())
        return out
    }

    private fun floorStart(starts: LongArray, addr: Long): Long {
        var lo = 0; var hi = starts.size - 1; var res = addr
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            if (starts[mid] <= addr) { res = starts[mid]; lo = mid + 1 } else hi = mid - 1
        }
        return res
    }

    private fun word32(b: ByteArray, i: Int, little: Boolean): Long {
        val b0 = b[i].toLong() and 0xFF; val b1 = b[i + 1].toLong() and 0xFF
        val b2 = b[i + 2].toLong() and 0xFF; val b3 = b[i + 3].toLong() and 0xFF
        return if (little) b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)
        else b3 or (b2 shl 8) or (b1 shl 16) or (b0 shl 24)
    }
}
