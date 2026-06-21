package io.github.nitanmarcel.jdex.disasm

object NativePseudo {

    private enum class A { ARM, X86, MIPS }

    private class PIns(val addr: Long, val mnem: String, val ops: List<String>, val opsStr: String, val comment: String?)

    private fun parse(lines: List<String>): List<PIns> {
        val insns = ArrayList<PIns>()
        for (raw in lines) {
            val t = raw.trimStart()
            if (t.length < 10 || t[8] != ':') continue
            val addr = t.substring(0, 8).toLongOrNull(16) ?: continue
            val ci = t.indexOf("  ; ")
            val body = if (ci >= 0) t.substring(0, ci) else t
            val comment = if (ci >= 0) t.substring(ci + 4).trim() else null
            val (mnem, ops, opsStr) = parseFull(body) ?: continue
            insns.add(PIns(addr, mnem, ops, opsStr, comment))
        }
        return insns
    }

    private fun isFuncLabel(line: String): Boolean {
        val t = line.trim()
        return t.endsWith(":") && t.length > 1 && (t[0].isLetter() || t[0] == '_') && !t.startsWith("loc_") && ' ' !in t
    }

    fun argCount(lines: List<String>): Int {
        var start = 0
        while (start < lines.size && !isFuncLabel(lines[start])) start++
        if (start >= lines.size) start = 0
        var end = lines.size
        for (i in start + 1 until lines.size) if (isFuncLabel(lines[i])) { end = i; break }
        val fn = lines.subList(start, end)
        val insns = parse(fn)
        return detectArgs(argSpec(detectArch(fn), insns), insns).size
    }

    class PseudoCode(val text: String, val lineAddrs: LongArray)

    fun forFunction(name: String, lines: List<String>, x86Is32: Boolean? = null, calleeArgs: (String) -> Int? = { null }): String =
        forFunctionMapped(name, lines, x86Is32, calleeArgs).text

    fun forFunctionMapped(name: String, lines: List<String>, x86Is32: Boolean? = null, calleeArgs: (String) -> Int? = { null }): PseudoCode {
        val arch = detectArch(lines)
        val insns = parse(lines)
        val spec = argSpec(arch, insns, x86Is32)
        val funcArgs = detectArgs(spec, insns)
        val ret = if (returnsValue(arch, insns)) "" else "void "
        val sb = StringBuilder()
        sb.append("// ").append(name).append("\n").append(ret).append(funcName(name)).append("(")
            .append(funcArgs.joinToString(", ")).append(")\n{\n")
        if (insns.isEmpty()) { sb.append("}\n"); return PseudoCode(sb.toString(), LongArray(4) { -1L }) }

        val leaders = sortedSetOf(insns.first().addr)
        for (i in insns.indices) {
            val ins = insns[i]
            if (endsBlock(arch, ins)) {
                insns.getOrNull(if (arch == A.MIPS) i + 2 else i + 1)?.let { leaders.add(it.addr) }
                locTarget(ins)?.let { leaders.add(it) }
            }
            if (ins.comment?.startsWith("switch (") == true)
                locRef.findAll(ins.comment).forEach { m -> m.groupValues[1].toLongOrNull(16)?.let { leaders.add(it) } }
        }

        val (armFoldVal, armFoldSkip) = if (arch == A.ARM) computeArmFolds(insns, leaders)
            else emptyMap<Long, Long>() to emptySet<Long>()

        val blocks = ArrayList<NativeStructurer.SBlock>()
        var i = 0
        while (i < insns.size) {
            val start = insns[i].addr
            val stmts = ArrayList<String>()
            val stmtAddrs = ArrayList<Long>()
            var termAddr = start
            var term: NativeStructurer.Term = NativeStructurer.Term.Fall
            var cmp: Pair<String, List<String>>? = null
            val defined = BooleanArray(spec.size)
            if (start == insns.first().addr) for (k in funcArgs.indices) defined[k] = true
            while (i < insns.size) {
                val ins = insns[i]
                if (ins.addr != start && ins.addr in leaders) break
                i++
                if (armWidth(ins.mnem) in COMPARE) { cmp = armWidth(ins.mnem) to ins.ops; continue }
                if (vfpBase(ins.mnem) == "vcmp" || vfpBase(ins.mnem) == "vcmpe") { cmp = "cmp" to ins.ops; continue }
                if (ins.mnem.lowercase() == "vmrs") continue
                if (isArmCondCompare(ins.mnem) || ins.mnem.lowercase() in setOf("ccmp", "ccmn")) cmp = null
                if (endsBlock(arch, ins)) {
                    var branchIns = ins
                    if (arch == A.MIPS) insns.getOrNull(i)?.let { ds ->
                        if (ds.addr !in leaders) {
                            i++
                            val dest = if (mipsWritesReg(ds)) ds.ops.getOrNull(0) else null
                            if (dest != null && dest.startsWith("$") && ins.ops.any { it == dest }) {
                                stmts.add("${dest}_pre = $dest"); stmtAddrs.add(ins.addr)
                                branchIns = PIns(ins.addr, ins.mnem,
                                    ins.ops.map { if (it == dest) "${dest}_pre" else it },
                                    ins.opsStr.replace(Regex(Regex.escape(dest) + """\b""")) { "${dest}_pre" }, ins.comment)
                            }
                            stmtOf(arch, ds, cmp)?.let { if (it.isNotEmpty()) { stmts.add(it); stmtAddrs.add(ds.addr) } }
                        }
                    }
                    termAddr = ins.addr; term = terminator(arch, branchIns, cmp); break
                }
                if (isFrameOp(arch, ins)) continue
                if (ins.mnem == "adrp") {
                    val nx = insns.getOrNull(i)
                    if (nx != null && nx.addr !in leaders && nx.ops.firstOrNull() == ins.ops.firstOrNull() &&
                        (nx.mnem == "add" || nx.mnem.startsWith("ldr")) && nx.comment?.startsWith("\"") == true) continue
                }
                if (ins.mnem in CALL_MNEMS) {
                    val raw = ins.ops.getOrNull(0) ?: ins.opsStr
                    val argc = (calleeArgs(raw) ?: run { var a = 0; for (s in defined.indices) if (defined[s]) a = s + 1; a }).coerceIn(0, spec.size)
                    val tgt = mem(raw)
                    val call = "$tgt(${(0 until argc).joinToString(", ") { spec[it].second }})"
                    val jni = ins.comment?.takeIf { it.startsWith("JNIEnv->") || it.startsWith("JavaVM->") }
                    stmts.add(if (jni != null) "$call /* $jni */" else call); stmtAddrs.add(ins.addr)
                    defined.fill(false)
                    cmp = null
                    if (NORETURN.containsMatchIn(raw)) { termAddr = ins.addr; term = NativeStructurer.Term.Return; break }
                    continue
                }
                if (ins.addr in armFoldSkip) continue
                val foldV = armFoldVal[ins.addr]
                if (foldV != null) {
                    stmts.add("${ins.ops[0]} = 0x${java.lang.Long.toHexString(foldV)}"); stmtAddrs.add(ins.addr)
                    for (slot in spec.indices) if (spec[slot].first.containsMatchIn(ins.ops[0])) defined[slot] = true
                    cmp = null
                    continue
                }
                stmtOf(arch, ins, cmp)?.let { if (it.isNotEmpty()) { stmts.add(it); stmtAddrs.add(ins.addr) } }
                if (ins.ops.isNotEmpty() && setsFlags(arch, ins.mnem)) cmp = flagCompare(ins.mnem, ins.ops)
                if (writesDest(ins.mnem, ins.ops)) {
                    for (slot in spec.indices) if (spec[slot].first.containsMatchIn(ins.ops[0])) defined[slot] = true
                    if ((ins.mnem == "ldp" || ins.mnem == "ldpsw") && ins.ops.size > 1)
                        for (slot in spec.indices) if (spec[slot].first.containsMatchIn(ins.ops[1])) defined[slot] = true
                }
            }
            blocks.add(NativeStructurer.SBlock(start, stmts, term, stmtAddrs, termAddr))
        }

        val structured = NativeStructurer.structureMapped(blocks)
        sb.append(structured.text)
        sb.append("}\n")
        val addrs = LongArray(3 + structured.lineAddrs.size + 1) { -1L }
        structured.lineAddrs.copyInto(addrs, 3)
        return PseudoCode(sb.toString(), addrs)
    }

    private val UNCOND = setOf("b", "jmp", "j")
    private val INDIRECT = setOf("br", "bx", "eret")
    private val RETURN = setOf("ret", "retn", "retaa", "retab", "leave")
    private val locRef = Regex("""\bloc_([0-9a-fA-F]+)\b""")

    private fun locTarget(ins: PIns): Long? = locRef.find(ins.opsStr)?.groupValues?.get(1)?.toLongOrNull(16)

    private fun isArmCondCompare(mnem0: String): Boolean {
        val m = armWidth(mnem0)
        return m.length == 5 && m.takeLast(2) in ARM_COND && m.dropLast(2) in setOf("cmp", "cmn", "tst")
    }

    private fun isCond(mnem0: String): Boolean {
        val mnem = armWidth(mnem0)
        return when {
            mnem == "cbz" || mnem == "cbnz" || mnem == "tbz" || mnem == "tbnz" -> true
            mnem.startsWith("b.") -> true
            mnem.length > 1 && mnem[0] == 'b' && mnem !in UNCOND && mnem != "bl" && mnem != "blr" &&
                mnem != "blx" && mnem !in INDIRECT && armCond(mnem.substring(1)) != null -> true
            mnem.length > 1 && mnem[0] == 'j' && mnem != "jmp" -> true
            else -> false
        }
    }

    private val MIPS_COND = setOf(
        "beq", "bne", "beqz", "bnez", "blez", "bgtz", "bltz", "bgez",
        "beql", "bnel", "blezl", "bgtzl", "bltzl", "bgezl", "bc1t", "bc1f",
        "bc1tl", "bc1fl",
    )

    private fun endsBlock(arch: A, ins: PIns): Boolean {
        val m = ins.mnem
        if (arch == A.MIPS) return m == "jr" || m == "j" || m == "b" || m in MIPS_COND
        val mw = armWidth(m)
        return mw in RETURN || mw in UNCOND || mw in INDIRECT || isCond(mw) ||
            ((mw == "jmp" || mw == "br" || mw == "bx") && locTarget(ins) == null)
    }

    private fun terminator(arch: A, ins: PIns, cmp: Pair<String, List<String>>?): NativeStructurer.Term {
        val loc = locTarget(ins)
        if (arch == A.MIPS) return mipsTerm(ins, loc)
        val m = armWidth(ins.mnem)
        val switch = ins.comment?.takeIf { it.startsWith("switch (") }
        val jniTail = ins.comment?.takeIf { it.startsWith("JNIEnv->") || it.startsWith("JavaVM->") }
        return when {
            m in RETURN -> NativeStructurer.Term.Return
            switch != null -> {
                val reg = switch.substringAfter("(").substringBefore(")").trim()
                val cases = locRef.findAll(switch).mapNotNull { it.groupValues[1].toLongOrNull(16) }.toList()
                if (cases.isEmpty()) NativeStructurer.Term.Indirect("goto *${ins.opsStr}")
                else NativeStructurer.Term.Switch(reg, cases)
            }
            jniTail != null && (m in INDIRECT || m in UNCOND) ->
                NativeStructurer.Term.Indirect("return ${ins.opsStr}() /* $jniTail */")
            m == "eret" -> NativeStructurer.Term.Return
            m in INDIRECT && (ins.opsStr == "lr" || ins.opsStr == "x30" || ins.opsStr == "r14") -> NativeStructurer.Term.Return
            m in INDIRECT -> NativeStructurer.Term.Indirect("goto *${ins.opsStr}")
            isCond(m) -> {
                val cond = condOf(m, ins.ops, cmp)
                if (loc != null) NativeStructurer.Term.Cond(cond, loc)
                else NativeStructurer.Term.Indirect("if ($cond) goto ${ins.ops.lastOrNull() ?: ins.opsStr}")
            }
            m in UNCOND -> when {
                loc != null -> NativeStructurer.Term.Goto(loc)
                ins.opsStr.startsWith("sub_") || (arch == A.ARM && !ins.opsStr.startsWith("0x")) ->
                    NativeStructurer.Term.Indirect("return ${ins.opsStr}()")
                else -> NativeStructurer.Term.Indirect("goto ${ins.opsStr}")
            }
            else -> NativeStructurer.Term.Indirect("goto ${ins.opsStr}")
        }
    }

    private fun mipsTerm(ins: PIns, loc: Long?): NativeStructurer.Term {
        val m = ins.mnem
        val r0 = ins.ops.getOrElse(0) { "" }
        val tgt = ins.ops.lastOrNull() ?: ins.opsStr
        return when {
            m == "jr" && (r0 == "ra" || r0 == "\$ra") -> NativeStructurer.Term.Return
            m == "jr" -> NativeStructurer.Term.Indirect("goto *$r0")
            (m == "j" || m == "b") && loc != null -> NativeStructurer.Term.Goto(loc)
            (m == "j" || m == "b") -> NativeStructurer.Term.Indirect("goto $tgt")
            loc != null -> NativeStructurer.Term.Cond(mipsCond(m, ins.ops), loc)
            else -> NativeStructurer.Term.Indirect("if (${mipsCond(m, ins.ops)}) goto $tgt")
        }
    }

    private val MIPS_NO_DEST = setOf(
        "sw", "sb", "sh", "sd", "swl", "swr", "swc1", "sdc1", "nop", "sync", "teq", "break",
        "beq", "bne", "beqz", "bnez", "bgtz", "bltz", "bgez", "blez", "b", "j", "jr", "jal", "jalr", "bal",
        "mtlo", "mthi", "mtc1", "dmtc1",
        "mult", "multu", "dmult", "dmultu", "div", "divu", "ddiv", "ddivu",
    )
    private fun mipsWritesReg(ins: PIns): Boolean =
        ins.ops.firstOrNull()?.startsWith("$") == true && ins.mnem !in MIPS_NO_DEST

    private fun mipsCond(m: String, ops: List<String>): String {
        fun o(i: Int) = ops.getOrElse(i) { "?" }
        return when (m) {
            "beq", "beql" -> "${o(0)} == ${o(1)}"
            "bne", "bnel" -> "${o(0)} != ${o(1)}"
            "beqz" -> "${o(0)} == 0"
            "bnez" -> "${o(0)} != 0"
            "blez", "blezl" -> "${o(0)} <= 0"
            "bgtz", "bgtzl" -> "${o(0)} > 0"
            "bltz", "bltzl" -> "${o(0)} < 0"
            "bgez", "bgezl" -> "${o(0)} >= 0"
            "bc1t", "bc1tl" -> "fp_cond"
            "bc1f", "bc1fl" -> "!fp_cond"
            else -> "??"
        }
    }

    private fun condOf(mnem0: String, ops: List<String>, cmp: Pair<String, List<String>>?): String {
        fun o(i: Int) = ops.getOrElse(i) { "?" }
        val mnem = armWidth(mnem0)
        return when {
            mnem == "cbz" -> "${o(0)} == 0"
            mnem == "cbnz" -> "${o(0)} != 0"
            mnem == "tbz" -> "(${o(0)} & (1LL << ${o(1)})) == 0"
            mnem == "tbnz" -> "(${o(0)} & (1LL << ${o(1)})) != 0"
            mnem.startsWith("b.") -> cond(mnem.substring(2), cmp)
            mnem[0] == 'j' -> cond(mnem.substring(1), cmp)
            else -> cond(mnem.substring(1), cmp)
        }
    }

    private fun stmtOf(arch: A, ins: PIns, cmp: Pair<String, List<String>>?): String? {
        if (ins.comment != null && ins.comment.startsWith("\"") && ins.mnem in DATA_REF)
            return "${ins.ops.getOrElse(0) { "?" }} = ${ins.comment}"
        if (arch == A.MIPS && ins.comment != null && (ins.mnem == "lw" || ins.mnem == "ld") &&
            !ins.comment.startsWith("\"") && !ins.comment.startsWith("switch ("))
            return "${ins.ops.getOrElse(0) { "?" }} = ${ins.comment}"
        return translate(arch, ins.mnem, ins.ops, cmp)
    }

    private val X86_FLAG_OPS = setOf(
        "add", "sub", "and", "or", "xor", "shl", "shr", "sar", "sal", "inc", "dec", "neg", "imul", "adc", "sbb",
        "bt", "bts", "btr", "btc",
    )
    private val X86_BIT_TEST = setOf("bt", "bts", "btr", "btc")
    private val ARM_FLAG_OPS = setOf(
        "adds", "subs", "ands", "orrs", "eors", "bics", "negs", "muls", "lsls", "lsrs", "asrs", "rsbs",
        "adcs", "sbcs", "rscs", "ngcs", "rors", "orns", "movs", "mvns",
    )

    private fun armWidth(m: String): String = if (m.endsWith(".w") || m.endsWith(".n")) m.dropLast(2) else m

    private fun vfpBase(m: String): String = armWidth(m).substringBefore('.')

    private fun flagCompare(mnem: String, ops: List<String>): Pair<String, List<String>> {
        if (mnem in X86_BIT_TEST) return "bt" to listOf(ops.getOrElse(0) { "?" }, ops.getOrElse(1) { "0" })
        val base = armWidth(mnem).removeSuffix("s")
        return when {
            base == "sub" && ops.size >= 3 -> "cmp" to (listOf(ops[1], ops[2]) + listOfNotNull(ops.getOrNull(3)?.takeIf { isShiftMod(it) }))
            else -> "cmp" to listOf(ops[0], "0")
        }
    }

    private fun setsFlags(arch: A, mnem: String): Boolean = when (arch) {
        A.X86 -> mnem in X86_FLAG_OPS
        A.ARM -> armWidth(mnem) in ARM_FLAG_OPS
        A.MIPS -> false
    }

    private val ARM_COND = setOf(
        "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc",
        "hi", "ls", "ge", "lt", "gt", "le", "al",
    )

    private fun armCond(suffix: String): String? = if (suffix in ARM_COND) suffix else null

    private val CALL_MNEMS = setOf("bl", "blr", "blx", "call", "jal", "jalr", "bal")
    private val NORETURN = Regex("""\b(abort|exit|_exit|__assert_fail|__assert2|__stack_chk_fail|__cxa_throw|__cxa_rethrow|_Unwind_Resume|_ZSt9terminatev|longjmp|siglongjmp|pthread_exit)\b""")
    private val NO_DEST = setOf(
        "cmp", "cmn", "tst", "test", "push", "ret", "retn", "retaa", "retab", "eret",
        "call", "jmp", "b", "bl", "blr", "br", "bx", "blx", "nop", "brk", "hlt", "ud2",
        "sw", "sb", "sh", "swl", "swr", "sd", "beqz", "bnez",
    )

    private fun writesDest(mnem: String, ops: List<String>): Boolean {
        if (ops.isEmpty() || '[' in ops[0]) return false
        if (mnem in NO_DEST) return false
        if (mnem.startsWith("st")) return false
        if (mnem.startsWith("b.") || mnem[0] == 'j' || mnem.startsWith("cb") || mnem.startsWith("tb")) return false
        if (mnem.length > 1 && mnem[0] == 'b' && armCond(mnem.substring(1)) != null) return false
        return true
    }

    private val x86_64Reg = Regex("""\b(r[abcd]x|rsi|rdi|rbp|rsp|rip|r8|r9|r1[0-5])[bwd]?\b""")
    private val x86_32MemBase = Regex("""\[e(ax|bx|cx|dx|si|di|bp|sp)\b""")
    private fun isX86_32(sample: String): Boolean =
        !x86_64Reg.containsMatchIn(sample) && x86_32MemBase.containsMatchIn(sample)

    private fun argSpec(arch: A, insns: List<PIns>, x86Is32: Boolean? = null): List<Pair<Regex, String>> {
        val sample = insns.joinToString(" ") { it.opsStr }
        return when (arch) {
            A.ARM -> if (Regex("""\b[xw]\d""").containsMatchIn(sample)) (0..7).map { Regex("""\b[xw]$it\b""") to "x$it" }
            else (0..3).map { Regex("""\br$it\b""") to "r$it" }
            A.X86 -> if (x86Is32 ?: isX86_32(sample)) emptyList()
            else listOf(
                Regex("""\b(rdi|edi|dil)\b""") to "rdi",
                Regex("""\b(rsi|esi|sil)\b""") to "rsi",
                Regex("""\b(rdx|edx|dl)\b""") to "rdx",
                Regex("""\b(rcx|ecx|cl)\b""") to "rcx",
                Regex("""\b(r8|r8d|r8w|r8b)\b""") to "r8",
                Regex("""\b(r9|r9d|r9w|r9b)\b""") to "r9",
            )
            A.MIPS -> (0..3).map { Regex("""\$?a$it\b""") to "a$it" }
        }
    }

    private fun returnsValue(arch: A, insns: List<PIns>): Boolean {
        if (arch != A.X86) return true
        val retRx = Regex("""\b(rax|eax|ax|al|xmm0)\b""")
        val retSites = ArrayList<Int>()
        for ((i, ins) in insns.withIndex()) {
            if (writesDest(ins.mnem, ins.ops) && retRx.containsMatchIn(ins.ops[0])) return true
            if (ins.mnem in UNCOND && locTarget(ins) == null) return true
            if (ins.mnem in RETURN) retSites.add(i)
        }
        for (r in retSites) for (j in r - 1 downTo maxOf(0, r - 6)) if (insns[j].mnem in CALL_MNEMS) return true
        return false
    }

    private fun detectArgs(spec: List<Pair<Regex, String>>, insns: List<PIns>): List<String> {
        if (spec.isEmpty()) return emptyList()
        val state = IntArray(spec.size)
        for (ins in insns) {
            if (ins.mnem in CALL_MNEMS) break
            val writes = writesDest(ins.mnem, ins.ops)
            val dest = if (writes) ins.ops.getOrNull(0) else null
            val dest2 = if (writes && (ins.mnem == "ldp" || ins.mnem == "ldpsw")) ins.ops.getOrNull(1) else null
            val selfZero = ins.ops.size == 2 && ins.ops[0] == ins.ops[1] &&
                ins.mnem in setOf("xor", "eor", "sub", "pxor", "xorps", "xorpd")
            val reads = StringBuilder()
            if (!selfZero) ins.ops.forEachIndexed { i, op -> if (!((i == 0 && dest != null) || (i == 1 && dest2 != null))) reads.append(op).append(' ') }
            val readText = reads.toString()
            for (slot in spec.indices) if (state[slot] == 0) {
                val rx = spec[slot].first
                if (rx.containsMatchIn(readText)) state[slot] = 1
                else if ((dest != null && rx.containsMatchIn(dest)) || (dest2 != null && rx.containsMatchIn(dest2))) state[slot] = 2
            }
        }
        val maxArg = state.indexOfLast { it == 1 }
        return if (maxArg < 0) emptyList() else spec.subList(0, maxArg + 1).map { it.second }
    }

    private val ARM_CALLEE = Regex("""^[xw](19|2[0-8]|29|30)$|^(lr|fp)$""")
    private val X86_CALLEE = setOf("rbp", "rbx", "r12", "r13", "r14", "r15")

    private fun isFrameOp(arch: A, ins: PIns): Boolean {
        val m = ins.mnem; val ops = ins.ops
        return when (arch) {
            A.ARM -> when {
                (m == "stp" || m == "ldp") && ops.size >= 3 && ops.any { "sp" in it || "x29" in it } &&
                    ARM_CALLEE.matches(ops[0]) && ARM_CALLEE.matches(ops[1]) -> true
                (m == "str" || m == "ldr") && ops.size == 2 && ARM_CALLEE.matches(ops[0]) && "[sp" in ops[1] -> true
                (m == "sub" || m == "add") && ops.size >= 2 && ops[0] == "sp" && ops[1] == "sp" -> true
                (m == "mov" || m == "add") && ops.size >= 2 && ops[0] == "x29" && ops[1] == "sp" -> true
                else -> false
            }
            A.X86 -> when {
                (m == "push" || m == "pop") && ops.size == 1 && ops[0] in X86_CALLEE -> true
                m == "mov" && ops.size == 2 && ops[0] == "rbp" && ops[1] == "rsp" -> true
                (m == "sub" || m == "add") && ops.size >= 2 && ops[0] == "rsp" -> true
                else -> false
            }
            A.MIPS -> false
        }
    }

    private val X86_PREFIXES = setOf("notrack", "bnd", "lock", "rep", "repe", "repz", "repne", "repnz")

    private fun parseFull(t: String): Triple<String, List<String>, String>? {
        val rest = t.substring(9).trim()
        val sp = rest.indexOf(' ')
        if (sp < 0) return null
        var afterBytes = rest.substring(sp).trim()
        if (afterBytes.isEmpty()) return null
        var mnem = afterBytes.takeWhile { !it.isWhitespace() }.lowercase()
        while (mnem in X86_PREFIXES) {
            afterBytes = afterBytes.substring(mnem.length).trim()
            mnem = afterBytes.takeWhile { !it.isWhitespace() }.lowercase()
        }
        val opsStr = afterBytes.substring(mnem.length).trim()
        return Triple(mnem, splitOps(opsStr), opsStr)
    }

    private val ATOMIC_LOADS = setOf("ldar", "ldarb", "ldarh", "ldapr", "ldaxr", "ldxr", "ldaxrb", "ldaxrh", "ldxrb", "ldxrh",
        "lda", "ldab", "ldah", "ldaex", "ldaexb", "ldaexh")
    private val ARM_PARALLEL = setOf(
        "sadd16", "qadd16", "shadd16", "uadd16", "uqadd16", "uhadd16",
        "ssub16", "qsub16", "shsub16", "usub16", "uqsub16", "uhsub16",
        "sadd8", "qadd8", "shadd8", "uadd8", "uqadd8", "uhadd8",
        "ssub8", "qsub8", "shsub8", "usub8", "uqsub8", "uhsub8",
        "sasx", "qasx", "shasx", "uasx", "uqasx", "uhasx",
        "ssax", "qsax", "shsax", "usax", "uqsax", "uhsax",
    )
    private val ARM_HINTS = setOf("yield", "wfe", "wfi", "sev", "sevl", "setend", "dbg", "clrex", "csdb", "esb", "pssbb", "ssbb")
    private val ARM_CP_DATA = setOf("mrc", "mcr", "mrc2", "mcr2", "cdp", "cdp2", "ldc", "ldc2", "stc", "stc2")
    private val ARM_CP_DATA2 = setOf("mrrc", "mcrr", "mrrc2", "mcrr2")
    private val COMPARE = setOf("cmp", "test", "cmn", "tst", "cmpl", "cmpb", "cmpw", "cmpq")
    private val DATA_REF = setOf("add", "adr", "adrp", "ldr", "lea")
    private val SSE_REG = Regex("""\b[xyz]?mm\d""")

    private fun splitOps(s: String): List<String> {
        if (s.isBlank()) return emptyList()
        val out = ArrayList<String>(); var depth = 0; val sb = StringBuilder()
        for (c in s) when (c) {
            '[', '{' -> { depth++; sb.append(c) }
            ']', '}' -> { depth--; sb.append(c) }
            ',' -> if (depth == 0) { out.add(sb.toString().trim()); sb.clear() } else sb.append(c)
            else -> sb.append(c)
        }
        if (sb.isNotBlank()) out.add(sb.toString().trim())
        return out.map { it.removePrefix("#") }
    }

    private fun mipsMem(op: String, deref: Boolean): String? {
        val paren = op.indexOf('(')
        if ('[' in op || paren < 0 || !op.endsWith(")")) return null
        val base = op.substring(paren + 1, op.length - 1).trim()
        if (base.isEmpty()) return null
        val off = op.substring(0, paren).trim()
        val addr = when {
            off.isEmpty() || off == "0" -> base
            off.startsWith("-") -> "($base - ${off.drop(1)})"
            else -> "($base + $off)"
        }
        return if (deref) "*$addr" else addr
    }

    private fun mem(op: String): String {
        if (op == "xzr" || op == "wzr") return "0"
        mipsMem(op, deref = true)?.let { return it }
        val bracket = op.indexOf('[')
        if (bracket < 0) return op
        val close = op.lastIndexOf(']')
        if (close < bracket) return op
        val inner = op.substring(bracket + 1, close).removeSuffix("!")
        val parts = inner.replace(" - ", " + -").split(",", "+").map { it.trim().removePrefix("#") }.filter { it.isNotEmpty() }
        frameVar(parts)?.let { return it }
        val terms = foldMemTerms(parts)
        return if (terms.size <= 1) { val t = terms.firstOrNull() ?: inner; if (t.any { it in "+-*<> " }) "*($t)" else "*$t" }
            else "*(${terms.joinToString(" + ").replace(" + -", " - ")})"
    }

    private fun memAddr(op: String): String {
        mipsMem(op, deref = false)?.let { return it }
        val bracket = op.indexOf('[')
        if (bracket < 0) return op
        val close = op.lastIndexOf(']')
        if (close < bracket) return op
        val inner = op.substring(bracket + 1, close).removeSuffix("!")
        val parts = inner.replace(" - ", " + -").split(",", "+").map { it.trim().removePrefix("#") }.filter { it.isNotEmpty() }
        frameVar(parts)?.let { return "&$it" }
        val terms = foldMemTerms(parts)
        return if (terms.size <= 1) (terms.firstOrNull() ?: inner) else "(${terms.joinToString(" + ").replace(" + -", " - ")})"
    }

    private val SHIFT_MOD = Regex("""^(lsl|lsr|asr|ror)\s+#?(\w+)$""")
    private val EXTEND_MOD = Regex("""^(?:uxt|sxt)[bhwx](?:\s+#?(\w+))?$""")

    private fun isShiftMod(s: String): Boolean { val l = s.trim().lowercase(); return SHIFT_MOD.matches(l) || EXTEND_MOD.matches(l) }

    private fun foldMemTerms(parts: List<String>): List<String> {
        val terms = ArrayList<String>()
        for (p in parts) {
            val low = p.lowercase()
            val sh = SHIFT_MOD.find(low)
            val ext = EXTEND_MOD.find(low)
            when {
                sh != null && terms.isNotEmpty() -> {
                    val op = if (sh.groupValues[1] == "lsl") "<<" else ">>"
                    terms[terms.size - 1] = "(${terms.last()} $op ${sh.groupValues[2]})"
                }
                ext != null && terms.isNotEmpty() -> {
                    val amt = ext.groupValues[1]
                    if (amt.isNotEmpty()) terms[terms.size - 1] = "(${terms.last()} << $amt)"
                }
                else -> terms.add(p)
            }
        }
        return terms
    }

    private val FRAME_REGS = mapOf("x29" to "", "fp" to "", "rbp" to "", "ebp" to "", "sp" to "s", "rsp" to "s", "esp" to "s")

    private fun frameVar(parts: List<String>): String? {
        if (parts.isEmpty() || parts.size > 2) return null
        val prefix = FRAME_REGS[parts[0]] ?: return null
        val offTok = parts.getOrElse(1) { "0" }
        val neg = offTok.startsWith("-")
        val raw = offTok.removePrefix("-")
        val v = (if (raw.startsWith("0x")) raw.substring(2).toLongOrNull(16) else raw.toLongOrNull()) ?: return null
        return "var_$prefix${if (neg) "m" else ""}${v.toString(16)}"
    }

    private fun immToken(s: String): Long {
        val t = s.substringAfterLast(' ').removePrefix("#")
        return (if (t.startsWith("0x")) t.substring(2).toLongOrNull(16) else t.toLongOrNull()) ?: 0L
    }

    private fun shiftAmt(op: String): Long = if ("?" in op) 0L else immToken(op)

    private val IMM_RE = Regex("""^#?-?(0x[0-9a-fA-F]+|\d+)$""")
    private fun isImm(op: String?): Boolean = op != null && IMM_RE.matches(op.substringAfterLast(' ').trim())

    private fun regRegex(reg: String): Regex? = when {
        Regex("""^[wx]\d+$""").matches(reg) -> Regex("""\b[wx]${reg.drop(1)}\b""")
        Regex("""^r\d+$""").matches(reg) -> Regex("""\b$reg\b""")
        reg == "ip" || reg == "sb" || reg == "sl" || reg == "fp" || reg == "lr" -> Regex("""\b$reg\b""")
        else -> null
    }

    private fun computeArmFolds(insns: List<PIns>, leaders: Set<Long>): Pair<Map<Long, Long>, Set<Long>> {
        val values = HashMap<Long, Long>(); val skip = HashSet<Long>()
        for ((idx, seed) in insns.withIndex()) {
            val rd = seed.ops.getOrNull(0) ?: continue
            val m = armWidth(seed.mnem)
            if ((m != "mov" && m != "movz" && m != "movw") || !isImm(seed.ops.getOrNull(1))) continue
            val regRe = regRegex(rd) ?: continue
            val baseSh = if (seed.ops.size >= 3) shiftAmt(seed.ops[2]) else 0L
            var value = immToken(seed.ops[1]) shl baseSh.toInt()
            val chain = ArrayList<Long>()
            var j = idx + 1
            while (j < insns.size) {
                val nx = insns[j]
                if (nx.addr in leaders || endsBlock(A.ARM, nx) || nx.mnem in CALL_MNEMS) break
                if (!regRe.containsMatchIn(nx.opsStr)) { j++; continue }
                val nm = armWidth(nx.mnem)
                if ((nm == "movk" || nm == "movt") && nx.ops.getOrNull(0) == rd && isImm(nx.ops.getOrNull(1))) {
                    val sh = if (nm == "movt") 16L else if (nx.ops.size >= 3) shiftAmt(nx.ops[2]) else 0L
                    value = (value and (0xffffL shl sh.toInt()).inv()) or (immToken(nx.ops[1]) shl sh.toInt())
                    chain.add(nx.addr); j++
                } else break
            }
            if (chain.isNotEmpty()) { values[seed.addr] = value; skip.addAll(chain) }
        }
        return values to skip
    }

    private fun bitMask(widthOp: String): String {
        val w = immToken(widthOp)
        return if (w in 1..63) "0x${((1L shl w.toInt()) - 1).toString(16)}" else "${(if (w >= 64) -1L else 0L)}"
    }

    private fun translate(arch: A, mnem: String, ops: List<String>, cmp: Pair<String, List<String>>?): String? {
        return when (arch) {
            A.MIPS -> mips(mnem, ops)
            A.X86 -> x86(mnem, ops, cmp)
            A.ARM -> arm(mnem, ops, cmp)
        }
    }

    private fun foldShift(ops: List<String>): List<String> {
        if (ops.size < 4 || ops.any { '[' in it || ']' in it }) return ops
        val expr = shiftExpr(ops[ops.size - 2], ops.last()) ?: return ops
        return ops.dropLast(2) + expr
    }

    private fun shiftExpr(reg: String, mod: String): String? {
        val parts = mod.trim().split(' ', limit = 2)
        val kind = parts[0].lowercase()
        val amt = parts.getOrNull(1)?.removePrefix("#")?.trim()
        return when {
            kind == "lsl" && amt != null -> "($reg << $amt)"
            (kind == "lsr" || kind == "asr") && amt != null -> "($reg >> $amt)"
            kind == "ror" && amt != null -> "rotr($reg, $amt)"
            kind.startsWith("uxt") || kind.startsWith("sxt") -> {
                val w = when (kind.lastOrNull()) { 'b' -> 8; 'h' -> 16; 'w' -> 32; else -> 64 }
                val cast = if (kind.startsWith("uxt")) "(uint${w}_t)" else "(int${w}_t)"
                if (amt != null) "($cast$reg << $amt)" else "$cast$reg"
            }
            else -> null
        }
    }

    private fun arm(rawMnem: String, rawOps: List<String>, cmp: Pair<String, List<String>>?): String? {
        val ops = foldShift(rawOps)
        fun o(i: Int) = ops.getOrElse(i) { "?" }.let { if (it == "xzr" || it == "wzr") "0" else it }
        fun sh(i: Int): String { val v = o(i); val m = ops.getOrNull(i + 1); return if (m != null && isShiftMod(m)) shiftExpr(v, m) ?: v else v }
        fun loadCast(rawM: String): String { val m = rawM.removeSuffix("t"); return when {
            rawM.startsWith("ldra") -> ""
            m.endsWith("sb") -> "(int8_t)"; m.endsWith("sh") -> "(int16_t)"; m.endsWith("sw") -> "(int32_t)"
            m.endsWith("b") -> "(uint8_t)"; m.endsWith("h") -> "(uint16_t)"
            else -> ""
        } }
        fun writeback(memIdx: Int): String {
            val memOp = ops.getOrNull(memIdx) ?: return ""
            val base = memOp.substringAfter('[', "").substringBefore(']').split(",").firstOrNull()?.trim()?.takeIf { it.isNotEmpty() } ?: return ""
            if (memOp.trimEnd().endsWith("!")) {
                val off = memOp.substringAfter(',', "").substringBefore(']').trim().removePrefix("#").trim()
                return if (off.isNotEmpty()) "; $base += $off" else ""
            }
            val post = ops.getOrNull(memIdx + 1)
            return if (post != null && memOp.trimEnd().endsWith("]")) "; $base += ${post.removePrefix("#")}" else ""
        }
        val n = ops.size
        val vb = vfpBase(rawMnem)
        val mnem = armWidth(rawMnem).let { if (it in ARM_FLAG_OPS) it.dropLast(1) else it }
        if (mnem.length > 2 && mnem != "movt" && !vb.startsWith("vsel") && mnem.takeLast(2) in ARM_COND && mnem.takeLast(2) != "al") {
            val base = mnem.dropLast(2)
            val baseStmt = arm(base, ops, cmp)
            if (baseStmt != null && baseStmt.isNotEmpty() && baseStmt != base && !baseStmt.startsWith("$base "))
                return "if (${cond(mnem.takeLast(2), cmp)}) $baseStmt"
        }
        return when {
            mnem == "ret" -> "return"
            mnem == "nop" || mnem == "bti" || mnem.startsWith("pac") || mnem.startsWith("aut") || mnem.startsWith("hint") -> ""
            mnem.startsWith("it") && mnem.length <= 4 && mnem.drop(2).all { it == 't' || it == 'e' } -> ""
            mnem == "b" || mnem == "br" -> "goto ${o(0)}"
            mnem == "bx" -> if (o(0) == "lr" || o(0) == "pc" || o(0) == "x30" || o(0) == "r14") "return" else "goto *${o(0)}"
            mnem == "bl" || mnem == "blr" || mnem == "blx" -> "${o(0)}()"
            mnem == "cbz" -> "if (${o(0)} == 0) goto ${o(1)}"
            mnem == "cbnz" -> "if (${o(0)} != 0) goto ${o(1)}"
            mnem == "tbz" -> "if ((${o(0)} & (1LL << ${o(1)})) == 0) goto ${o(2)}"
            mnem == "tbnz" -> "if ((${o(0)} & (1LL << ${o(1)})) != 0) goto ${o(2)}"
            mnem.startsWith("b.") -> "if (${cond(mnem.substring(2), cmp)}) goto ${o(0)}"
            mnem == "movn" -> "${o(0)} = ~${o(1)}"
            vb == "vadd" -> if (n >= 3) "${o(0)} = ${o(1)} + ${o(2)}" else "${o(0)} += ${o(1)}"
            vb == "vsub" -> if (n >= 3) "${o(0)} = ${o(1)} - ${o(2)}" else "${o(0)} -= ${o(1)}"
            vb == "vmul" -> if (n >= 3) "${o(0)} = ${o(1)} * ${o(2)}" else "${o(0)} *= ${o(1)}"
            vb == "vdiv" -> if (n >= 3) "${o(0)} = ${o(1)} / ${o(2)}" else "${o(0)} /= ${o(1)}"
            vb == "vnmul" -> "${o(0)} = -(${o(1)} * ${o(2)})"
            vb == "vneg" -> "${o(0)} = -${o(1)}"
            vb == "vabs" -> "${o(0)} = fabs(${o(1)})"
            vb == "vsqrt" -> "${o(0)} = sqrt(${o(1)})"
            vb == "vmla" || vb == "vfma" -> "${o(0)} += ${o(1)} * ${o(2)}"
            vb == "vmls" || vb == "vfms" -> "${o(0)} -= ${o(1)} * ${o(2)}"
            vb == "vnmla" || vb == "vfnma" -> "${o(0)} = -${o(0)} - ${o(1)} * ${o(2)}"
            vb == "vnmls" || vb == "vfnms" -> "${o(0)} = -${o(0)} + ${o(1)} * ${o(2)}"
            vb == "vcvtb" || vb == "vcvtt" -> if (vcvtHalfToSingle(rawMnem)) "${o(0)} = __f16_to_f32(${o(1)})" else "${o(0)} = __f32_to_f16(${o(1)})"
            vb == "vrintz" -> "${o(0)} = trunc(${o(1)})"
            vb == "vrintm" -> "${o(0)} = floor(${o(1)})"
            vb == "vrintp" -> "${o(0)} = ceil(${o(1)})"
            vb == "vrinta" -> "${o(0)} = round(${o(1)})"
            vb == "vrintn" || vb == "vrintr" || vb == "vrintx" -> "${o(0)} = rint(${o(1)})"
            vb == "vmaxnm" -> "${o(0)} = fmax(${o(1)}, ${o(2)})"
            vb == "vminnm" -> "${o(0)} = fmin(${o(1)}, ${o(2)})"
            vb.startsWith("vsel") && vb.length == 6 -> "${o(0)} = (${condExpr(vb.substring(4), cmp)}) ? ${o(1)} : ${o(2)}"
            vb == "vcvt" || vb == "vcvtr" -> "${o(0)} = (${vcvtType(rawMnem)})${o(1)}"
            vb == "vldr" -> "${o(0)} = ${mem(o(1))}"
            vb == "vstr" -> "${mem(o(1))} = ${o(0)}"
            vb == "vmov" && n >= 3 && Regex("""^[dq]\d""").containsMatchIn(o(0)) -> "${o(0)} = ${o(1)}, ${o(2)}"
            vb == "vmov" && n >= 3 -> "${o(0)}, ${o(1)} = ${o(2)}"
            vb == "vmov" -> "${o(0)} = ${o(1)}"
            mnem == "vmov" && n >= 3 && Regex("""^[dq]\d""").containsMatchIn(o(0)) -> "${o(0)} = ${o(1)}, ${o(2)}"
            mnem == "vmov" && n >= 3 -> "${o(0)}, ${o(1)} = ${o(2)}"
            mnem == "mov" || mnem == "movz" || mnem == "fmov" || mnem == "vmov" || mnem == "adr" || mnem == "adrp" -> "${o(0)} = ${o(1)}"
            mnem == "mvn" -> "${o(0)} = ~${sh(1)}"
            mnem == "neg" -> "${o(0)} = -${sh(1)}"
            mnem == "cset" -> "${o(0)} = (${condExpr(o(1), cmp)})"
            mnem == "csetm" -> "${o(0)} = (${condExpr(o(1), cmp)}) ? -1 : 0"
            mnem == "csel" -> "${o(0)} = (${condExpr(o(3), cmp)}) ? ${o(1)} : ${o(2)}"
            mnem == "csinc" -> "${o(0)} = (${condExpr(o(3), cmp)}) ? ${o(1)} : ${o(2)} + 1"
            mnem == "csinv" -> "${o(0)} = (${condExpr(o(3), cmp)}) ? ${o(1)} : ~${o(2)}"
            mnem == "csneg" -> "${o(0)} = (${condExpr(o(3), cmp)}) ? ${o(1)} : -${o(2)}"
            mnem == "cinc" -> "${o(0)} = (${condExpr(o(2), cmp)}) ? ${o(1)} + 1 : ${o(1)}"
            mnem == "cinv" -> "${o(0)} = (${condExpr(o(2), cmp)}) ? ~${o(1)} : ${o(1)}"
            mnem == "cneg" -> "${o(0)} = (${condExpr(o(2), cmp)}) ? -${o(1)} : ${o(1)}"
            mnem == "add" && n >= 3 && frameVar(listOf(o(1), o(2))) != null -> "${o(0)} = &${frameVar(listOf(o(1), o(2)))}"
            mnem == "add" || mnem == "fadd" -> if (n >= 3) "${o(0)} = ${o(1)} + ${o(2)}" else "${o(0)} += ${o(1)}"
            mnem == "sub" || mnem == "fsub" -> if (n >= 3) "${o(0)} = ${o(1)} - ${o(2)}" else "${o(0)} -= ${o(1)}"
            mnem == "rsb" -> if (n >= 3) "${o(0)} = ${o(2)} - ${o(1)}" else "${o(0)} = -${o(1)}"
            mnem == "mul" || mnem == "fmul" -> if (n >= 3) "${o(0)} = ${o(1)} * ${o(2)}" else "${o(0)} *= ${o(1)}"
            mnem == "udiv" || mnem == "sdiv" || mnem == "fdiv" -> if (n >= 3) "${o(0)} = ${o(1)} / ${o(2)}" else "${o(0)} /= ${o(1)}"
            mnem == "and" -> if (n >= 3) "${o(0)} = ${o(1)} & ${o(2)}" else "${o(0)} &= ${o(1)}"
            mnem == "orr" -> if (n >= 3) "${o(0)} = ${o(1)} | ${o(2)}" else "${o(0)} |= ${o(1)}"
            mnem == "eor" -> if (n >= 3) "${o(0)} = ${o(1)} ^ ${o(2)}" else "${o(0)} ^= ${o(1)}"
            mnem == "lsl" -> if (n >= 3) "${o(0)} = ${o(1)} << ${o(2)}" else "${o(0)} <<= ${o(1)}"
            mnem == "lsr" || mnem == "asr" -> if (n >= 3) "${o(0)} = ${o(1)} >> ${o(2)}" else "${o(0)} >>= ${o(1)}"
            mnem == "ror" -> if (n >= 3) "${o(0)} = rotr(${o(1)}, ${o(2)})" else "${o(0)} = rotr(${o(0)}, ${o(1)})"
            mnem == "extr" -> "${o(0)} = extr(${o(1)}, ${o(2)}, ${o(3)})"
            mnem == "bic" -> if (n >= 3) "${o(0)} = ${o(1)} & ~${o(2)}" else "${o(0)} &= ~${o(1)}"
            mnem == "orn" -> if (n >= 3) "${o(0)} = ${o(1)} | ~${o(2)}" else "${o(0)} |= ~${o(1)}"
            mnem == "eon" -> if (n >= 3) "${o(0)} = ${o(1)} ^ ~${o(2)}" else "${o(0)} ^= ~${o(1)}"
            mnem == "madd" || mnem == "smaddl" || mnem == "umaddl" || mnem == "mla" -> "${o(0)} = ${o(1)} * ${o(2)} + ${o(3)}"
            mnem == "msub" || mnem == "smsubl" || mnem == "umsubl" || mnem == "mls" -> "${o(0)} = ${o(3)} - ${o(1)} * ${o(2)}"
            mnem == "mneg" -> "${o(0)} = -(${o(1)} * ${o(2)})"
            (mnem == "smull" || mnem == "umull") && n >= 4 -> "${o(0)}, ${o(1)} = ${o(2)} * ${o(3)}"
            mnem == "smull" || mnem == "umull" -> "${o(0)} = ${o(1)} * ${o(2)}"
            (mnem == "smlal" || mnem == "umlal") && n >= 4 -> "${o(0)}, ${o(1)} += ${o(2)} * ${o(3)}"
            mnem == "umulh" || mnem == "smulh" -> "${o(0)} = (${o(1)} * ${o(2)}) >> 64"
            mnem == "adc" -> if (n >= 3) "${o(0)} = ${o(1)} + ${o(2)} + carry" else "${o(0)} = ${o(0)} + ${o(1)} + carry"
            mnem == "sbc" -> if (n >= 3) "${o(0)} = ${o(1)} - ${o(2)} - carry" else "${o(0)} = ${o(0)} - ${o(1)} - carry"
            mnem == "rsc" -> if (n >= 3) "${o(0)} = ${o(2)} - ${o(1)} - carry" else "${o(0)} = ${o(1)} - ${o(0)} - carry"
            mnem == "ngc" -> "${o(0)} = -${o(1)} - carry"
            mnem == "rev" || mnem == "rev64" -> "${o(0)} = bswap(${o(1)})"
            mnem == "rev16" -> "${o(0)} = rev16(${o(1)})"
            mnem == "rev32" -> "${o(0)} = rev32(${o(1)})"
            mnem == "revsh" -> "${o(0)} = (int16_t)rev16(${o(1)})"
            mnem == "clz" -> "${o(0)} = clz(${o(1)})"
            mnem == "cls" -> "${o(0)} = cls(${o(1)})"
            mnem == "rbit" -> "${o(0)} = rbit(${o(1)})"
            mnem == "ubfx" && n >= 4 -> "${o(0)} = (${o(1)} >> ${o(2)}) & ${bitMask(o(3))}"
            mnem == "sbfx" -> "${o(0)} = sbfx(${o(1)}, ${o(2)}, ${o(3)})"
            mnem == "ubfiz" || mnem == "sbfiz" || mnem == "bfi" || mnem == "bfxil" || mnem == "ubfm" || mnem == "sbfm" -> "${o(0)} = $mnem(${ops.drop(1).joinToString(", ")})"
            mnem == "sxtab" && n >= 3 -> "${o(0)} = ${o(1)} + (int8_t)${o(2)}"
            mnem == "sxtah" && n >= 3 -> "${o(0)} = ${o(1)} + (int16_t)${o(2)}"
            mnem == "uxtab" && n >= 3 -> "${o(0)} = ${o(1)} + (uint8_t)${o(2)}"
            mnem == "uxtah" && n >= 3 -> "${o(0)} = ${o(1)} + (uint16_t)${o(2)}"
            mnem == "sxtb" -> "${o(0)} = (int8_t)${o(1)}"
            mnem == "sxth" -> "${o(0)} = (int16_t)${o(1)}"
            mnem == "sxtw" -> "${o(0)} = (int32_t)${o(1)}"
            mnem == "uxtb" -> "${o(0)} = (uint8_t)${o(1)}"
            mnem == "uxth" -> "${o(0)} = (uint16_t)${o(1)}"
            mnem == "mrs" || mnem == "msr" -> "${o(0)} = ${o(1)}"
            mnem == "movk" -> { val sh = shiftAmt(o(2)); if (sh == 0L) "${o(0)} = (${o(0)} & ~0xffff) | ${o(1)}" else "${o(0)} = (${o(0)} & ~(0xffffL << $sh)) | ((long)${o(1)} << $sh)" }
            mnem == "movw" -> "${o(0)} = ${o(1)}"
            mnem == "movt" -> "${o(0)} = (${o(0)} & 0xffff) | (${o(1)} << 16)"
            mnem == "brk" -> "__break(${o(0)})"
            mnem == "hlt" -> "__halt(${o(0)})"
            mnem == "udf" -> "__undefined()"
            mnem == "svc" -> "__syscall(${o(0)})"
            mnem == "dmb" || mnem == "dsb" || mnem == "isb" -> "__$mnem()"
            (mnem == "pop" || mnem.startsWith("ldm")) && ops.any { "pc" in it } -> "return"
            (mnem == "stxr" || mnem == "stlxr") && n >= 3 -> "${o(0)} = __stxr(${mem(o(2))}, ${o(1)})"
            (mnem == "strexd" || mnem == "stlexd") && n >= 4 -> "${o(0)} = __strex(${mem(o(3))}, ${o(1)}, ${o(2)})"
            (mnem.startsWith("strex") || mnem.startsWith("stlex")) && n >= 3 -> "${o(0)} = __strex(${mem(o(2))}, ${o(1)})"
            (mnem == "ldrexd" || mnem == "ldaexd") && n >= 3 && '[' in o(2) -> "${o(0)}, ${o(1)} = ${mem(o(2))}"
            mnem == "ldrd" && n >= 3 && '[' in o(2) -> "${o(0)}, ${o(1)} = ${mem(o(2))}${writeback(2)}"
            mnem == "strd" && n >= 3 && '[' in o(2) -> "${mem(o(2))} = ${o(0)}, ${o(1)}${writeback(2)}"
            (mnem.startsWith("ldr") || mnem.startsWith("ldur") || mnem in ATOMIC_LOADS) && n >= 2 -> "${o(0)} = ${loadCast(mnem)}${mem(o(1))}${writeback(1)}"
            (mnem.startsWith("str") || mnem.startsWith("stur") || mnem == "stlr" || mnem == "stl" || mnem == "stlb" || mnem == "stlh") && n >= 2 -> "${mem(o(1))} = ${o(0)}${writeback(1)}"
            mnem == "ldp" -> "${o(0)}, ${o(1)} = ${mem(o(2))}${writeback(2)}"
            mnem == "stp" -> "${mem(o(2))} = ${o(0)}, ${o(1)}${writeback(2)}"
            mnem in ARM_PARALLEL && n >= 3 -> "${o(0)} = __$mnem(${o(1)}, ${o(2)})"
            mnem == "sel" -> "${o(0)} = __sel(${o(1)}, ${o(2)})"
            mnem == "qadd" -> "${o(0)} = __qadd(${o(1)}, ${o(2)})"
            mnem == "qsub" -> "${o(0)} = __qsub(${o(1)}, ${o(2)})"
            mnem == "qdadd" -> "${o(0)} = __qdadd(${o(1)}, ${o(2)})"
            mnem == "qdsub" -> "${o(0)} = __qdsub(${o(1)}, ${o(2)})"
            mnem == "smuad" || mnem == "smuadx" -> "${o(0)} = __smuad(${o(1)}, ${o(2)})"
            mnem == "smusd" || mnem == "smusdx" -> "${o(0)} = __smusd(${o(1)}, ${o(2)})"
            (mnem == "smlad" || mnem == "smladx") && n >= 4 -> "${o(0)} = ${o(3)} + __smuad(${o(1)}, ${o(2)})"
            (mnem == "smlsd" || mnem == "smlsdx") && n >= 4 -> "${o(0)} = ${o(3)} + __smusd(${o(1)}, ${o(2)})"
            (mnem == "smlald" || mnem == "smlaldx") && n >= 4 -> "${o(0)}, ${o(1)} += __smuad(${o(2)}, ${o(3)})"
            (mnem == "smlsld" || mnem == "smlsldx") && n >= 4 -> "${o(0)}, ${o(1)} += __smusd(${o(2)}, ${o(3)})"
            mnem == "smulbb" -> "${o(0)} = (int16_t)${o(1)} * (int16_t)${o(2)}"
            mnem == "smulbt" -> "${o(0)} = (int16_t)${o(1)} * ((int32_t)${o(2)} >> 16)"
            mnem == "smultb" -> "${o(0)} = ((int32_t)${o(1)} >> 16) * (int16_t)${o(2)}"
            mnem == "smultt" -> "${o(0)} = ((int32_t)${o(1)} >> 16) * ((int32_t)${o(2)} >> 16)"
            mnem == "smlabb" && n >= 4 -> "${o(0)} = ${o(3)} + (int16_t)${o(1)} * (int16_t)${o(2)}"
            mnem == "smlabt" && n >= 4 -> "${o(0)} = ${o(3)} + (int16_t)${o(1)} * ((int32_t)${o(2)} >> 16)"
            mnem == "smlatb" && n >= 4 -> "${o(0)} = ${o(3)} + ((int32_t)${o(1)} >> 16) * (int16_t)${o(2)}"
            mnem == "smlatt" && n >= 4 -> "${o(0)} = ${o(3)} + ((int32_t)${o(1)} >> 16) * ((int32_t)${o(2)} >> 16)"
            mnem == "smulwb" -> "${o(0)} = ((int64_t)${o(1)} * (int16_t)${o(2)}) >> 16"
            mnem == "smulwt" -> "${o(0)} = ((int64_t)${o(1)} * ((int32_t)${o(2)} >> 16)) >> 16"
            mnem == "smlawb" && n >= 4 -> "${o(0)} = ${o(3)} + (((int64_t)${o(1)} * (int16_t)${o(2)}) >> 16)"
            mnem == "smlawt" && n >= 4 -> "${o(0)} = ${o(3)} + (((int64_t)${o(1)} * ((int32_t)${o(2)} >> 16)) >> 16)"
            mnem == "smmul" || mnem == "smmulr" -> "${o(0)} = ((int64_t)${o(1)} * ${o(2)}) >> 32"
            (mnem == "smmla" || mnem == "smmlar") && n >= 4 -> "${o(0)} = ${o(3)} + (((int64_t)${o(1)} * ${o(2)}) >> 32)"
            (mnem == "smmls" || mnem == "smmlsr") && n >= 4 -> "${o(0)} = ${o(3)} - (((int64_t)${o(1)} * ${o(2)}) >> 32)"
            mnem == "usad8" -> "${o(0)} = __usad8(${o(1)}, ${o(2)})"
            mnem == "usada8" && n >= 4 -> "${o(0)} = ${o(3)} + __usad8(${o(1)}, ${o(2)})"
            mnem == "ssat" && n >= 3 -> "${o(0)} = __ssat(${o(2)}, ${o(1)})"
            mnem == "usat" && n >= 3 -> "${o(0)} = __usat(${o(2)}, ${o(1)})"
            mnem == "ssat16" && n >= 3 -> "${o(0)} = __ssat16(${o(2)}, ${o(1)})"
            mnem == "usat16" && n >= 3 -> "${o(0)} = __usat16(${o(2)}, ${o(1)})"
            mnem == "pkhbt" -> "${o(0)} = (${o(1)} & 0xffff) | (${o(2)} & 0xffff0000)"
            mnem == "pkhtb" -> "${o(0)} = (${o(1)} & 0xffff0000) | (${o(2)} & 0xffff)"
            mnem == "rrx" -> "${o(0)} = (${o(1)} >> 1) | (carry << 31)"
            mnem == "pld" || mnem == "pldw" || mnem == "pli" -> ""
            mnem in ARM_HINTS -> ""
            mnem.startsWith("cps") -> ""
            mnem == "bkpt" -> "__break(${o(0)})"
            mnem == "smc" -> "__smc(${o(0)})"
            mnem == "hvc" -> "__hvc(${o(0)})"
            mnem == "swp" -> "${o(0)} = __swp(${mem(o(2))}, ${o(1)})"
            mnem == "swpb" -> "${o(0)} = __swpb(${mem(o(2))}, ${o(1)})"
            mnem == "mrc" || mnem == "mrc2" -> "${ops.getOrElse(2) { "?" }} = __mrc(${ops.filterIndexed { idx, _ -> idx != 2 }.joinToString(", ")})"
            mnem == "mrrc" || mnem == "mrrc2" -> "${ops.getOrElse(2) { "?" }}, ${ops.getOrElse(3) { "?" }} = __mrrc(${ops.filterIndexed { idx, _ -> idx != 2 && idx != 3 }.joinToString(", ")})"
            mnem == "mcr" || mnem == "mcr2" -> "__mcr(${ops.joinToString(", ")})"
            mnem in ARM_CP_DATA2 -> "__$mnem(${ops.joinToString(", ")})"
            mnem in ARM_CP_DATA -> "__$mnem(${ops.joinToString(", ")})"
            mnem.startsWith("srs") -> "__srs(${ops.joinToString(", ")})"
            mnem.startsWith("rfe") -> "__rfe(${ops.joinToString(", ")})"
            mnem.startsWith("ldm") -> ldmStm(mnem, ops, true)
            mnem.startsWith("stm") -> ldmStm(mnem, ops, false)
            else -> "${mnem} ${ops.joinToString(", ")}".trim()
        }
    }

    private fun vcvtHalfToSingle(rawMnem: String): Boolean = armWidth(rawMnem).split('.').lastOrNull() == "f16"

    private fun vcvtType(rawMnem: String): String {
        val parts = armWidth(rawMnem).split('.')
        val dst = parts.getOrNull(1) ?: "f32"
        return when (dst) {
            "f32" -> "float"; "f64" -> "double"
            "s32", "s16" -> "int32_t"; "u32", "u16" -> "uint32_t"
            else -> "float"
        }
    }

    private fun ldmStm(mnem: String, ops: List<String>, load: Boolean): String {
        val regs = ops.lastOrNull()?.substringAfter('{', "")?.substringBefore('}', "")
            ?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: return "${mnem} ${ops.joinToString(", ")}".trim()
        if (regs.any { "pc" in it } && load) return "return"
        val baseRaw = ops.firstOrNull() ?: return ""
        val base = baseRaw.removeSuffix("!").trim()
        val n = regs.size
        val mode = mnem.removePrefix("ldm").removePrefix("stm").removeSuffix(".w").take(2)
        val decr = mode == "db" || mode == "da"
        val baseIdx = when (mode) { "ib" -> 1; "da" -> -(n - 1); "db" -> -n; else -> 0 }
        val parts = ArrayList<String>()
        for ((idx, r) in regs.withIndex()) {
            val off = (baseIdx + idx) * 4
            val cell = when {
                off == 0 -> "*$base"
                off > 0 -> "*($base + $off)"
                else -> "*($base - ${-off})"
            }
            parts.add(if (load) "$r = $cell" else "$cell = $r")
        }
        val wb = if (baseRaw.trimEnd().endsWith("!")) "; $base ${if (decr) "-=" else "+="} ${n * 4}" else ""
        return parts.joinToString("; ") + wb
    }

    private fun x86SrcWidth(op: String): Int = when {
        "byte ptr" in op -> 8; "word ptr" in op -> 16; "dword ptr" in op -> 32
        Regex("""\b([a-d][lh]|sil|dil|spl|bpl|r\d+b)\b""").containsMatchIn(op) -> 8
        Regex("""\b([a-d]x|si|di|sp|bp|r\d+w)\b""").containsMatchIn(op) -> 16
        Regex("""\b(e[a-d]x|e[sd]i|e[sb]p|r\d+d)\b""").containsMatchIn(op) -> 32
        else -> 8
    }

    private fun x86Acc(op: String): Pair<String, String> =
        if ("qword" in op || Regex("""\b(r[a-z]x|r\d+|rsi|rdi|rbp|rsp)\b""").containsMatchIn(op)) "rax" to "rdx" else "eax" to "edx"

    private fun x86AccW(op: String): Triple<String, String, Int> = when {
        "qword" in op || Regex("""\b(r[a-z]x|r\d+|rsi|rdi|rbp|rsp)\b""").containsMatchIn(op) -> Triple("rax", "rdx", 64)
        else -> when (x86SrcWidth(op)) {
            8 -> Triple("al", "ah", 8)
            16 -> Triple("ax", "dx", 16)
            else -> Triple("eax", "edx", 32)
        }
    }

    private fun x86(mnem: String, ops: List<String>, cmp: Pair<String, List<String>>?): String? {
        fun o(i: Int) = mem(ops.getOrElse(i) { "?" })
        fun raw(i: Int) = ops.getOrElse(i) { "?" }
        fun fo(i: Int) = ops.getOrElse(i) { "?" }.let { if (it.startsWith("st")) it else mem(it) }
        return when {
            mnem == "ret" || mnem == "retn" || mnem == "leave" -> "return"
            mnem == "nop" || mnem == "endbr64" || mnem == "endbr32" -> ""
            mnem == "bt" -> ""
            mnem == "bts" -> "${o(0)} |= (1 << ${o(1)})"
            mnem == "btr" -> "${o(0)} &= ~(1 << ${o(1)})"
            mnem == "btc" -> "${o(0)} ^= (1 << ${o(1)})"
            mnem == "jmp" -> "goto ${o(0)}"
            mnem == "call" -> "${o(0)}()"
            mnem == "push" -> "push(${o(0)})"
            mnem == "pop" -> "${o(0)} = pop()"
            mnem == "lea" -> "${raw(0)} = ${memAddr(raw(1))}"
            mnem == "mov" || mnem == "movaps" || mnem == "movdqa" || mnem == "movdqu" -> "${o(0)} = ${o(1)}"
            mnem == "movsx" -> "${o(0)} = (int${x86SrcWidth(raw(1))}_t)${o(1)}"
            mnem == "movzx" -> "${o(0)} = (uint${x86SrcWidth(raw(1))}_t)${o(1)}"
            mnem == "movsxd" -> "${o(0)} = (int32_t)${o(1)}"
            mnem == "add" -> "${o(0)} += ${o(1)}"
            mnem == "sub" -> "${o(0)} -= ${o(1)}"
            mnem == "imul" || mnem == "mul" -> when {
                ops.size == 3 -> "${o(0)} = ${o(1)} * ${o(2)}"
                ops.size == 2 -> "${o(0)} *= ${o(1)}"
                else -> { val (a, d, w) = x86AccW(raw(0)); if (w == 8) "ax = al * ${o(0)}" else "$d:$a = $a * ${o(0)}" }
            }
            mnem == "div" || mnem == "idiv" -> { val (a, d, w) = x86AccW(raw(0)); if (w == 8) "al = ax / ${o(0)}; ah = ax % ${o(0)}" else "$d = $a % ${o(0)}; $a = $a / ${o(0)}" }
            mnem == "and" -> "${o(0)} &= ${o(1)}"
            mnem == "or" -> "${o(0)} |= ${o(1)}"
            mnem == "xor" -> if (ops.size == 2 && ops[0] == ops[1]) "${o(0)} = 0" else "${o(0)} ^= ${o(1)}"
            (mnem == "xorps" || mnem == "xorpd" || mnem == "pxor") && ops.size == 2 && ops[0] == ops[1] -> "${o(0)} = 0"
            mnem == "shl" || mnem == "sal" -> "${o(0)} <<= ${o(1)}"
            mnem == "shr" || mnem == "sar" -> "${o(0)} >>= ${o(1)}"
            mnem == "adc" -> "${o(0)} += ${o(1)} + carry"
            mnem == "sbb" -> "${o(0)} -= ${o(1)} + carry"
            mnem == "ror" -> "${o(0)} = rotr(${o(0)}, ${o(1)})"
            mnem == "rol" -> "${o(0)} = rotl(${o(0)}, ${o(1)})"
            mnem == "rcl" -> "${o(0)} = rcl(${o(0)}, ${o(1)})"
            mnem == "rcr" -> "${o(0)} = rcr(${o(0)}, ${o(1)})"
            mnem == "movabs" -> "${o(0)} = ${o(1)}"
            (mnem == "movsd" || mnem == "movss" || mnem == "movups" || mnem == "movupd" || mnem == "movapd" ||
                mnem == "movlps" || mnem == "movhps" || mnem == "movq" || mnem == "movd") && ops.size == 2 &&
                SSE_REG.containsMatchIn(ops[0] + " " + ops[1]) -> "${o(0)} = ${o(1)}"
            mnem == "bswap" -> "${o(0)} = bswap(${o(0)})"
            mnem == "popcnt" -> "${o(0)} = popcount(${o(1)})"
            mnem == "lzcnt" -> "${o(0)} = clz(${o(1)})"
            mnem == "tzcnt" -> "${o(0)} = ctz(${o(1)})"
            mnem == "bsr" -> "${o(0)} = bsr(${o(1)})"
            mnem == "bsf" -> "${o(0)} = bsf(${o(1)})"
            mnem == "andn" -> "${o(0)} = ~${o(1)} & ${o(2)}"
            mnem == "bextr" -> "${o(0)} = (${o(1)} >> (${o(2)} & 0xff)) & ((1 << ((${o(2)} >> 8) & 0xff)) - 1)"
            mnem == "bzhi" -> "${o(0)} = ${o(1)} & ((1 << (${o(2)} & 0xff)) - 1)"
            mnem == "blsi" -> "${o(0)} = ${o(1)} & -${o(1)}"
            mnem == "blsr" -> "${o(0)} = ${o(1)} & (${o(1)} - 1)"
            mnem == "blsmsk" -> "${o(0)} = ${o(1)} ^ (${o(1)} - 1)"
            mnem == "mulx" -> { val w = x86Acc(raw(2)).first == "rax"; val d = if (w) "rdx" else "edx"; "${o(1)} = $d * ${o(2)}; ${o(0)} = ($d * ${o(2)}) >> ${if (w) 64 else 32}" }
            mnem == "rorx" -> "${o(0)} = rotr(${o(1)}, ${o(2)})"
            mnem == "sarx" -> "${o(0)} = ${o(1)} >> ${o(2)}"
            mnem == "shlx" -> "${o(0)} = ${o(1)} << ${o(2)}"
            mnem == "shrx" -> "${o(0)} = (unsigned)${o(1)} >> ${o(2)}"
            mnem == "crc32" -> "${o(0)} = crc32(${o(0)}, ${o(1)})"
            mnem == "pdep" -> "${o(0)} = pdep(${o(1)}, ${o(2)})"
            mnem == "pext" -> "${o(0)} = pext(${o(1)}, ${o(2)})"
            mnem == "adcx" -> "${o(0)} += ${o(1)} + carry"
            mnem == "adox" -> "${o(0)} += ${o(1)} + overflow"
            mnem == "movbe" -> "${o(0)} = bswap(${o(1)})"
            mnem == "xadd" -> "${o(1)} = __xadd(${memAddr(raw(0))}, ${o(1)})"
            mnem == "xchg" -> "__xchg(${memAddr(raw(0))}, ${memAddr(raw(1))})"
            mnem == "cmpxchg" -> { val (a, _) = x86Acc(raw(0)); "if ($a == ${o(0)}) ${o(0)} = ${o(1)}; else $a = ${o(0)}" }
            mnem == "shld" -> "${o(0)} = shld(${o(0)}, ${o(1)}, ${o(2)})"
            mnem == "shrd" -> "${o(0)} = shrd(${o(0)}, ${o(1)}, ${o(2)})"
            mnem == "cdq" -> "edx = (int32_t)eax >> 31"
            mnem == "cdqe" -> "rax = (int32_t)eax"
            mnem == "cqo" -> "rdx = (int64_t)rax >> 63"
            mnem == "cwde" -> "eax = (int16_t)ax"
            mnem == "int3" -> "__debugbreak()"
            mnem == "mfence" || mnem == "lfence" || mnem == "sfence" -> "__$mnem()"
            mnem == "inc" -> "${o(0)}++"
            mnem == "dec" -> "${o(0)}--"
            mnem == "neg" -> "${o(0)} = -${o(0)}"
            mnem == "not" -> "${o(0)} = ~${o(0)}"
            mnem == "addsd" || mnem == "addss" -> "${o(0)} += ${o(1)}"
            mnem == "subsd" || mnem == "subss" -> "${o(0)} -= ${o(1)}"
            mnem == "mulsd" || mnem == "mulss" -> "${o(0)} *= ${o(1)}"
            mnem == "divsd" || mnem == "divss" -> "${o(0)} /= ${o(1)}"
            mnem == "addps" || mnem == "addpd" -> "${o(0)} = vadd(${o(0)}, ${o(1)})"
            mnem == "subps" || mnem == "subpd" -> "${o(0)} = vsub(${o(0)}, ${o(1)})"
            mnem == "mulps" || mnem == "mulpd" -> "${o(0)} = vmul(${o(0)}, ${o(1)})"
            mnem == "divps" || mnem == "divpd" -> "${o(0)} = vdiv(${o(0)}, ${o(1)})"
            mnem == "sqrtsd" || mnem == "sqrtss" -> "${o(0)} = sqrt(${o(1)})"
            mnem == "cvtsi2sd" || mnem == "cvtss2sd" -> "${o(0)} = (double)${o(1)}"
            mnem == "cvtsi2ss" || mnem == "cvtsd2ss" -> "${o(0)} = (float)${o(1)}"
            mnem == "cvttsd2si" || mnem == "cvttss2si" || mnem == "cvtsd2si" || mnem == "cvtss2si" -> "${o(0)} = (long)${o(1)}"
            mnem == "por" -> "${o(0)} |= ${o(1)}"
            mnem == "pand" -> "${o(0)} &= ${o(1)}"
            mnem == "pandn" -> "${o(0)} = ~${o(0)} & ${o(1)}"
            mnem == "pxor" -> "${o(0)} ^= ${o(1)}"
            mnem == "paddd" || mnem == "paddq" || mnem == "paddw" || mnem == "paddb" -> "${o(0)} = vadd(${o(0)}, ${o(1)})"
            mnem == "psubd" || mnem == "psubq" || mnem == "psubw" || mnem == "psubb" -> "${o(0)} = vsub(${o(0)}, ${o(1)})"
            mnem == "pmulld" || mnem == "pmullw" -> "${o(0)} = vmul(${o(0)}, ${o(1)})"
            mnem == "movmskps" || mnem == "movmskpd" -> "${o(0)} = movmsk(${o(1)})"
            mnem == "pmovmskb" -> "${o(0)} = pmovmskb(${o(1)})"
            mnem == "ptest" -> "__ptest(${o(0)}, ${o(1)})"
            mnem == "fld" || mnem == "fild" -> "st0 = ${fo(0)}"
            mnem == "fstp" || mnem == "fst" -> "${fo(0)} = st0"
            mnem == "fistp" || mnem == "fist" -> "${fo(0)} = (long)st0"
            mnem == "fadd" || mnem == "faddp" -> if (ops.size >= 2) "${fo(0)} += ${fo(1)}" else "st0 += ${fo(0)}"
            mnem == "fsub" || mnem == "fsubp" -> if (ops.size >= 2) "${fo(0)} -= ${fo(1)}" else "st0 -= ${fo(0)}"
            mnem == "fmul" || mnem == "fmulp" -> if (ops.size >= 2) "${fo(0)} *= ${fo(1)}" else "st0 *= ${fo(0)}"
            mnem == "fdiv" || mnem == "fdivp" -> if (ops.size >= 2) "${fo(0)} /= ${fo(1)}" else "st0 /= ${fo(0)}"
            mnem == "fcomi" || mnem == "fcomip" || mnem == "fucomi" || mnem == "fucomip" -> "__fcmp(st0, ${fo(0)})"
            mnem == "rdtsc" -> "edx:eax = __rdtsc()"
            mnem == "cpuid" -> "__cpuid()"
            mnem == "maxsd" || mnem == "maxss" -> "${o(0)} = fmax(${o(0)}, ${o(1)})"
            mnem == "minsd" || mnem == "minss" -> "${o(0)} = fmin(${o(0)}, ${o(1)})"
            (mnem == "maxps" || mnem == "maxpd") -> "${o(0)} = vmax(${o(0)}, ${o(1)})"
            (mnem == "minps" || mnem == "minpd") -> "${o(0)} = vmin(${o(0)}, ${o(1)})"
            mnem == "roundsd" || mnem == "roundss" -> "${o(0)} = round(${o(1)})"
            mnem == "andnps" || mnem == "andnpd" -> "${o(0)} = ~${o(0)} & ${o(1)}"
            mnem == "andps" || mnem == "andpd" -> "${o(0)} &= ${o(1)}"
            mnem == "orps" || mnem == "orpd" -> "${o(0)} |= ${o(1)}"
            mnem == "aesenc" -> "${o(0)} = __aesenc(${o(0)}, ${o(1)})"
            mnem == "aesenclast" -> "${o(0)} = __aesenclast(${o(0)}, ${o(1)})"
            mnem == "aesdec" -> "${o(0)} = __aesdec(${o(0)}, ${o(1)})"
            mnem == "aesdeclast" -> "${o(0)} = __aesdeclast(${o(0)}, ${o(1)})"
            mnem == "aesimc" -> "${o(0)} = __aesimc(${o(1)})"
            mnem == "aeskeygenassist" -> "${o(0)} = __aeskeygenassist(${o(1)}, ${o(2)})"
            mnem == "pclmulqdq" -> "${o(0)} = __pclmulqdq(${o(0)}, ${o(1)}, ${o(2)})"
            mnem == "sha256rnds2" -> "${o(0)} = __sha256rnds2(${o(0)}, ${o(1)}, ${o(2)})"
            mnem == "sha256msg1" -> "${o(0)} = __sha256msg1(${o(0)}, ${o(1)})"
            mnem == "sha256msg2" -> "${o(0)} = __sha256msg2(${o(0)}, ${o(1)})"
            mnem == "sha1rnds4" -> "${o(0)} = __sha1rnds4(${o(0)}, ${o(1)}, ${o(2)})"
            mnem == "sha1nexte" -> "${o(0)} = __sha1nexte(${o(0)}, ${o(1)})"
            mnem == "sha1msg1" -> "${o(0)} = __sha1msg1(${o(0)}, ${o(1)})"
            mnem == "sha1msg2" -> "${o(0)} = __sha1msg2(${o(0)}, ${o(1)})"
            mnem == "gf2p8affineqb" -> "${o(0)} = __gf2p8affineqb(${o(0)}, ${o(1)}, ${o(2)})"
            mnem == "gf2p8mulb" -> "${o(0)} = __gf2p8mulb(${o(0)}, ${o(1)})"
            mnem == "gf2p8affineinvqb" -> "${o(0)} = __gf2p8affineinvqb(${o(0)}, ${o(1)}, ${o(2)})"
            kmask(mnem, ops) != null -> kmask(mnem, ops)
            mnem[0] == 'v' && avx(mnem, ops, cmp) != null -> avx(mnem, ops, cmp)
            mnem.startsWith("set") && mnem.length > 3 -> "${o(0)} = (${condExpr(mnem.substring(3), cmp)})"
            mnem.startsWith("cmov") && ops.size >= 2 -> "if (${condExpr(mnem.substring(4), cmp)}) ${o(0)} = ${o(1)}"
            mnem.startsWith("j") -> "if (${cond(mnem.substring(1), cmp)}) goto ${o(0)}"
            else -> "${mnem} ${ops.joinToString(", ")}".trim()
        }
    }

    private fun kmask(mnem: String, ops: List<String>): String? {
        fun o(i: Int) = mem(ops.getOrElse(i) { "?" })
        if (mnem.length < 2 || mnem[0] != 'k') return null
        if (mnem.startsWith("kunpck")) return "${o(0)} = __kunpck(${o(1)}, ${o(2)})"
        val base = mnem.dropLast(1).takeIf { mnem.last() in "bwdq" } ?: mnem
        return when (base) {
            "kmov" -> "${o(0)} = ${o(1)}"
            "knot" -> "${o(0)} = ~${o(1)}"
            "kand" -> "${o(0)} = ${o(1)} & ${o(2)}"
            "kandn" -> "${o(0)} = ~${o(1)} & ${o(2)}"
            "kor" -> "${o(0)} = ${o(1)} | ${o(2)}"
            "kxor" -> "${o(0)} = ${o(1)} ^ ${o(2)}"
            "kxnor" -> "${o(0)} = ~(${o(1)} ^ ${o(2)})"
            "kadd" -> "${o(0)} = ${o(1)} + ${o(2)}"
            "kshiftl" -> "${o(0)} = ${o(1)} << ${o(2)}"
            "kshiftr" -> "${o(0)} = ${o(1)} >> ${o(2)}"
            "kortest" -> "__kortest(${o(0)}, ${o(1)})"
            "ktest" -> "__ktest(${o(0)}, ${o(1)})"
            else -> null
        }
    }

    private val EVEX_MASK = Regex("""\s*\{(k[0-7])\}(\s*\{z\})?\s*$""")

    private fun stripMask(op: String): Triple<String, String?, Boolean> {
        val m = EVEX_MASK.find(op) ?: return Triple(op, null, false)
        return Triple(op.substring(0, m.range.first).trim(), m.groupValues[1], m.groupValues[2].isNotEmpty())
    }

    private fun avx(vmnem: String, rawOps: List<String>, cmp: Pair<String, List<String>>?): String? {
        val (dest0, mask, zero) = stripMask(rawOps.getOrElse(0) { "?" })
        val ops = if (mask == null) rawOps else listOf(dest0) + rawOps.drop(1)
        val body = avxBody(vmnem, ops, cmp) ?: return null
        if (mask == null || body.isEmpty() || !body.contains(" = ")) return body
        val lhs = body.substringBefore(" = ")
        val rhs = body.substringAfter(" = ")
        val merge = if (zero) "0" else lhs
        return "$lhs = __mask_blend($mask, $rhs, $merge)"
    }

    private fun avxBody(vmnem: String, ops: List<String>, cmp: Pair<String, List<String>>?): String? {
        fun o(i: Int) = mem(ops.getOrElse(i) { "?" })
        val m = vmnem.substring(1)
        val n = ops.size
        if (m == "zeroupper" || m == "zeroall") return ""
        if (m.startsWith("fmaddsub") || m.startsWith("fmsubadd")) {
            val order = m.dropWhile { !it.isDigit() }.takeWhile { it.isDigit() }
            if (order.isEmpty() || n < 3) return null
            val a = o(0); val b = o(1); val c = o(2)
            val (p1, p2, add) = when (order) {
                "132" -> Triple(a, c, b)
                "231" -> Triple(b, c, a)
                else -> Triple(b, a, c)
            }
            val fn = if (m.startsWith("fmaddsub")) "__fmaddsub" else "__fmsubadd"
            return "$a = $fn($p1 * $p2, $add)"
        }
        if (m.startsWith("fmadd") || m.startsWith("fmsub") || m.startsWith("fnmadd") || m.startsWith("fnmsub")) {
            val order = m.dropWhile { !it.isDigit() }.takeWhile { it.isDigit() }
            if (order.isEmpty() || n < 3) return null
            val a = o(0); val b = o(1); val c = o(2)
            val (p1, p2, add) = when (order) {
                "132" -> Triple(a, c, b)
                "231" -> Triple(b, c, a)
                else -> Triple(b, a, c)
            }
            val prod = "$p1 * $p2"
            return when {
                m.startsWith("fnmadd") -> "$a = -($prod) + $add"
                m.startsWith("fnmsub") -> "$a = -($prod) - $add"
                m.startsWith("fmsub") -> "$a = $prod - $add"
                else -> "$a = $prod + $add"
            }
        }
        return when {
            (m == "addsd" || m == "addss") && n >= 3 -> "${o(0)} = ${o(1)} + ${o(2)}"
            (m == "subsd" || m == "subss") && n >= 3 -> "${o(0)} = ${o(1)} - ${o(2)}"
            (m == "mulsd" || m == "mulss") && n >= 3 -> "${o(0)} = ${o(1)} * ${o(2)}"
            (m == "divsd" || m == "divss") && n >= 3 -> "${o(0)} = ${o(1)} / ${o(2)}"
            (m == "maxsd" || m == "maxss") && n >= 3 -> "${o(0)} = fmax(${o(1)}, ${o(2)})"
            (m == "minsd" || m == "minss") && n >= 3 -> "${o(0)} = fmin(${o(1)}, ${o(2)})"
            m == "sqrtsd" || m == "sqrtss" -> "${o(0)} = sqrt(${o(n - 1)})"
            (m == "roundsd" || m == "roundss") && n >= 3 -> "${o(0)} = round(${o(n - 2)})"
            m == "cvtsi2sd" || m == "cvtss2sd" -> "${o(0)} = (double)${o(n - 1)}"
            m == "cvtsi2ss" || m == "cvtsd2ss" -> "${o(0)} = (float)${o(n - 1)}"
            m == "cvttsd2si" || m == "cvttss2si" || m == "cvtsd2si" || m == "cvtss2si" -> "${o(0)} = (long)${o(n - 1)}"
            (m == "xorps" || m == "xorpd" || m == "pxor") && n == 3 && ops[1] == ops[2] -> "${o(0)} = 0"
            (m == "andnps" || m == "andnpd" || m == "pandn") && n >= 3 -> "${o(0)} = ~${o(1)} & ${o(2)}"
            (m == "andps" || m == "andpd" || m == "pand") && n >= 3 -> "${o(0)} = ${o(1)} & ${o(2)}"
            (m == "orps" || m == "orpd" || m == "por") && n >= 3 -> "${o(0)} = ${o(1)} | ${o(2)}"
            (m == "xorps" || m == "xorpd" || m == "pxor") && n >= 3 -> "${o(0)} = ${o(1)} ^ ${o(2)}"
            (m == "addps" || m == "addpd") && n >= 3 -> "${o(0)} = vadd(${o(1)}, ${o(2)})"
            (m == "subps" || m == "subpd") && n >= 3 -> "${o(0)} = vsub(${o(1)}, ${o(2)})"
            (m == "mulps" || m == "mulpd") && n >= 3 -> "${o(0)} = vmul(${o(1)}, ${o(2)})"
            (m == "divps" || m == "divpd") && n >= 3 -> "${o(0)} = vdiv(${o(1)}, ${o(2)})"
            (m == "movsd" || m == "movss" || m == "movd" || m == "movq" || m == "movaps" || m == "movapd" ||
                m == "movups" || m == "movupd" || m == "movdqa" || m == "movdqu" || m == "lddqu") && n == 2 -> "${o(0)} = ${o(1)}"
            m == "movmskps" || m == "movmskpd" -> "${o(0)} = movmsk(${o(1)})"
            m == "pmovmskb" -> "${o(0)} = pmovmskb(${o(1)})"
            (m == "broadcastss" || m == "broadcastsd" || m == "pbroadcastb" || m == "pbroadcastw" ||
                m == "pbroadcastd" || m == "pbroadcastq" || m == "broadcastf128" || m == "broadcasti128") && n == 2 ->
                "${o(0)} = broadcast(${o(1)})"
            (m == "blendvps" || m == "blendvpd" || m == "pblendvb") && n >= 4 -> "${o(0)} = blendv(${o(1)}, ${o(2)}, ${o(3)})"
            (m == "blendps" || m == "blendpd" || m == "pblendw" || m == "pblendd") && n >= 4 -> "${o(0)} = blend(${o(1)}, ${o(2)}, ${o(3)})"
            (m == "permilps" || m == "permilpd") && n >= 3 -> "${o(0)} = permil(${o(1)}, ${o(2)})"
            (m == "perm2f128" || m == "perm2i128") && n >= 4 -> "${o(0)} = perm2(${o(1)}, ${o(2)}, ${o(3)})"
            (m == "extractf128" || m == "extracti128") && n >= 3 -> "${o(0)} = extract128(${o(1)}, ${o(2)})"
            (m == "insertf128" || m == "inserti128") && n >= 4 -> "${o(0)} = insert128(${o(1)}, ${o(2)}, ${o(3)})"
            (m == "ptest" || m == "testps" || m == "testpd") && n == 2 -> "__ptest(${o(0)}, ${o(1)})"
            m == "cvtph2ps" && n >= 2 -> "${o(0)} = __cvtph2ps(${o(n - 1)})"
            m == "cvtps2ph" && n >= 2 -> "${o(0)} = __cvtps2ph(${o(1)}, ${o(n - 1)})"
            (m == "addpd" || m == "addps") && n >= 3 -> "${o(0)} = vadd(${o(1)}, ${o(2)})"
            (m == "subpd" || m == "subps") && n >= 3 -> "${o(0)} = vsub(${o(1)}, ${o(2)})"
            (m == "mulpd" || m == "mulps") && n >= 3 -> "${o(0)} = vmul(${o(1)}, ${o(2)})"
            (m == "divpd" || m == "divps") && n >= 3 -> "${o(0)} = vdiv(${o(1)}, ${o(2)})"
            m == "aesenc" && n >= 3 -> "${o(0)} = __aesenc(${o(1)}, ${o(2)})"
            m == "aesenclast" && n >= 3 -> "${o(0)} = __aesenclast(${o(1)}, ${o(2)})"
            m == "aesdec" && n >= 3 -> "${o(0)} = __aesdec(${o(1)}, ${o(2)})"
            m == "aesdeclast" && n >= 3 -> "${o(0)} = __aesdeclast(${o(1)}, ${o(2)})"
            m == "pclmulqdq" && n >= 4 -> "${o(0)} = __pclmulqdq(${o(1)}, ${o(2)}, ${o(3)})"
            (m == "pternlogd" || m == "pternlogq") && n >= 4 -> "${o(0)} = __vpternlog(${o(0)}, ${o(1)}, ${o(2)}, ${o(3)})"
            (m == "pconflictd" || m == "pconflictq") && n >= 2 -> "${o(0)} = __vpconflict(${o(1)})"
            (m == "plzcntd" || m == "plzcntq") && n >= 2 -> "${o(0)} = __vplzcnt(${o(1)})"
            (m == "popcntb" || m == "popcntw" || m == "popcntd" || m == "popcntq") && n >= 2 -> "${o(0)} = __vpopcnt(${o(1)})"
            (m == "scalefpd" || m == "scalefps" || m == "scalefsd" || m == "scalefss") && n >= 3 -> "${o(0)} = __vscalef(${o(1)}, ${o(2)})"
            (m == "getexppd" || m == "getexpps" || m == "getexpsd" || m == "getexpss") && n >= 2 -> "${o(0)} = __vgetexp(${o(n - 1)})"
            (m == "getmantpd" || m == "getmantps" || m == "getmantsd" || m == "getmantss") && n >= 3 -> "${o(0)} = __vgetmant(${o(n - 2)}, ${o(n - 1)})"
            (m == "rcp14pd" || m == "rcp14ps" || m == "rcp14sd" || m == "rcp14ss") && n >= 2 -> "${o(0)} = __vrcp14(${o(n - 1)})"
            (m == "rsqrt14pd" || m == "rsqrt14ps" || m == "rsqrt14sd" || m == "rsqrt14ss") && n >= 2 -> "${o(0)} = __vrsqrt14(${o(n - 1)})"
            (m == "gf2p8affineqb") && n >= 4 -> "${o(0)} = __gf2p8affineqb(${o(1)}, ${o(2)}, ${o(3)})"
            (m == "gf2p8affineinvqb") && n >= 4 -> "${o(0)} = __gf2p8affineinvqb(${o(1)}, ${o(2)}, ${o(3)})"
            (m == "gf2p8mulb") && n >= 3 -> "${o(0)} = __gf2p8mulb(${o(1)}, ${o(2)})"
            m.startsWith("pcompress") && n >= 2 -> "${o(0)} = __vpcompress(${o(1)})"
            m.startsWith("pexpand") && n >= 2 -> "${o(0)} = __vpexpand(${o(1)})"
            m.startsWith("compress") && n >= 2 -> "${o(0)} = __vcompress(${o(1)})"
            m.startsWith("expand") && n >= 2 -> "${o(0)} = __vexpand(${o(1)})"
            (m.startsWith("rndscale")) && n >= 3 -> "${o(0)} = __vrndscale(${o(n - 2)}, ${o(n - 1)})"
            (m.startsWith("fixupimm")) && n >= 4 -> "${o(0)} = __vfixupimm(${o(0)}, ${o(1)}, ${o(2)}, ${o(3)})"
            (m == "gatherdps" || m == "gatherdpd" || m == "gatherqps" || m == "gatherqpd") && n >= 2 -> "${o(0)} = __vgather(${o(1)})"
            (m == "pgatherdd" || m == "pgatherdq" || m == "pgatherqd" || m == "pgatherqq") && n >= 2 -> "${o(0)} = __vpgather(${o(1)})"
            (m == "pmovzxbd" || m == "pmovzxbw" || m == "pmovzxbq" || m == "pmovzxwd" || m == "pmovzxwq" || m == "pmovzxdq") && n == 2 -> "${o(0)} = __vpmovzx(${o(1)})"
            (m == "pmovsxbd" || m == "pmovsxbw" || m == "pmovsxbq" || m == "pmovsxwd" || m == "pmovsxwq" || m == "pmovsxdq") && n == 2 -> "${o(0)} = __vpmovsx(${o(1)})"
            (m == "movdqa64" || m == "movdqa32" || m == "movdqu64" || m == "movdqu32" || m == "movdqu8" || m == "movdqu16") && n == 2 -> "${o(0)} = ${o(1)}"
            m.startsWith("ptestm") && n >= 3 -> "${o(0)} = __vptestm(${o(n - 2)}, ${o(n - 1)})"
            m.startsWith("ptestnm") && n >= 3 -> "${o(0)} = __vptestnm(${o(n - 2)}, ${o(n - 1)})"
            else -> null
        }
    }

    private fun mips(mnem: String, ops: List<String>): String? {
        fun o(i: Int) = ops.getOrElse(i) { "?" }
        return when {
            mnem == "nop" -> ""
            mnem == "jr" || mnem == "jrc" -> if (o(0) == "ra" || o(0) == "\$ra") "return" else "goto ${o(0)}"
            mnem == "j" || mnem == "b" || mnem == "bc" -> "goto ${o(0)}"
            mnem == "jal" || mnem == "jalr" || mnem == "bal" || mnem == "balc" || mnem == "jalrc" -> "${o(0)}()"
            mnem == "jic" -> "goto ${o(1)}(${o(0)})"
            mnem == "jialc" -> "${o(1)}(${o(0)})"
            mnem == "beqzc" -> "if (${o(0)} == 0) goto ${o(1)}"
            mnem == "bnezc" -> "if (${o(0)} != 0) goto ${o(1)}"
            mnem == "beqc" -> "if (${o(0)} == ${o(1)}) goto ${o(2)}"
            mnem == "bnec" -> "if (${o(0)} != ${o(1)}) goto ${o(2)}"
            mnem == "lui" -> "${o(0)} = ${o(1)} << 16"
            mnem == "aui" || mnem == "daui" -> "${o(0)} = ${o(1)} + (${o(2)} << 16)"
            mnem == "dahi" -> "${o(0)} = ${o(0)} + ((int64_t)${o(1)} << 32)"
            mnem == "dati" -> "${o(0)} = ${o(0)} + ((int64_t)${o(1)} << 48)"
            mnem == "move" || mnem == "li" -> "${o(0)} = ${o(1)}"
            mnem == "addiu" || mnem == "addu" || mnem == "add" || mnem == "addi" ||
                mnem == "daddiu" || mnem == "daddu" || mnem == "dadd" || mnem == "daddi" -> "${o(0)} = ${o(1)} + ${o(2)}"
            mnem == "subu" || mnem == "sub" || mnem == "dsubu" || mnem == "dsub" -> "${o(0)} = ${o(1)} - ${o(2)}"
            mnem == "mul" -> "${o(0)} = ${o(1)} * ${o(2)}"
            mnem == "and" || mnem == "andi" -> "${o(0)} = ${o(1)} & ${o(2)}"
            mnem == "or" || mnem == "ori" -> "${o(0)} = ${o(1)} | ${o(2)}"
            mnem == "xor" || mnem == "xori" -> "${o(0)} = ${o(1)} ^ ${o(2)}"
            mnem == "sll" -> "${o(0)} = ${o(1)} << ${o(2)}"
            mnem == "srl" -> "${o(0)} = (unsigned)${o(1)} >> ${o(2)}"
            mnem == "sra" -> "${o(0)} = ${o(1)} >> ${o(2)}"
            mnem == "dsll" -> "${o(0)} = ${o(1)} << ${o(2)}"
            mnem == "dsll32" -> "${o(0)} = ${o(1)} << (${o(2)} + 32)"
            mnem == "dsrl" -> "${o(0)} = (uint64_t)${o(1)} >> ${o(2)}"
            mnem == "dsrl32" -> "${o(0)} = (uint64_t)${o(1)} >> (${o(2)} + 32)"
            mnem == "dsra" -> "${o(0)} = ${o(1)} >> ${o(2)}"
            mnem == "dsra32" -> "${o(0)} = ${o(1)} >> (${o(2)} + 32)"
            mnem == "dsllv" -> "${o(0)} = ${o(1)} << ${o(2)}"
            mnem == "dsrlv" -> "${o(0)} = (uint64_t)${o(1)} >> ${o(2)}"
            mnem == "dsrav" -> "${o(0)} = ${o(1)} >> ${o(2)}"
            mnem == "lb" -> "${o(0)} = (int8_t)${mem(o(1))}"
            mnem == "lbu" -> "${o(0)} = (uint8_t)${mem(o(1))}"
            mnem == "lh" -> "${o(0)} = (int16_t)${mem(o(1))}"
            mnem == "lhu" -> "${o(0)} = (uint16_t)${mem(o(1))}"
            mnem == "lwu" -> "${o(0)} = (uint32_t)${mem(o(1))}"
            mnem == "lw" || mnem == "ld" || mnem == "lwc1" || mnem == "ldc1" ||
                mnem == "lwxc1" || mnem == "ldxc1" || mnem == "luxc1" -> "${o(0)} = ${mem(o(1))}"
            mnem == "sw" || mnem == "sb" || mnem == "sh" || mnem == "sd" || mnem == "swc1" || mnem == "sdc1" ||
                mnem == "swxc1" || mnem == "sdxc1" || mnem == "suxc1" -> "${mem(o(1))} = ${o(0)}"
            mnem == "pref" || mnem == "prefx" || mnem == "cache" -> ""
            mnem == "lwl" -> "${o(0)} = __lwl(${o(0)}, ${memAddr(o(1))})"
            mnem == "lwr" -> "${o(0)} = __lwr(${o(0)}, ${memAddr(o(1))})"
            mnem == "swl" -> "__swl(${memAddr(o(1))}, ${o(0)})"
            mnem == "swr" -> "__swr(${memAddr(o(1))}, ${o(0)})"
            mnem == "seb" -> "${o(0)} = (int8_t)${o(1)}"
            mnem == "seh" -> "${o(0)} = (int16_t)${o(1)}"
            mnem == "wsbh" -> "${o(0)} = wsbh(${o(1)})"
            mnem == "ll" || mnem == "lld" -> "${o(0)} = __ll(${memAddr(o(1)).removeSurrounding("(", ")")})"
            mnem == "sc" || mnem == "scd" -> "${o(0)} = __sc(${memAddr(o(1)).removeSurrounding("(", ")")}, ${o(0)})"
            mnem == "beq" -> "if (${o(0)} == ${o(1)}) goto ${o(2)}"
            mnem == "bne" -> "if (${o(0)} != ${o(1)}) goto ${o(2)}"
            mnem == "beqz" -> "if (${o(0)} == 0) goto ${o(1)}"
            mnem == "bnez" -> "if (${o(0)} != 0) goto ${o(1)}"
            mnem == "bgtz" -> "if (${o(0)} > 0) goto ${o(1)}"
            mnem == "bltz" -> "if (${o(0)} < 0) goto ${o(1)}"
            mnem == "bgez" -> "if (${o(0)} >= 0) goto ${o(1)}"
            mnem == "blez" -> "if (${o(0)} <= 0) goto ${o(1)}"
            mnem == "bgezal" || mnem == "bgezall" -> "if (${o(0)} >= 0) ${o(1)}()"
            mnem == "bltzal" || mnem == "bltzall" -> "if (${o(0)} < 0) ${o(1)}()"
            mnem == "slt" || mnem == "slti" -> "${o(0)} = (${o(1)} < ${o(2)})"
            mnem == "sltu" || mnem == "sltiu" -> "${o(0)} = ((unsigned)${o(1)} < (unsigned)${o(2)})"
            mnem == "nor" -> "${o(0)} = ~(${o(1)} | ${o(2)})"
            mnem == "movz" -> "if (${o(2)} == 0) ${o(0)} = ${o(1)}"
            mnem == "movn" -> "if (${o(2)} != 0) ${o(0)} = ${o(1)}"
            mnem == "seleqz" -> "${o(0)} = (${o(2)} == 0) ? ${o(1)} : 0"
            mnem == "selnez" -> "${o(0)} = (${o(2)} != 0) ? ${o(1)} : 0"
            mnem == "negu" || mnem == "neg" -> "${o(0)} = -${o(1)}"
            mnem == "sllv" -> "${o(0)} = ${o(1)} << ${o(2)}"
            mnem == "srlv" -> "${o(0)} = (unsigned)${o(1)} >> ${o(2)}"
            mnem == "srav" -> "${o(0)} = ${o(1)} >> ${o(2)}"
            mnem == "clz" || mnem == "dclz" -> "${o(0)} = clz(${o(1)})"
            mnem == "clo" || mnem == "dclo" -> "${o(0)} = clo(${o(1)})"
            mnem == "dsbh" -> "${o(0)} = dsbh(${o(1)})"
            mnem == "dshd" -> "${o(0)} = dshd(${o(1)})"
            mnem == "bitswap" -> "${o(0)} = rbit(${o(1)})"
            mnem == "dbitswap" -> "${o(0)} = rbit(${o(1)})"
            mnem == "not" -> "${o(0)} = ~${o(1)}"
            mnem == "rotr" || mnem == "rotrv" || mnem == "drotr" || mnem == "drotrv" -> "${o(0)} = rotr(${o(1)}, ${o(2)})"
            mnem == "ext" || mnem == "dext" -> "${o(0)} = (${o(1)} >> ${o(2)}) & ((1 << ${o(3)}) - 1)"
            mnem == "ins" || mnem == "dins" -> "${o(0)} = (${o(0)} & ~(((1 << ${o(3)}) - 1) << ${o(2)})) | ((${o(1)} & ((1 << ${o(3)}) - 1)) << ${o(2)})"
            mnem == "seq" -> "${o(0)} = (${o(1)} == ${o(2)})"
            mnem == "sne" -> "${o(0)} = (${o(1)} != ${o(2)})"
            mnem == "tne" -> "if (${o(0)} != ${o(1)}) __trap()"
            mnem == "tge" -> "if (${o(0)} >= ${o(1)}) __trap()"
            mnem == "tgeu" -> "if ((unsigned)${o(0)} >= (unsigned)${o(1)}) __trap()"
            mnem == "tlt" -> "if (${o(0)} < ${o(1)}) __trap()"
            mnem == "tltu" -> "if ((unsigned)${o(0)} < (unsigned)${o(1)}) __trap()"
            mnem == "teqi" -> "if (${o(0)} == ${o(1)}) __trap()"
            mnem == "tnei" -> "if (${o(0)} != ${o(1)}) __trap()"
            mnem == "tgei" -> "if (${o(0)} >= ${o(1)}) __trap()"
            mnem == "tgeiu" -> "if ((unsigned)${o(0)} >= (unsigned)${o(1)}) __trap()"
            mnem == "tlti" -> "if (${o(0)} < ${o(1)}) __trap()"
            mnem == "tltiu" -> "if ((unsigned)${o(0)} < (unsigned)${o(1)}) __trap()"
            mnem == "madd" || mnem == "maddu" || mnem == "dmadd" -> {
                val (x, y) = if (ops.size >= 3) o(1) to o(2) else o(0) to o(1)
                "hi:lo = hi:lo + $x * $y"
            }
            mnem == "msub" || mnem == "msubu" || mnem == "dmsub" -> {
                val (x, y) = if (ops.size >= 3) o(1) to o(2) else o(0) to o(1)
                "hi:lo = hi:lo - $x * $y"
            }
            mnem == "muh" || mnem == "muhu" -> "${o(0)} = (${o(1)} * ${o(2)}) >> 32"
            mnem.startsWith("madd.") -> "${o(0)} = ${o(1)} + ${o(2)} * ${o(3)}"
            mnem.startsWith("msub.") -> "${o(0)} = ${o(2)} * ${o(3)} - ${o(1)}"
            mnem.startsWith("nmadd.") -> "${o(0)} = -(${o(1)} + ${o(2)} * ${o(3)})"
            mnem.startsWith("nmsub.") -> "${o(0)} = -(${o(2)} * ${o(3)} - ${o(1)})"
            mnem.startsWith("recip.") -> "${o(0)} = 1.0 / ${o(1)}"
            mnem.startsWith("rsqrt.") -> "${o(0)} = 1.0 / sqrt(${o(1)})"
            mnem.startsWith("add.") -> "${o(0)} = ${o(1)} + ${o(2)}"
            mnem.startsWith("sub.") -> "${o(0)} = ${o(1)} - ${o(2)}"
            mnem.startsWith("mul.") -> "${o(0)} = ${o(1)} * ${o(2)}"
            mnem.startsWith("div.") -> "${o(0)} = ${o(1)} / ${o(2)}"
            mnem.startsWith("neg.") -> "${o(0)} = -${o(1)}"
            mnem.startsWith("abs.") -> "${o(0)} = fabs(${o(1)})"
            mnem.startsWith("sqrt.") -> "${o(0)} = sqrt(${o(1)})"
            mnem.startsWith("cvt.") || mnem.startsWith("trunc.") || mnem.startsWith("round.") ||
                mnem.startsWith("ceil.") || mnem.startsWith("floor.") -> "${o(0)} = (${fpCastType(mnem)})${o(1)}"
            mnem.startsWith("c.") && mnem.count { it == '.' } == 2 -> "fp_cond = ${o(0)} ${fpCmpOp(mnem)} ${o(1)}"
            mnem == "movt" || mnem == "movt.s" || mnem == "movt.d" -> "if (fp_cond) ${o(0)} = ${o(1)}"
            mnem == "movf" || mnem == "movf.s" || mnem == "movf.d" -> "if (!fp_cond) ${o(0)} = ${o(1)}"
            mnem == "mfhc1" -> "${o(0)} = hi(${o(1)})"
            mnem == "mthc1" -> "hi(${o(1)}) = ${o(0)}"
            mnem == "sync" -> "__sync()"
            mnem == "synci" -> ""
            mnem == "ehb" -> ""
            mnem == "rdhwr" -> "${o(0)} = hwr(${o(1)})"
            mnem == "mfc0" || mnem == "dmfc0" -> "${o(0)} = cp0(${o(1)})"
            mnem == "mtc0" || mnem == "dmtc0" -> "cp0(${o(1)}) = ${o(0)}"
            mnem == "cfc1" -> "${o(0)} = fcr(${o(1)})"
            mnem == "ctc1" -> "fcr(${o(1)}) = ${o(0)}"
            mnem == "lwc2" || mnem == "ldc2" -> "${o(0)} = ${mem(o(1))}"
            mnem == "swc2" || mnem == "sdc2" -> "${mem(o(1))} = ${o(0)}"
            mnem == "mult" || mnem == "multu" || mnem == "dmult" || mnem == "dmultu" -> {
                val (x, y) = if (ops.size >= 3) o(1) to o(2) else o(0) to o(1)
                "hi:lo = $x * $y"
            }
            (mnem == "div" || mnem == "ddiv") && ops.size >= 3 && o(0) != "\$zero" && o(0) != "zero" -> "${o(0)} = ${o(1)} / ${o(2)}"
            (mnem == "divu" || mnem == "ddivu") && ops.size >= 3 && o(0) != "\$zero" && o(0) != "zero" -> "${o(0)} = (unsigned)${o(1)} / (unsigned)${o(2)}"
            mnem == "mod" -> "${o(0)} = ${o(1)} % ${o(2)}"
            mnem == "modu" -> "${o(0)} = (unsigned)${o(1)} % (unsigned)${o(2)}"
            mnem == "div" || mnem == "divu" || mnem == "ddiv" || mnem == "ddivu" -> {
                val (x, y) = if (ops.size >= 3) o(1) to o(2) else o(0) to o(1)
                "lo = $x / $y, hi = $x % $y"
            }
            mnem == "mflo" -> "${o(0)} = lo"
            mnem == "mfhi" -> "${o(0)} = hi"
            mnem == "mtlo" -> "lo = ${o(0)}"
            mnem == "mthi" -> "hi = ${o(0)}"
            mnem == "mtc1" || mnem == "dmtc1" -> "${o(1)} = ${o(0)}"
            mnem == "mov.s" || mnem == "mov.d" || mnem == "mfc1" || mnem == "dmfc1" -> "${o(0)} = ${o(1)}"
            mnem == "teq" -> "if (${o(0)} == ${o(1)}) __trap()"
            else -> "${mnem} ${ops.joinToString(", ")}".trim()
        }
    }

    private fun fpCastType(mnem: String): String = when (mnem.split(".").getOrNull(1)) {
        "s" -> "float"; "d" -> "double"; "w" -> "int32_t"; "l" -> "int64_t"; else -> "float"
    }

    private fun fpCmpOp(mnem: String): String = when (mnem.split(".").getOrNull(1)) {
        "eq", "ueq", "seq" -> "=="; "lt", "ult", "olt" -> "<"; "le", "ule", "ole" -> "<="
        "ngt" -> "<="; "nge" -> "<"; else -> "=="
    }

    private fun condExpr(suffix: String, cmp: Pair<String, List<String>>?): String =
        if (cmp != null) cond(suffix, cmp) else suffix

    private fun cond(suffix: String, cmp: Pair<String, List<String>>?): String {
        val mnem = cmp?.first
        val ops = cmp?.second
        if (ops == null) return "cond_$suffix"
        val a = mem(ops.getOrNull(0) ?: "a")
        var b = mem(ops.getOrNull(1) ?: "b")
        if (mnem == "bt") {
            val bit = "(($a >> $b) & 1)"
            return when (suffix) {
                "b", "c", "nae" -> "$bit != 0"
                "ae", "nc", "nb" -> "$bit == 0"
                else -> bit
            }
        }
        ops.getOrNull(2)?.let { if (isShiftMod(it)) shiftExpr(b, it)?.let { e -> b = e } }
        val bitwise = mnem == "test" || mnem == "tst"
        val lhs: String; val rhs: String
        if (bitwise) {
            lhs = if (a == b) a else "($a & $b)"
            rhs = "0"
        } else {
            lhs = a; rhs = if (mnem == "cmn") "-$b" else b
        }
        fun u(op: String) = "(unsigned)$lhs $op (unsigned)$rhs"
        return when (suffix) {
            "eq", "e", "z" -> "$lhs == $rhs"
            "ne", "nz" -> "$lhs != $rhs"
            "lt", "l" -> "$lhs < $rhs"
            "le" -> "$lhs <= $rhs"
            "gt", "g" -> "$lhs > $rhs"
            "ge" -> "$lhs >= $rhs"
            "b", "lo", "cc", "c" -> u("<")
            "be", "ls" -> u("<=")
            "a", "hi" -> u(">")
            "ae", "hs", "cs", "nc" -> u(">=")
            "mi", "s" -> if (rhs == "0") "$lhs < 0" else "($lhs - $rhs) < 0"
            "pl", "ns" -> if (rhs == "0") "$lhs >= 0" else "($lhs - $rhs) >= 0"
            "al" -> "1"
            "vs", "o" -> "overflow($lhs, $rhs)"
            "vc", "no" -> "!overflow($lhs, $rhs)"
            "p", "pe" -> "parity($lhs)"
            "np", "po" -> "!parity($lhs)"
            else -> "cond_$suffix($lhs, $rhs)"
        }
    }

    private fun funcName(name: String): String {
        if (name.isEmpty()) return "fn"
        return if (name.first().isLetter() || name.first() == '_') name.takeWhile { it.isLetterOrDigit() || it == '_' }.ifEmpty { "fn" } else "fn"
    }

    private val ARM64_REG = Regex("""\b[xw](\d{1,2}|zr)\b""")
    private val X86_REG = Regex("""\b[re](ax|bx|cx|dx|si|di|sp|bp)\b|\br(8|9|1[0-5])[dwb]\b|\b[xyz]mm\d+\b|\brip\b""")
    private val MIPS_REG = Regex("""\$[a-z]\d|\bzero\b|\$\w+""")
    private val ARM32_REG = Regex("""\br\d{1,2}\b""")

    private fun detectArch(lines: List<String>): A {
        val sample = lines.asSequence().filter { val t = it.trimStart(); t.length >= 10 && t[8] == ':' }.take(60).joinToString("\n")
        return when {
            ARM64_REG.containsMatchIn(sample) -> A.ARM
            X86_REG.containsMatchIn(sample) -> A.X86
            MIPS_REG.containsMatchIn(sample) -> A.MIPS
            ARM32_REG.containsMatchIn(sample) -> A.ARM
            else -> A.ARM
        }
    }
}
