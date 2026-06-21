package io.github.nitanmarcel.jdex.disasm

object NativeJumpTable {

    class Result(val indexReg: String, val targets: List<Long>)

    private const val MAX_CASES = 1024
    private val NUM = Regex("0x[0-9a-fA-F]+|\\d+")

    fun resolve(insns: List<Insn>, branchIdx: Int, elf: ElfFile, arch: ElfArch): Result? {
        return when (arch) {
            ElfArch.ARM64 -> resolveArm64(insns, branchIdx, elf)
            ElfArch.X86_64, ElfArch.X86 -> resolveX86(insns, branchIdx, elf)
            ElfArch.MIPS -> resolveMips(insns, branchIdx, elf)
            ElfArch.ARM -> resolveArmThumb(insns, branchIdx, elf)
            else -> null
        }
    }

    private fun resolveArmThumb(insns: List<Insn>, k: Int, elf: ElfFile): Result? {
        val branch = insns[k]
        val m = coreMnem(branch.mnemonic).substringBefore('.')
        if (m != "tbb" && m != "tbh") return null
        val elemSize = if (m == "tbh") 2 else 1
        val inner = inside(branch.operands) ?: return null
        val parts = inner.split(",").map { it.trim() }
        if (parts.firstOrNull()?.lowercase() != "pc") return null
        val idxReg = parts.getOrNull(1)?.let { stripShift(it) }?.takeIf { it.isNotEmpty() } ?: return null
        val base = branch.address + 4
        val count = boundFromArmCmp(insns, k, maxOf(0, k - 8), idxReg) ?: return null
        val targets = ArrayList<Long>(count)
        for (i in 0 until count) {
            val entry = (if (elemSize == 2) elf.readShort(base + i.toLong() * 2)?.toLong()?.and(0xFFFFL)
                else elf.readByte(base + i.toLong())?.toLong()?.and(0xFFL)) ?: return null
            val t = base + 2 * entry
            if (!inExec(elf, t)) return null
            targets.add(t)
        }
        return Result(idxReg, targets)
    }

    private fun boundFromArmCmp(insns: List<Insn>, before: Int, lo: Int, idxReg: String): Int? {
        for (j in before - 1 downTo lo) {
            val m = insns[j].mnemonic.lowercase().substringAfterLast(' ').substringBefore('.')
            val ops = split(insns[j].operands)
            if (m == "cmp" && ops.size == 2 && ops[0] == idxReg) {
                val n = simm(ops[1]) ?: return null
                if (n in 0L..MAX_CASES.toLong()) {
                    val g = insns.getOrNull(j + 1)?.mnemonic?.lowercase()?.substringAfterLast(' ')?.substringBefore('.') ?: ""
                    val exclusive = g == "bcs" || g == "bhs" || g == "bge"
                    return (if (exclusive) n else n + 1).toInt()
                }
            }
        }
        return null
    }

    private fun resolveMips(insns: List<Insn>, k: Int, elf: ElfFile): Result? {
        val branch = insns[k]
        if (coreMnem(branch.mnemonic) != "jr") return null
        val brReg = branch.operands.trim()
        if (brReg.isEmpty() || brReg == "\$ra" || '(' in brReg) return null
        val lo = maxOf(0, k - 24)

        var pAddu = -1; var offReg: String? = null
        for (j in k - 1 downTo lo) {
            val m = insns[j].mnemonic.lowercase(); val ops = split(insns[j].operands)
            if (m == "addu" && ops.size == 3 && ops[0] == brReg) {
                offReg = when ("\$gp") { ops[1] -> ops[2]; ops[2] -> ops[1]; else -> null }
                pAddu = j; break
            }
        }
        if (offReg == null) return null

        var pLw = -1; var tableDisp: Long? = null; var addrReg: String? = null
        for (j in pAddu - 1 downTo lo) {
            val m = insns[j].mnemonic.lowercase(); val ops = split(insns[j].operands)
            if (m == "lw" && ops.size == 2 && ops[0] == offReg && '(' in ops[1]) {
                val mm = parseMipsMem(ops[1]) ?: return null
                tableDisp = mm.first; addrReg = mm.second; pLw = j; break
            }
        }
        if (tableDisp == null || addrReg == null) return null

        var idxReg: String? = null
        for (j in pLw - 1 downTo lo) {
            val m = insns[j].mnemonic.lowercase(); val ops = split(insns[j].operands)
            if (m == "addu" && ops.size == 3 && ops[0] == addrReg) {
                for (cand in listOf(ops[1], ops[2])) {
                    val s = findMipsScaledIndex(insns, j, lo, cand)
                    if (s != null) { idxReg = s; break }
                }
                break
            }
        }
        val idx = idxReg ?: return null

        val count = boundFromSltiu(insns, k, lo, idx) ?: return null
        val gpVal = mipsGp(insns, k) ?: return null

        val targets = ArrayList<Long>(count)
        for (i in 0 until count) {
            val entry = elf.readInt(tableDisp + i.toLong() * 4) ?: return null
            val t = gpVal + entry.toLong()
            if (!inExec(elf, t)) return null
            targets.add(t)
        }
        return Result(idx, targets)
    }

    private fun parseMipsMem(op: String): Pair<Long, String>? {
        val lp = op.indexOf('('); val rp = op.indexOf(')')
        if (lp < 0 || rp <= lp) return null
        val disp = simm(op.substring(0, lp).trim()) ?: 0L
        val base = op.substring(lp + 1, rp).trim()
        return if (base.isEmpty()) null else disp to base
    }

    private fun findMipsScaledIndex(insns: List<Insn>, before: Int, lo: Int, reg: String): String? {
        for (j in before - 1 downTo lo) {
            val ops = split(insns[j].operands)
            if (ops.isNotEmpty() && ops[0] == reg) {
                return if (insns[j].mnemonic.lowercase() == "sll" && ops.size == 3 && simm(ops[2]) == 2L) ops[1] else null
            }
        }
        return null
    }

    private fun boundFromSltiu(insns: List<Insn>, before: Int, lo: Int, idxReg: String): Int? {
        for (j in before - 1 downTo lo) {
            val m = insns[j].mnemonic.lowercase(); val ops = split(insns[j].operands)
            if ((m == "sltiu" || m == "slti") && ops.size == 3 && ops[1] == idxReg) {
                val n = simm(ops[2])
                if (n != null && n in 1L..MAX_CASES.toLong()) return n.toInt()
            }
        }
        return null
    }

    private fun mipsGp(insns: List<Insn>, k: Int): Long? {
        val funcEntry = insns.first().address
        var hiReg: String? = null
        for (j in k - 1 downTo 0) {
            val m = insns[j].mnemonic.lowercase(); val ops = split(insns[j].operands)
            if (m == "addu" && ops.size == 3 && ops[0] == "\$gp") {
                hiReg = when {
                    ops[2] == "\$t9" || ops[2] == "\$25" -> ops[1]
                    ops[1] == "\$t9" || ops[1] == "\$25" -> ops[2]
                    else -> null
                }
                break
            }
        }
        val reg = hiReg ?: return null
        var hi: Long? = null; var loImm = 0L
        for (j in 0 until k) {
            val m = insns[j].mnemonic.lowercase(); val ops = split(insns[j].operands)
            if (m == "lui" && ops.size == 2 && ops[0] == reg) hi = simm(ops[1])
            if (m == "addiu" && ops.size == 3 && ops[0] == reg && ops[1] == reg) loImm = simm(ops[2]) ?: 0L
        }
        val h = hi ?: return null
        return (h shl 16) + loImm + funcEntry
    }

    private fun simm(s: String): Long? {
        val t = s.trim().removePrefix("#").trim()
        val neg = t.startsWith("-")
        val u = t.removePrefix("-").trim()
        val v = if (u.startsWith("0x") || u.startsWith("0X")) u.substring(2).toLongOrNull(16) else u.toLongOrNull()
        return v?.let { if (neg) -it else it }
    }

    private fun resolveArm64(insns: List<Insn>, k: Int, elf: ElfFile): Result? {
        val branch = insns[k]
        if (coreMnem(branch.mnemonic) != "br") return null
        val brReg = branch.operands.trim()
        if (brReg.isEmpty() || '[' in brReg) return null
        val lo = maxOf(0, k - 16)

        var addBaseReg: String? = null; var offReg: String? = null; var ext: String? = null
        for (j in k - 1 downTo lo) {
            val ops = split(insns[j].operands)
            if (insns[j].mnemonic.lowercase() == "add" && ops.size >= 3 && ops[0] == brReg) {
                addBaseReg = ops[1]; offReg = stripShift(ops[2]); ext = ops.getOrNull(3); break
            }
        }
        if (addBaseReg == null || offReg == null) return null

        var elemSize = 0; var ldrSigned = false; var idxReg: String? = null; var tblBaseReg: String? = null
        for (j in k - 1 downTo lo) {
            val m = insns[j].mnemonic.lowercase()
            val ops = split(insns[j].operands)
            if (ops.size >= 2 && regCore(ops[0]) == regCore(offReg) && '[' in ops[1] && m.startsWith("ldr")) {
                val parts = (inside(ops[1]) ?: return null).split(",").map { it.trim() }
                tblBaseReg = parts.getOrNull(0) ?: continue
                idxReg = parts.getOrNull(1)?.let { stripShift(it) } ?: continue
                elemSize = when {
                    m.startsWith("ldrb") || m.startsWith("ldrsb") -> 1
                    m.startsWith("ldrh") || m.startsWith("ldrsh") -> 2
                    else -> 4
                }
                ldrSigned = m.startsWith("ldrs")
                break
            }
        }
        if (elemSize == 0 || idxReg == null || tblBaseReg == null) return null
        val tableBase = adrpBase(insns, k, tblBaseReg) ?: return null
        val addBase = adrpBase(insns, k, addBaseReg) ?: return null
        val (signed, shift) = parseExt(ext, ldrSigned)
        val count = boundFromCmp(insns, k, lo, idxReg) ?: return null
        val targets = readRelativeTable(elf, tableBase, addBase, elemSize, signed, shift, count) ?: return null
        return Result(idxReg, targets)
    }

    private fun parseExt(ext: String?, ldrSigned: Boolean): Pair<Boolean, Int> {
        if (ext == null) return ldrSigned to 0
        val op = ext.takeWhile { !it.isWhitespace() }.lowercase()
        val shift = ext.substringAfter("#", "").trim().toIntOrNull() ?: 0
        val signed = when {
            op.startsWith("s") -> true
            op.startsWith("u") -> false
            else -> ldrSigned
        }
        return signed to shift
    }

    private fun resolveX86(insns: List<Insn>, k: Int, elf: ElfFile): Result? {
        val branch = insns[k]
        if (coreMnem(branch.mnemonic) != "jmp") return null
        val op = branch.operands.trim()
        val lo = maxOf(0, k - 16)

        if ('[' in op) {
            val mem = inside(op) ?: return null
            val (baseReg, idxReg, scale, disp) = parseMem(mem)
            if (scale != 4 && scale != 8) return null
            val tableBase = when (baseReg) {
                "rip" -> branch.address + branch.size + (disp ?: 0)
                null -> disp ?: return null
                else -> (leaBase(insns, k, baseReg) ?: return null) + (disp ?: 0)
            }
            val idx = idxReg ?: return null
            fun ptrAt(at: Long): Long? = if (scale == 8) elf.readLong(at) else elf.readInt(at)?.toLong()?.and(0xFFFFFFFFL)
            val count = boundFromCmp(insns, k, lo, idx) ?: scanAbsolute(elf, tableBase, scale)
            if (count <= 1) return null
            val targets = ArrayList<Long>(count)
            for (i in 0 until count) {
                val t = ptrAt(tableBase + i.toLong() * scale) ?: return null
                if (!inExec(elf, t)) return null
                targets.add(t)
            }
            return Result(idx, targets)
        }

        val brReg = op
        if (NUM.matches(brReg)) return null
        var tableReg: String? = null
        for (j in k - 1 downTo lo) {
            val ops = split(insns[j].operands)
            if (insns[j].mnemonic.lowercase() == "add" && ops.size == 2 && ops[0] == brReg) { tableReg = ops[1]; break }
        }
        if (tableReg == null) return null
        var idxReg: String? = null; var memBase: String? = null; var memDisp = 0L
        for (j in k - 1 downTo lo) {
            val m = insns[j].mnemonic.lowercase()
            val ops = split(insns[j].operands)
            if ((m == "movsxd" || m == "mov" || m == "movsx") && ops.size == 2 && ops[0] == brReg && '[' in ops[1]) {
                val (b, idx, _, d) = parseMem(inside(ops[1]) ?: return null)
                memBase = b; memDisp = d ?: 0L
                if (b != null && regCore(b) == regCore(tableReg)) idxReg = idx
                break
            }
        }
        val idx = idxReg ?: return null
        val count = boundFromCmp(insns, k, lo, idx) ?: return null
        val pic = if (memBase != null && regCore(memBase) == regCore(tableReg)) picBase(insns, k, tableReg) else null
        val (tableBase, addBase) = if (pic != null) (pic + memDisp) to pic
            else (leaBase(insns, k, tableReg) ?: return null).let { it to it }
        val targets = readRelativeTable(elf, tableBase, addBase, 4, true, 0, count) ?: return null
        return Result(idx, targets)
    }

    private fun picBase(insns: List<Insn>, before: Int, reg: String): Long? {
        var add = 0L; var addSeen = false
        for (j in before - 1 downTo maxOf(0, before - 24)) {
            val m = insns[j].mnemonic.lowercase()
            val ops = split(insns[j].operands)
            if (m == "add" && ops.size == 2 && regCore(ops[0]) == regCore(reg)) {
                add = parseLong(ops[1]) ?: return null; addSeen = true; continue
            }
            if (m == "pop" && ops.size == 1 && regCore(ops[0]) == regCore(reg) && addSeen) {
                val prev = insns.getOrNull(j - 1) ?: return null
                if (coreMnem(prev.mnemonic) != "call") return null
                val tgt = parseLong(prev.operands.trim()) ?: return null
                if (tgt != prev.address + prev.size) return null
                return tgt + add
            }
            if (ops.isNotEmpty() && regCore(ops[0]) == regCore(reg)) return null
        }
        return null
    }

    private fun readRelativeTable(elf: ElfFile, tableBase: Long, addBase: Long, elemSize: Int, signed: Boolean, shift: Int, count: Int): List<Long>? {
        if (count <= 0 || count > MAX_CASES) return null
        val out = ArrayList<Long>(count)
        for (i in 0 until count) {
            val at = tableBase + i.toLong() * elemSize
            val raw = when (elemSize) {
                4 -> elf.readInt(at)?.let { if (signed) it.toLong() else it.toLong() and 0xFFFFFFFFL }
                2 -> elf.readShort(at)?.let { if (signed) it.toShort().toLong() else it.toLong() }
                1 -> elf.readByte(at)?.let { if (signed) it.toByte().toLong() else it.toLong() }
                else -> null
            } ?: return null
            val target = addBase + (raw shl shift)
            if (!inExec(elf, target)) return null
            out.add(target)
        }
        return out
    }

    private fun scanAbsolute(elf: ElfFile, tableBase: Long, scale: Int = 8): Int {
        var n = 0
        while (n < MAX_CASES) {
            val at = tableBase + n.toLong() * scale
            val t = (if (scale == 8) elf.readLong(at) else elf.readInt(at)?.toLong()?.and(0xFFFFFFFFL)) ?: break
            if (!inExec(elf, t)) break
            n++
        }
        return n
    }

    private fun adrpBase(insns: List<Insn>, before: Int, reg: String): Long? {
        var addImm: Long? = null; var pageReg: String? = null
        for (j in before - 1 downTo maxOf(0, before - 20)) {
            val m = insns[j].mnemonic.lowercase()
            val ops = split(insns[j].operands)
            if (addImm == null && m == "adr" && ops.size >= 2 && ops[0] == reg) return parseLong(ops[1])
            if (addImm == null && m == "add" && ops.size >= 3 && ops[0] == reg) { addImm = parseLong(ops[2]); pageReg = ops[1]; continue }
            if (m == "adrp" && ops.size >= 2 && ops[0] == (pageReg ?: reg)) {
                val page = parseLong(ops[1]) ?: return null
                return page + (addImm ?: 0)
            }
        }
        return null
    }

    private fun leaBase(insns: List<Insn>, before: Int, reg: String): Long? {
        for (j in before - 1 downTo maxOf(0, before - 20)) {
            val m = insns[j].mnemonic.lowercase()
            val ops = split(insns[j].operands)
            if (m == "lea" && ops.size == 2 && ops[0] == reg && "rip" in ops[1]) {
                val mem = inside(ops[1]) ?: return null
                val disp = NUM.find(mem.substringAfter("rip"))?.value?.let { parseLong(it) } ?: return null
                val sign = if (Regex("-\\s*0x|-\\s*\\d").containsMatchIn(mem.substringAfter("rip"))) -1 else 1
                return insns[j].address + insns[j].size + sign * disp
            }
        }
        return null
    }

    private fun boundFromCmp(insns: List<Insn>, before: Int, lo: Int, idxReg: String): Int? {
        var want = regCore(idxReg)
        for (j in before - 1 downTo lo) {
            val m = insns[j].mnemonic.lowercase()
            val ops = split(insns[j].operands)
            if (ops.size == 2 && (m == "mov" || m == "movzx" || m == "movsxd" || m == "movsx") &&
                regCore(ops[0]) == want && '[' !in ops[1] && !NUM.matches(ops[1]) && parseLong(ops[1]) == null
            ) { want = regCore(ops[1]); continue }
            if ((m == "cmp" || m == "subs") && ops.size >= 2 && regCore(ops[0]) == want) {
                val n = hex(ops[1]) ?: parseLong(ops[1])
                if (n != null && n in 0..MAX_CASES) {
                    val guard = insns.getOrNull(j + 1)?.mnemonic?.lowercase() ?: ""
                    val exclusive = guard in setOf("jae", "jnb", "jnc", "jge", "jnl")
                    return (if (exclusive) n else n + 1).toInt()
                }
            }
        }
        return null
    }

    private data class Mem(val base: String?, val index: String?, val scale: Int, val ripDisp: Long?)

    private fun parseMem(inner: String): Mem {
        val terms = inner.replace("-", "+-").split("+").map { it.trim() }.filter { it.isNotEmpty() }
        var base: String? = null; var index: String? = null; var scale = 1; var disp: Long? = null
        for (t in terms) {
            val neg = t.startsWith("-")
            val tt = t.removePrefix("-").trim()
            when {
                tt.contains("*") -> { index = tt.substringBefore("*").trim(); scale = tt.substringAfter("*").trim().toIntOrNull() ?: 1 }
                tt.startsWith("rip") -> base = "rip"
                NUM.matches(tt) -> disp = parseLong(tt)?.let { if (neg) -it else it }
                base == null -> base = tt
            }
        }
        return Mem(base, index, scale, disp)
    }

    private fun inExec(elf: ElfFile, addr: Long): Boolean =
        elf.textSections.any { addr >= it.addr && addr < it.addr + it.size }

    private fun inside(op: String): String? {
        val a = op.indexOf('['); val b = op.lastIndexOf(']')
        return if (a in 0 until b) op.substring(a + 1, b) else null
    }

    private fun stripShift(op: String): String = op.substringBefore(",").substringBefore(" ").trim()

    private fun coreMnem(m: String): String = m.lowercase().substringAfterLast(' ')

    private fun regCore(r: String): String {
        val s = r.lowercase().trim()
        Regex("^r(1[0-5]|[89])[dwb]?$").matchEntire(s)?.let { return "r" + it.groupValues[1] }
        return if (s.length > 1 && s[0] in "xwre") s.drop(1) else s
    }

    private fun split(s: String): List<String> {
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

    private fun hex(s: String): Long? {
        val t = s.trim().removePrefix("#").trim()
        return if (t.startsWith("0x") || t.startsWith("0X")) t.substring(2).toLongOrNull(16) else null
    }

    private fun parseLong(s: String): Long? {
        val t = s.trim().removePrefix("#").trim()
        return if (t.startsWith("0x") || t.startsWith("0X")) t.substring(2).toLongOrNull(16) else t.toLongOrNull()
    }
}
