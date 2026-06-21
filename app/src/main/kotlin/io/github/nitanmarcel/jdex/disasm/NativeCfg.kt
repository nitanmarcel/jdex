package io.github.nitanmarcel.jdex.disasm

import io.github.nitanmarcel.jdex.project.CfgBlock
import io.github.nitanmarcel.jdex.project.CfgEdge
import io.github.nitanmarcel.jdex.project.CfgEdgeKind
import io.github.nitanmarcel.jdex.project.CfgInsn
import io.github.nitanmarcel.jdex.project.MethodCfg

object NativeCfg {

    private val RETURN = setOf("ret", "retn", "return", "eret", "retaa", "retab")
    private val UNCOND = setOf("b", "jmp", "j")
    private val INDIRECT = setOf("br", "bx", "brk", "hlt", "ud2")
    private val CALL = setOf("bl", "blx", "call", "jal")
    private val NORETURN = Regex("""\b(abort|exit|_exit|__assert_fail|__assert2|__stack_chk_fail|__cxa_throw|__cxa_rethrow|_Unwind_Resume|_ZSt9terminatev|longjmp|siglongjmp|pthread_exit)\b""")
    private val locRef = Regex("""\bloc_([0-9a-fA-F]+)\b""")

    private class NIns(val addr: Int, val mnem: String, val target: Int?, val text: String, val switchTargets: List<Int>, val noReturn: Boolean)

    fun fromListing(shortId: String, lines: List<String>): MethodCfg? {
        val insns = ArrayList<NIns>()
        for (raw in lines) {
            val t = raw.trimStart()
            if (t.length < 10 || t[8] != ':') continue
            val addr = (t.substring(0, 8).toLongOrNull(16) ?: continue).toInt()
            val rest = t.substring(9).trim()
            val sp = rest.indexOf(' ')
            if (sp < 0) continue
            val afterBytes = rest.substring(sp).trim()
            if (afterBytes.isEmpty()) continue
            val mnem = afterBytes.takeWhile { !it.isWhitespace() }
            if (mnem.startsWith(".")) continue
            val ops = afterBytes.substring(mnem.length).trim()
            val operand = afterBytes.substringBefore("  ; ")
            val target = locRef.find(operand)?.groupValues?.get(1)?.toLongOrNull(16)?.toInt()
            val switchTargets = if ("; switch" in afterBytes)
                locRef.findAll(afterBytes).mapNotNull { it.groupValues[1].toLongOrNull(16)?.toInt() }.distinct().toList()
            else emptyList()
            val noReturn = mnem.lowercase() in CALL && NORETURN.containsMatchIn(operand)
            insns.add(NIns(addr, mnem.lowercase(), target, if (ops.isEmpty()) mnem else "$mnem $ops", switchTargets, noReturn))
        }
        if (insns.isEmpty()) return null

        val addrs = insns.mapTo(HashSet()) { it.addr }
        val leaders = sortedSetOf(insns.first().addr)
        for (i in insns.indices) {
            val ins = insns[i]
            val ends = ins.target != null || ins.mnem in RETURN || ins.mnem in UNCOND || ins.mnem in INDIRECT || ins.switchTargets.isNotEmpty() || ins.noReturn
            if (ins.target != null && ins.target in addrs) leaders.add(ins.target)
            for (st in ins.switchTargets) if (st in addrs) leaders.add(st)
            if (ends) insns.getOrNull(i + 1)?.let { leaders.add(it.addr) }
        }

        val leaderList = leaders.toList()
        val blockByAddr = HashMap<Int, Int>()
        leaderList.forEachIndexed { idx, a -> blockByAddr[a] = idx }
        val blockInsns = Array(leaderList.size) { ArrayList<CfgInsn>() }
        val blockLast = arrayOfNulls<NIns>(leaderList.size)
        var bi = 0
        for (ins in insns) {
            while (bi + 1 < leaderList.size && leaderList[bi + 1] <= ins.addr) bi++
            blockInsns[bi].add(CfgInsn(ins.addr, ins.addr, null, ins.text))
            blockLast[bi] = ins
        }

        val blocks = leaderList.mapIndexed { idx, a -> CfgBlock(idx, a, blockInsns[idx]) }
        val edges = ArrayList<CfgEdge>()
        for (idx in leaderList.indices) {
            val last = blockLast[idx] ?: continue
            val next = idx + 1
            val target = last.target?.let { blockByAddr[it] }
            when {
                last.switchTargets.isNotEmpty() -> for (st in last.switchTargets) blockByAddr[st]?.let { edges.add(CfgEdge(idx, it, CfgEdgeKind.GOTO)) }
                last.noReturn -> {}
                last.mnem in RETURN || last.mnem in INDIRECT -> {}
                last.mnem in UNCOND && target == null -> {}
                target != null && last.mnem in UNCOND -> edges.add(CfgEdge(idx, target, CfgEdgeKind.GOTO))
                target != null -> {
                    edges.add(CfgEdge(idx, target, CfgEdgeKind.COND_TRUE))
                    if (next < blocks.size) edges.add(CfgEdge(idx, next, CfgEdgeKind.COND_FALSE))
                }
                next < blocks.size -> edges.add(CfgEdge(idx, next, CfgEdgeKind.FALLTHROUGH))
            }
        }
        return MethodCfg(shortId, blocks, edges)
    }
}
