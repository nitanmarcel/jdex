package io.github.nitanmarcel.jdex.disasm

object NativeStructurer {

    sealed class Term {
        object Return : Term()
        object Fall : Term()
        class Goto(val target: Long) : Term()
        class Cond(val cond: String, val target: Long) : Term()
        class Switch(val indexReg: String, val cases: List<Long>) : Term()
        class Indirect(val text: String) : Term()
    }

    class SBlock(val start: Long, val stmts: List<String>, val term: Term, val stmtAddrs: List<Long> = emptyList(), val termAddr: Long = start)

    class Structured(val text: String, val lineAddrs: LongArray)

    fun structure(blocks: List<SBlock>): String = structureMapped(blocks).text

    fun structureMapped(blocks: List<SBlock>): Structured {
        if (blocks.isEmpty()) return Structured("", LongArray(0))
        val n = blocks.size
        val idxOf = HashMap<Long, Int>(n * 2)
        blocks.forEachIndexed { i, b -> idxOf[b.start] = i }

        val succ = Array(n) { i ->
            when (val t = blocks[i].term) {
                is Term.Return, is Term.Indirect -> intArrayOf()
                is Term.Fall -> if (i + 1 < n) intArrayOf(i + 1) else intArrayOf()
                is Term.Goto -> idxOf[t.target]?.let { intArrayOf(it) } ?: intArrayOf()
                is Term.Cond -> {
                    val taken = idxOf[t.target]
                    val fall = if (i + 1 < n) i + 1 else null
                    listOfNotNull(taken, fall).toIntArray()
                }
                is Term.Switch -> t.cases.mapNotNull { idxOf[it] }.distinct().toIntArray()
            }
        }
        val preds = Array(n) { ArrayList<Int>() }
        for (i in 0 until n) for (s in succ[i]) preds[s].add(i)

        val targets = HashSet<Long>()
        for (b in blocks) when (val t = b.term) {
            is Term.Goto -> targets.add(t.target)
            is Term.Cond -> targets.add(t.target)
            is Term.Switch -> targets.addAll(t.cases)
            else -> {}
        }

        val dom = forwardDominators(n, succ, preds)
        val isHeader = BooleanArray(n)
        val bodyOf = arrayOfNulls<HashSet<Int>>(n)
        val loopFollow = IntArray(n) { -1 }
        for (a in 0 until n) for (h in succ[a]) if (dominates(h, a, dom)) {
            isHeader[h] = true
            val body = bodyOf[h] ?: HashSet<Int>().also { bodyOf[h] = it; it.add(h) }
            val stack = ArrayDeque<Int>()
            if (a != h && body.add(a)) stack.addLast(a)
            while (stack.isNotEmpty()) {
                val x = stack.removeLast()
                for (p in preds[x]) if (p != h && body.add(p)) stack.addLast(p)
            }
        }
        for (h in 0 until n) {
            val body = bodyOf[h] ?: continue
            val exits = HashMap<Int, Int>()
            for (x in body) for (s in succ[x]) if (s !in body) exits[s] = (exits[s] ?: 0) + 1
            loopFollow[h] = exits.maxByOrNull { it.value }?.key ?: -1
            loopFollow[h].takeIf { it >= 0 }?.let { targets.add(blocks[it].start) }
            targets.add(blocks[h].start)
            for (x in body) for (s in succ[x]) if (s !in body && s != loopFollow[h]) targets.add(blocks[s].start)
        }

        val indeg = IntArray(n)
        for (i in 0 until n) for (s in succ[i]) indeg[s]++
        val ipdom = postDominators(n, succ)

        val sb = StringBuilder()
        val lineAddrs = ArrayList<Long>()
        val visited = BooleanArray(n)
        fun sa(i: Int) = if (i in 0 until n) blocks[i].start else -1L
        fun label(i: Int) = "loc_${blocks[i].start.toString(16)}"
        fun needsLabel(i: Int) = blocks[i].start in targets || indeg[i] > 1
        fun line(indent: Int, s: String, addr: Long = -1L) { repeat(indent) { sb.append("    ") }; sb.append(s).append('\n'); lineAddrs.add(addr) }

        fun jumpKeyword(t: Int, loopH: Int, loopF: Int, body: HashSet<Int>?): String? = when {
            t == loopH -> "continue"
            t == loopF -> "break"
            t in 0 until n && visited[t] -> "goto ${label(t)}"
            body != null && t in 0 until n && t !in body -> "goto ${label(t)}"
            else -> null
        }

        fun emit(from: Int, stop: Int, indent: Int, loopH: Int, loopF: Int, body: HashSet<Int>?) {
            var cur = from
            var depth = 0
            while (cur in 0 until n && cur != stop && !visited[cur] && depth++ < 2 * n + 8) {
                if (isHeader[cur] && cur != loopH) {
                    val h = cur; val f = loopFollow[h]
                    line(indent, "while (true) {", sa(h))
                    emit(h, f, indent + 1, h, f, bodyOf[h])
                    line(indent, "}", sa(h))
                    cur = f
                    if (cur !in 0 until n) return
                    if (cur == loopH) { line(indent, "continue;", sa(cur)); return }
                    if (cur == loopF) { line(indent, "break;", sa(cur)); return }
                    if (cur == stop) return
                    if (visited[cur] || (body != null && cur !in body)) { line(indent, "goto ${label(cur)};", sa(cur)); return }
                    continue
                }
                visited[cur] = true
                val b = blocks[cur]
                val ba = b.start
                val ta = b.termAddr
                if (needsLabel(cur)) line(indent, "${label(cur)}:", ba)
                for ((k, s) in b.stmts.withIndex()) line(indent, "$s;", b.stmtAddrs.getOrElse(k) { ba })

                var next: Int
                when (val t = b.term) {
                    is Term.Return -> { line(indent, "return;", ta); return }
                    is Term.Indirect -> { line(indent, "${t.text};", ta); return }
                    is Term.Switch -> { emitSwitch(::line, ::label, idxOf, t, indent, ta); return }
                    is Term.Fall -> next = cur + 1
                    is Term.Goto -> next = idxOf[t.target] ?: return
                    is Term.Cond -> {
                        val thenB = idxOf[t.target] ?: -1
                        val elseB = if (cur + 1 < n) cur + 1 else -1
                        if (thenB < 0) {
                            line(indent, "if (${t.cond}) goto 0x${t.target.toString(16)};", ta); next = elseB
                        } else {
                            val kw = jumpKeyword(thenB, loopH, loopF, body)
                            val merge = ipdom[cur]
                            if (kw != null) {
                                line(indent, "if (${t.cond}) $kw;", ta); next = elseB
                            } else if (thenB == merge || thenB == stop) {
                                val ekw = if (elseB in 0 until n) jumpKeyword(elseB, loopH, loopF, body) else null
                                when {
                                    elseB < 0 || elseB == thenB || elseB == merge || elseB == stop -> {}
                                    ekw != null -> line(indent, "if (!(${t.cond})) $ekw;", ta)
                                    else -> {
                                        line(indent, "if (!(${t.cond})) {", ta)
                                        emit(elseB, thenB, indent + 1, loopH, loopF, body)
                                        line(indent, "}", ta)
                                    }
                                }
                                next = thenB
                            } else {
                                val stopThen = if (merge in 0 until n) merge else elseB
                                line(indent, "if (${t.cond}) {", ta)
                                emit(thenB, stopThen, indent + 1, loopH, loopF, body)
                                val doElse = merge in 0 until n && elseB >= 0 && elseB != merge &&
                                    !visited[elseB] && jumpKeyword(elseB, loopH, loopF, body) == null &&
                                    (body == null || elseB in body)
                                if (doElse) {
                                    line(indent, "} else {", ta)
                                    emit(elseB, merge, indent + 1, loopH, loopF, body)
                                    line(indent, "}", ta)
                                    next = merge
                                } else {
                                    line(indent, "}", ta)
                                    next = elseB
                                }
                            }
                        }
                    }
                }

                if (next !in 0 until n) return
                if (next == loopH) { line(indent, "continue;", ta); return }
                if (next == loopF) { line(indent, "break;", ta); return }
                if (next == stop) return
                if (visited[next] || (body != null && next !in body)) { line(indent, "goto ${label(next)};", ta); return }
                cur = next
            }
            if (cur in 0 until n && cur != stop && visited[cur]) line(indent, "goto ${label(cur)};", sa(cur))
        }

        emit(0, -1, 1, -1, -1, null)
        for (i in 0 until n) if (!visited[i]) {
            visited[i] = true
            val b = blocks[i]
            val ba = b.start
            val ta = b.termAddr
            line(1, "${label(i)}:", ba)
            for ((k, s) in b.stmts.withIndex()) line(1, "$s;", b.stmtAddrs.getOrElse(k) { ba })
            when (val t = b.term) {
                is Term.Return -> line(1, "return;", ta)
                is Term.Indirect -> line(1, "${t.text};", ta)
                is Term.Switch -> emitSwitch(::line, ::label, idxOf, t, 1, ta)
                is Term.Goto -> idxOf[t.target]?.let { line(1, "goto ${label(it)};", ta) }
                is Term.Cond -> idxOf[t.target]?.let { line(1, "if (${t.cond}) goto ${label(it)};", ta) }
                is Term.Fall -> {}
            }
        }
        return Structured(sb.toString(), lineAddrs.toLongArray())
    }

    private fun emitSwitch(line: (Int, String, Long) -> Unit, label: (Int) -> String, idxOf: Map<Long, Int>, t: Term.Switch, indent: Int, addr: Long) {
        line(indent, "switch (${t.indexReg}) {", addr)
        t.cases.forEachIndexed { i, target ->
            val dst = idxOf[target]?.let { label(it) } ?: "0x${target.toString(16)}"
            line(indent + 1, "case $i: goto $dst;", addr)
        }
        line(indent, "}", addr)
    }

    private fun dominates(b: Int, a: Int, dom: IntArray): Boolean {
        var x = a
        while (true) {
            if (x == b) return true
            val nx = dom[x]
            if (nx == x || nx < 0) return false
            x = nx
        }
    }

    private fun forwardDominators(n: Int, succ: Array<IntArray>, preds: Array<ArrayList<Int>>): IntArray {
        val post = ArrayList<Int>(n)
        val seen = BooleanArray(n)
        val stack = ArrayDeque<IntArray>()
        stack.addLast(intArrayOf(0, 0)); seen[0] = true
        while (stack.isNotEmpty()) {
            val top = stack.last()
            val u = top[0]
            if (top[1] < succ[u].size) {
                val v = succ[u][top[1]++]
                if (!seen[v]) { seen[v] = true; stack.addLast(intArrayOf(v, 0)) }
            } else { post.add(u); stack.removeLast() }
        }
        val order = ArrayList(post.asReversed())
        val rpoIndex = IntArray(n) { -1 }
        order.forEachIndexed { i, node -> rpoIndex[node] = i }

        val idom = IntArray(n) { -1 }
        idom[0] = 0
        fun intersect(a0: Int, b0: Int): Int {
            var a = a0; var b = b0
            while (a != b) {
                while (rpoIndex[a] > rpoIndex[b]) a = idom[a]
                while (rpoIndex[b] > rpoIndex[a]) b = idom[b]
            }
            return a
        }
        var changed = true
        while (changed) {
            changed = false
            for (node in order) {
                if (node == 0) continue
                var newIdom = -1
                for (p in preds[node]) {
                    if (rpoIndex[p] < 0 || idom[p] == -1) continue
                    newIdom = if (newIdom == -1) p else intersect(p, newIdom)
                }
                if (newIdom != -1 && idom[node] != newIdom) { idom[node] = newIdom; changed = true }
            }
        }
        return idom
    }

    private fun postDominators(n: Int, succ: Array<IntArray>): IntArray {
        val exit = n
        val total = n + 1
        val predsRev = Array(total) { ArrayList<Int>() }
        val succRev = Array(total) { ArrayList<Int>() }
        for (i in 0 until n) {
            if (succ[i].isEmpty()) { predsRev[i].add(exit); succRev[exit].add(i) }
            for (s in succ[i]) { predsRev[i].add(s); succRev[s].add(i) }
        }

        val post = ArrayList<Int>(total)
        val seen = BooleanArray(total)
        val stack = ArrayDeque<IntArray>()
        stack.addLast(intArrayOf(exit, 0)); seen[exit] = true
        while (stack.isNotEmpty()) {
            val top = stack.last()
            val u = top[0]
            if (top[1] < succRev[u].size) {
                val v = succRev[u][top[1]++]
                if (!seen[v]) { seen[v] = true; stack.addLast(intArrayOf(v, 0)) }
            } else { post.add(u); stack.removeLast() }
        }
        val order = ArrayList(post.asReversed())

        val rpoIndex = IntArray(total) { -1 }
        order.forEachIndexed { i, node -> rpoIndex[node] = i }

        val idom = IntArray(total) { -1 }
        idom[exit] = exit
        fun intersect(a0: Int, b0: Int): Int {
            var a = a0; var b = b0
            while (a != b) {
                while (rpoIndex[a] > rpoIndex[b]) a = idom[a]
                while (rpoIndex[b] > rpoIndex[a]) b = idom[b]
            }
            return a
        }
        var changed = true
        while (changed) {
            changed = false
            for (node in order) {
                if (node == exit) continue
                var newIdom = -1
                for (p in predsRev[node]) {
                    if (rpoIndex[p] < 0) continue
                    if (idom[p] == -1) continue
                    newIdom = if (newIdom == -1) p else intersect(p, newIdom)
                }
                if (newIdom != -1 && idom[node] != newIdom) { idom[node] = newIdom; changed = true }
            }
        }

        return IntArray(n) { val d = idom[it]; if (d == exit || d == it) -1 else d }
    }
}
