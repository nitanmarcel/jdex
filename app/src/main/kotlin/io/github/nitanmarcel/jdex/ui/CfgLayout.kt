package io.github.nitanmarcel.jdex.ui

import java.awt.geom.Rectangle2D

class CfgLayout(
    private val hGap: Double = 36.0,
    private val vGap: Double = 20.0,
    private val laneGap: Double = 12.0,
    private val margin: Double = 24.0,
    private val portPitch: Double = 16.0,
    private val edgeVGap: Double = 12.0,
) {
    class Route(val xs: DoubleArray, val ys: DoubleArray)
    class Result(val rects: Map<Int, Rectangle2D.Double>, val routes: List<Route>, val width: Double, val height: Double)

    private class Lane(val row: Int, var x: Double)

    fun layout(sizes: Map<Int, DoubleArray>, edges: List<IntArray>, entry: Int): Result {
        if (sizes.isEmpty()) return Result(emptyMap(), edges.map { Route(DoubleArray(0), DoubleArray(0)) }, 0.0, 0.0)

        val out = HashMap<Int, MutableList<Int>>()
        sizes.keys.forEach { out[it] = ArrayList() }
        edges.forEachIndexed { i, e -> if (e[0] != e[1]) out[e[0]]?.add(i) }

        val backEdge = BooleanArray(edges.size)
        run {
            val state = HashMap<Int, Int>()
            val order = ArrayList<Int>().apply { add(entry); addAll(sizes.keys.filter { it != entry }) }
            for (root in order) {
                if (state[root] != null) continue
                val stack = ArrayDeque<IntArray>()
                stack.addLast(intArrayOf(root, 0))
                state[root] = 1
                while (stack.isNotEmpty()) {
                    val top = stack.last()
                    val node = top[0]
                    val outs = out[node]!!
                    if (top[1] < outs.size) {
                        val ei = outs[top[1]]; top[1]++
                        val w = edges[ei][1]
                        when (state[w]) {
                            1 -> backEdge[ei] = true
                            null -> { state[w] = 1; stack.addLast(intArrayOf(w, 0)) }
                        }
                    } else {
                        state[node] = 2; stack.removeLast()
                    }
                }
            }
        }

        val dagInto = HashMap<Int, MutableList<Int>>()
        sizes.keys.forEach { dagInto[it] = ArrayList() }
        val indeg = HashMap<Int, Int>()
        sizes.keys.forEach { indeg[it] = 0 }
        edges.forEachIndexed { i, e ->
            if (e[0] != e[1] && !backEdge[i]) { dagInto[e[1]]!!.add(e[0]); indeg[e[1]] = indeg[e[1]]!! + 1 }
        }
        val topo = ArrayList<Int>()
        run {
            val q = ArrayDeque<Int>()
            sizes.keys.filter { indeg[it] == 0 }.sortedBy { if (it == entry) -1 else it }.forEach { q.addLast(it) }
            val deg = HashMap(indeg)
            while (q.isNotEmpty()) {
                val n = q.removeFirst(); topo.add(n)
                for (ei in out[n]!!) {
                    if (backEdge[ei]) continue
                    val w = edges[ei][1]
                    deg[w] = deg[w]!! - 1
                    if (deg[w] == 0) q.addLast(w)
                }
            }
            sizes.keys.forEach { if (it !in topo) topo.add(it) }
        }

        val row = HashMap<Int, Int>()
        sizes.keys.forEach { row[it] = 0 }
        for (n in topo) {
            val r = (dagInto[n] ?: emptyList()).maxOfOrNull { (row[it] ?: 0) + 1 } ?: 0
            row[n] = maxOf(row[n] ?: 0, r)
        }
        val maxRow = row.values.maxOrNull() ?: 0

        val slotW = HashMap<Int, Double>()
        val slotRow = HashMap<Int, Int>()
        sizes.forEach { (id, wh) -> slotW[id] = wh[0]; slotRow[id] = row[id]!! }

        var vid = -1
        val chains = ArrayList<List<Int>>(edges.size)
        val above = HashMap<Int, MutableList<Int>>()
        val below = HashMap<Int, MutableList<Int>>()
        fun link(a: Int, b: Int) {
            val ra = slotRow[a]!!; val rb = slotRow[b]!!
            if (ra == rb) return
            val (hi, lo) = if (ra < rb) a to b else b to a
            below.getOrPut(hi) { ArrayList() }.add(lo)
            above.getOrPut(lo) { ArrayList() }.add(hi)
        }
        for (e in edges) {
            if (e[0] == e[1] || e[0] !in sizes || e[1] !in sizes) { chains.add(listOf(e[0])); continue }
            val ru = row[e[0]]!!; val rv = row[e[1]]!!
            val chain = ArrayList<Int>()
            chain.add(e[0])
            val step = if (rv > ru) 1 else -1
            var r = ru + step
            while (r != rv) {
                val v = vid--
                slotW[v] = 1.0; slotRow[v] = r
                chain.add(v); r += step
            }
            chain.add(e[1])
            for (k in 0 until chain.size - 1) link(chain[k], chain[k + 1])
            chains.add(chain)
        }

        val rowSlots = HashMap<Int, MutableList<Int>>()
        slotRow.forEach { (id, r) -> rowSlots.getOrPut(r) { ArrayList() }.add(id) }
        for (r in 0..maxRow) rowSlots.getOrPut(r) { ArrayList() }
        rowSlots.values.forEach { it.sortBy { id -> if (id >= 0) id else Int.MAX_VALUE + id } }

        val posIn = HashMap<Int, Int>()
        fun reindex() { rowSlots.values.forEach { l -> l.forEachIndexed { i, id -> posIn[id] = i } } }
        reindex()
        fun bary(id: Int, side: HashMap<Int, MutableList<Int>>): Double {
            val nb = side[id] ?: return posIn[id]!!.toDouble()
            if (nb.isEmpty()) return posIn[id]!!.toDouble()
            return nb.map { posIn[it]!! }.sorted().let { it[it.size / 2].toDouble() }
        }
        repeat(6) {
            for (r in 1..maxRow) { rowSlots[r]!!.sortBy { bary(it, above) }; reindex() }
            for (r in maxRow - 1 downTo 0) { rowSlots[r]!!.sortBy { bary(it, below) }; reindex() }
        }
        reindex()

        fun sep(a: Int, b: Int): Double {
            val gap = if (a >= 0 && b >= 0) hGap else laneGap
            return slotW[a]!! / 2 + slotW[b]!! / 2 + gap
        }
        val x = HashMap<Int, Double>()
        for (r in 0..maxRow) {
            val ord = rowSlots[r]!!
            var cx = 0.0
            ord.forEachIndexed { i, id ->
                cx = if (i == 0) slotW[id]!! / 2 else cx + sep(ord[i - 1], id)
                x[id] = cx
            }
        }
        val desired = HashMap<Int, Double>()
        fun place(r: Int) {
            val ord = rowSlots[r]!!
            for (i in ord.indices) {
                val lo = if (i > 0) x[ord[i - 1]]!! + sep(ord[i - 1], ord[i]) else Double.NEGATIVE_INFINITY
                x[ord[i]] = maxOf(desired[ord[i]]!!, lo)
            }
            for (i in ord.indices.reversed()) {
                val hi = if (i < ord.size - 1) x[ord[i + 1]]!! - sep(ord[i], ord[i + 1]) else Double.POSITIVE_INFINITY
                val lo = if (i > 0) x[ord[i - 1]]!! + sep(ord[i - 1], ord[i]) else Double.NEGATIVE_INFINITY
                x[ord[i]] = maxOf(lo, minOf(desired[ord[i]]!!, hi))
            }
        }
        fun computeDesired() {
            for (id in slotW.keys) {
                val nb = ArrayList<Double>()
                above[id]?.forEach { nb.add(x[it]!!) }
                below[id]?.forEach { nb.add(x[it]!!) }
                desired[id] = if (nb.isEmpty()) x[id]!! else nb.sorted().let { (it[(it.size - 1) / 2] + it[it.size / 2]) / 2 }
            }
        }
        repeat(16) {
            computeDesired(); for (r in 1..maxRow) place(r)
            computeDesired(); for (r in maxRow - 1 downTo 0) place(r)
        }

        val nodeW = HashMap<Int, Double>(); val nodeCx = HashMap<Int, Double>()
        sizes.forEach { (id, wh) -> nodeW[id] = wh[0]; nodeCx[id] = x[id]!! }

        val laneChains = ArrayList<List<Lane>?>(edges.size)
        for (ci in chains.indices) {
            val chain = chains[ci]
            if (chain.size < 2) { laneChains.add(null); continue }
            laneChains.add(chain.map { Lane(slotRow[it]!!, x[it]!!) })
        }

        val exitOf = HashMap<Int, MutableList<Int>>()
        val entryOf = HashMap<Int, MutableList<Int>>()
        for (ci in laneChains.indices) {
            val lanes = laneChains[ci] ?: continue
            exitOf.getOrPut(edges[ci][0]) { ArrayList() }.add(ci)
            entryOf.getOrPut(edges[ci][1]) { ArrayList() }.add(ci)
        }
        fun spreadPorts(byNode: HashMap<Int, MutableList<Int>>, source: Boolean) {
            for ((node, list) in byNode) {
                val cx = nodeCx[node] ?: continue
                val w = nodeW[node]!!
                val down = HashMap<Int, Boolean>()
                list.forEach { ci -> val l = laneChains[ci]!!; down[ci] = l.first().row < l.last().row }
                for (side in booleanArrayOf(true, false)) {
                    val group = list.filter { (if (source) down[it]!! else !down[it]!!) == side }
                        .sortedBy { ci -> val l = laneChains[ci]!!; if (source) l[1].x else l[l.size - 2].x }
                    val k = group.size
                    if (k == 0) continue
                    val pitch = if (k <= 1) 0.0 else minOf(portPitch, (w - 12) / (k - 1))
                    val start = cx - pitch * (k - 1) / 2
                    group.forEachIndexed { i, ci ->
                        val px = start + i * pitch
                        val l = laneChains[ci]!!
                        if (source) l.first().x = px else l.last().x = px
                    }
                }
            }
        }
        spreadPorts(exitOf, true)
        spreadPorts(entryOf, false)

        class Seg(val edgeIdx: Int, val left: Double, val right: Double)
        val channelSegs = HashMap<Int, MutableList<Seg>>()
        for (ci in laneChains.indices) {
            val lanes = laneChains[ci] ?: continue
            for (k in 0 until lanes.size - 1) {
                val a = lanes[k]; val b = lanes[k + 1]
                val c = minOf(a.row, b.row)
                channelSegs.getOrPut(c) { ArrayList() }.add(Seg(ci, minOf(a.x, b.x), maxOf(a.x, b.x)))
            }
        }
        val trackOf = HashMap<Long, Int>()
        val channelTracks = HashMap<Int, Int>()
        channelSegs.forEach { (c, segs) ->
            segs.sortBy { it.left }
            val trackRight = ArrayList<Double>()
            for (s in segs) {
                var t = trackRight.indexOfFirst { it <= s.left - laneGap }
                if (t < 0) { t = trackRight.size; trackRight.add(0.0) }
                trackRight[t] = s.right
                trackOf[c.toLong() shl 32 or (s.edgeIdx.toLong() and 0xffffffffL)] = t
            }
            channelTracks[c] = trackRight.size
        }

        val rowH = DoubleArray(maxRow + 1)
        sizes.forEach { (id, wh) -> rowH[row[id]!!] = maxOf(rowH[row[id]!!], wh[1]) }
        val channelH = DoubleArray(maxRow + 1)
        for (c in 0..maxRow) channelH[c] = maxOf(vGap, ((channelTracks[c] ?: 0) + 1) * edgeVGap)
        val rowTop = DoubleArray(maxRow + 1)
        run { var y = margin; for (r in 0..maxRow) { rowTop[r] = y; y += rowH[r]; if (r < maxRow) y += channelH[r] } }
        fun channelTop(c: Int) = rowTop[c] + rowH[c]

        val rects = HashMap<Int, Rectangle2D.Double>()
        sizes.forEach { (id, wh) ->
            val r = row[id]!!
            rects[id] = Rectangle2D.Double(nodeCx[id]!! - wh[0] / 2, rowTop[r] + (rowH[r] - wh[1]) / 2, wh[0], wh[1])
        }

        val laneY = HashMap<Long, Double>()
        channelSegs.forEach { (c, segs) ->
            for (s in segs) {
                val key = c.toLong() shl 32 or (s.edgeIdx.toLong() and 0xffffffffL)
                laneY[key] = channelTop(c) + (trackOf[key]!! + 1) * edgeVGap
            }
        }

        val routes = ArrayList<Route>(edges.size)
        for (ci in edges.indices) {
            val e = edges[ci]
            if (e[0] == e[1] || e[0] !in rects || e[1] !in rects) {
                val r = rects[e[0]]
                routes.add(if (r == null) Route(DoubleArray(0), DoubleArray(0)) else selfLoop(r))
                continue
            }
            val lanes = laneChains[ci]!!
            val ra = rects[e[0]]!!; val rb = rects[e[1]]!!
            val down = lanes.first().row < lanes.last().row
            val xs = ArrayList<Double>(); val ys = ArrayList<Double>()
            xs.add(lanes.first().x); ys.add(if (down) ra.maxY else ra.y)
            for (k in 0 until lanes.size - 1) {
                val a = lanes[k]; val b = lanes[k + 1]
                val c = minOf(a.row, b.row)
                val y = laneY[c.toLong() shl 32 or (ci.toLong() and 0xffffffffL)]!!
                xs.add(a.x); ys.add(y)
                xs.add(b.x); ys.add(y)
            }
            xs.add(lanes.last().x); ys.add(if (down) rb.y else rb.maxY)
            routes.add(Route(xs.toDoubleArray(), ys.toDoubleArray()))
        }

        val minX = rects.values.minOf { it.x }.let { mx -> minOf(mx, routes.filter { it.xs.isNotEmpty() }.minOfOrNull { it.xs.min() } ?: mx) }
        val dx = margin - minX
        rects.values.forEach { it.x += dx }
        routes.forEach { r -> for (i in r.xs.indices) r.xs[i] += dx }
        val width = (rects.values.maxOfOrNull { it.maxX } ?: 0.0).let { w ->
            maxOf(w, routes.filter { it.xs.isNotEmpty() }.maxOfOrNull { it.xs.max() } ?: 0.0)
        } + margin
        val height = maxOf(
            rowTop[maxRow] + rowH[maxRow],
            routes.filter { it.ys.isNotEmpty() }.maxOfOrNull { it.ys.max() } ?: 0.0,
        ) + margin

        return Result(rects, routes, width, height)
    }

    private fun selfLoop(r: Rectangle2D.Double): Route {
        val x0 = r.maxX; val top = r.centerY - 8; val bot = r.centerY + 8
        return Route(doubleArrayOf(x0, x0 + 24, x0 + 24, x0), doubleArrayOf(top, top, bot, bot))
    }
}
