package io.github.nitanmarcel.jdex.ui

import io.github.nitanmarcel.jdex.project.CfgBlock
import io.github.nitanmarcel.jdex.project.CfgEdge
import io.github.nitanmarcel.jdex.project.CfgEdgeKind
import io.github.nitanmarcel.jdex.project.CfgInsn
import io.github.nitanmarcel.jdex.project.CommentStore
import io.github.nitanmarcel.jdex.project.MethodCfg
import io.github.nitanmarcel.jdex.project.Renames
import io.github.nitanmarcel.jdex.project.Symbol
import io.github.nitanmarcel.jdex.project.SymbolKind
import io.github.nitanmarcel.jdex.project.SyncTarget
import io.github.nitanmarcel.jdex.project.Syntax
import org.fife.ui.rsyntaxtextarea.SyntaxScheme
import org.fife.ui.rsyntaxtextarea.TokenMakerFactory
import org.fife.ui.rsyntaxtextarea.TokenTypes
import org.jgrapht.graph.DefaultEdge
import org.jgrapht.graph.DirectedPseudograph
import org.jungrapht.visualization.layout.algorithms.SugiyamaLayoutAlgorithm
import org.jungrapht.visualization.layout.model.LayoutModel
import org.jungrapht.visualization.layout.model.Rectangle
import java.awt.BasicStroke
import java.awt.Color
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.Point
import java.awt.RenderingHints
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.event.MouseWheelEvent
import java.awt.geom.AffineTransform
import java.awt.geom.Path2D
import java.awt.geom.Point2D
import java.awt.geom.Rectangle2D
import javax.swing.text.Segment
import javax.swing.AbstractAction
import javax.swing.JComponent
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JPopupMenu
import javax.swing.KeyStroke

interface GraphHost {
    val renames: Renames
    val comments: CommentStore
    fun goToDefinition(symbol: Symbol)
    fun findUsages(symbol: Symbol)
    fun rename(symbol: Symbol)
    fun openResource(type: String, name: String)
    fun decompile(rawName: String)
    fun reportCaret(target: SyncTarget)
    fun back()
}

class GraphView(
    private val cfg: MethodCfg,
    private val rawName: String,
    private val host: GraphHost,
    syntax: Syntax = Syntax.SMALI,
) : JComponent() {

    private val font = SyntaxThemes.editorFont()
    private val fm = getFontMetrics(font)
    private val lineH = fm.height
    private val cw = fm.charWidth('0')
    private val padX = 10
    private val padY = 6
    private val hGap = 36.0
    private val vGap = 44.0
    private val margin = 24.0

    private val renames get() = host.renames
    private val commentCache = HashMap<String, String>().apply { putAll(host.comments.all()) }
    private val methodKey = "L${rawName.replace('.', '/')};->${cfg.shortId}"
    private val methodId = "$rawName#${cfg.shortId}"
    private val registerToken = Regex("[vp]\\d+")
    private val tokenMaker = TokenMakerFactory.getDefaultInstance().getTokenMaker(SyntaxStyles.mime(syntax))

    private var syncBlock = -1
    private var syncInsn = -1

    private class GLine(val insn: CfgInsn?, val text: String, val comment: String?)
    private class Node(val block: Int, val lines: List<GLine>, var rect: Rectangle2D.Double)
    private class EdgePath(val edge: CfgEdge, val xs: DoubleArray, val ys: DoubleArray, val adx: Double, val ady: Double)

    private val nodes = ArrayList<Node>()
    private val nodeByBlock = HashMap<Int, Node>()
    private val layerOf = HashMap<Int, Int>()
    private val flat = ArrayList<Pair<Int, Int>>()
    private val effLine = HashMap<Int, Int>()
    private val edgePaths = ArrayList<EdgePath>()
    private var contentW = 0.0
    private var contentH = 0.0

    private var selBlock = -1
    private var selInsn = -1
    private var selCol = 0
    private var hoverBlock = -1
    private var hoverInsn = -1
    private var hoveredEdge = -1

    private var scale = 1.0
    private var tx = 0.0
    private var ty = 0.0
    private var fitted = false

    private val rethemeable = object : SyntaxThemes.Rethemeable {
        override fun retheme() = repaint()
    }

    init {
        isFocusable = true
        focusTraversalKeysEnabled = false
        buildLayout()
        cfg.blocks.firstOrNull { it.insns.isNotEmpty() }?.let { selBlock = it.id; selInsn = 0 }
        SyntaxThemes.register(rethemeable)
        installInteraction()
        installKeys()
    }

    private fun renderLine(raw: String): String =
        if (!renames.hasAny()) raw else renames.display(raw, { rawName }, { methodKey })

    private fun buildLines(b: CfgBlock): List<GLine> {
        val header = GLine(null, "B${b.id}  ${"%04x".format(b.startOffset)}", null)
        val insns = b.insns.map { insn ->
            GLine(insn, renderLine("${"%04x".format(insn.offset)}: ${insn.text}"), commentCache["i:%08x".format(insn.addr)])
        }
        return listOf(header) + insns
    }

    private fun lineCols(l: GLine): Int = l.text.length + (l.comment?.let { ("    ; $it").length } ?: 0)

    private fun buildLayout() {
        nodes.clear(); nodeByBlock.clear(); layerOf.clear(); flat.clear(); edgePaths.clear(); effLine.clear()
        var cur: Int? = null
        for (b in cfg.blocks) {
            val lines = buildLines(b)
            val w = (lines.maxOfOrNull { lineCols(it) } ?: 8) * cw + padX * 2.0
            val h = lines.size * lineH + padY * 2.0
            val n = Node(b.id, lines, Rectangle2D.Double(0.0, 0.0, w, h))
            nodes.add(n); nodeByBlock[b.id] = n
            b.insns.forEachIndexed { i, insn ->
                flat.add(b.id to i)
                insn.line?.let { cur = it }
                cur?.let { effLine[insn.offset] = it }
            }
        }
        if (nodes.isEmpty()) return

        val g = DirectedPseudograph<Int, DefaultEdge>(DefaultEdge::class.java)
        cfg.blocks.forEach { g.addVertex(it.id) }
        cfg.edges.asSequence().filter { it.from != it.to }.map { it.from to it.to }.distinct()
            .forEach { (f, t) -> runCatching { g.addEdge(f, t) } }

        val lm = LayoutModel.builder<Int>().graph(g).size(4000, 4000).build()
        val alg = SugiyamaLayoutAlgorithm.edgeAwareBuilder<Int, DefaultEdge>().threaded(false).build()
        alg.setVertexBoundsFunction { id -> nodeByBlock[id]!!.let { Rectangle.of(0.0, 0.0, it.rect.width, it.rect.height) } }
        runCatching { lm.accept(alg) }

        val minNodeH = nodes.minOf { it.rect.height }
        val layers = ArrayList<MutableList<Node>>()
        var lastY = Double.NEGATIVE_INFINITY
        nodes.sortedBy { lm.get(it.block).y }.forEach { n ->
            val y = lm.get(n.block).y
            if (layers.isEmpty() || y - lastY > minNodeH * 0.5) layers.add(mutableListOf(n)) else layers.last().add(n)
            lastY = y
        }

        var y = margin
        layers.forEachIndexed { li, layer ->
            layer.sortBy { lm.get(it.block).x }
            val layerH = layer.maxOf { it.rect.height }
            val totalW = layer.sumOf { it.rect.width } + hGap * (layer.size - 1)
            var x = -totalW / 2
            for (n in layer) {
                n.rect = Rectangle2D.Double(x, y + (layerH - n.rect.height) / 2, n.rect.width, n.rect.height)
                layerOf[n.block] = li
                x += n.rect.width + hGap
            }
            y += layerH + vGap
        }

        val minX = nodes.minOf { it.rect.x }
        nodes.forEach { it.rect.x += margin - minX }
        computeEdgePaths()
        val maxEdgeX = edgePaths.maxOfOrNull { p -> p.xs.maxOrNull() ?: 0.0 } ?: 0.0
        contentW = maxOf(nodes.maxOf { it.rect.maxX }, maxEdgeX) + margin
        contentH = maxOf(nodes.maxOf { it.rect.maxY }, edgePaths.maxOfOrNull { p -> p.ys.maxOrNull() ?: 0.0 } ?: 0.0) + margin
    }

    private fun adjacent(e: CfgEdge): Boolean {
        val la = layerOf[e.from] ?: return false
        val lb = layerOf[e.to] ?: return false
        return e.from != e.to && lb - la == 1
    }

    private fun computeEdgePaths() {
        edgePaths.clear()
        val direct = cfg.edges.filter { adjacent(it) }
        val outOf = direct.groupBy { it.from }.mapValues { (_, es) -> es.sortedBy { nodeByBlock[it.to]?.rect?.centerX ?: 0.0 } }
        val intoOf = direct.groupBy { it.to }.mapValues { (_, es) -> es.sortedBy { nodeByBlock[it.from]?.rect?.centerX ?: 0.0 } }
        fun spread(node: Node, list: List<CfgEdge>?, edge: CfgEdge): Double {
            val n = list?.size ?: 1
            if (n <= 1) return node.rect.centerX
            val i = list!!.indexOf(edge)
            val gap = minOf(24.0, (node.rect.width - 16) / n)
            return node.rect.centerX + (i - (n - 1) / 2.0) * gap
        }
        for (edge in cfg.edges) {
            val a = nodeByBlock[edge.from] ?: continue
            val b = nodeByBlock[edge.to] ?: continue
            if (adjacent(edge)) {
                val outs = outOf[edge.from]
                val x1 = spread(a, outs, edge); val y1 = a.rect.maxY
                val x2 = spread(b, intoOf[edge.to], edge); val y2 = b.rect.y
                val n = outs?.size ?: 1
                val i = outs?.indexOf(edge) ?: 0
                val midY = (y1 + y2) / 2 + (i - (n - 1) / 2.0) * 5
                edgePaths.add(EdgePath(edge, doubleArrayOf(x1, x1, x2, x2), doubleArrayOf(y1, midY, midY, y2), 0.0, 1.0))
            } else {
                edgePaths.add(routeOrthogonal(edge, a, b))
            }
        }
    }

    private fun routeOrthogonal(edge: CfgEdge, a: Node, b: Node): EdgePath {
        val x1 = a.rect.centerX; val y1 = a.rect.maxY
        val x2 = b.rect.centerX; val y2 = b.rect.y
        val bandTop = minOf(a.rect.maxY, b.rect.y) - 4
        val bandBot = maxOf(a.rect.maxY, b.rect.y) + 4
        val occ = nodes.filter { it !== a && it !== b && it.rect.maxY > bandTop && it.rect.y < bandBot }
            .map { (it.rect.x - 10) to (it.rect.maxX + 10) }
        fun free(x: Double) = occ.none { x in it.first..it.second }
        val colX = when {
            free(x1) -> x1
            free(x2) -> x2
            else -> {
                val candidates = occ.flatMap { listOf(it.first - 4, it.second + 4) } + listOf(x1, x2)
                candidates.filter { free(it) }.minByOrNull { minOf(Math.abs(it - x1), Math.abs(it - x2)) }
                    ?.coerceAtLeast(4.0) ?: x1
            }
        }
        if (colX == x1 && colX == x2) {
            return EdgePath(edge, doubleArrayOf(x1, x2), doubleArrayOf(y1, y2), 0.0, 1.0)
        }
        val yA = y1 + 10
        val yB = y2 - 10
        return EdgePath(
            edge,
            doubleArrayOf(x1, x1, colX, colX, x2, x2),
            doubleArrayOf(y1, yA, yA, yB, yB, y2),
            0.0, 1.0,
        )
    }

    fun refresh() {
        val keepBlock = selBlock; val keepInsn = selInsn
        buildLayout()
        selBlock = keepBlock; selInsn = keepInsn
        repaint()
    }

    private fun toContent(p: Point): Point2D.Double =
        Point2D.Double((p.x - tx) / scale, (p.y - ty) / scale)

    private fun nodeAt(c: Point2D.Double): Node? = nodes.firstOrNull { it.rect.contains(c.x, c.y) }

    private fun selectAt(c: Point2D.Double): Boolean {
        val node = nodeAt(c) ?: return false
        val li = ((c.y - (node.rect.y + padY)) / lineH).toInt()
        if (li < 1 || li >= node.lines.size) return false
        selBlock = node.block
        selInsn = li - 1
        selCol = (((c.x - (node.rect.x + padX)) / cw).toInt()).coerceAtLeast(0)
        reportCaret()
        return true
    }

    private fun hoverAt(c: Point2D.Double) {
        val node = nodeAt(c)
        var b = -1; var i = -1
        if (node != null) {
            val li = ((c.y - (node.rect.y + padY)) / lineH).toInt()
            if (li in 1 until node.lines.size) { b = node.block; i = li - 1 }
        }
        if (b != hoverBlock || i != hoverInsn) { hoverBlock = b; hoverInsn = i; repaint() }
    }

    private fun currentInsn(): CfgInsn? = nodeByBlock[selBlock]?.lines?.getOrNull(selInsn + 1)?.insn

    private fun currentText(): String? = nodeByBlock[selBlock]?.lines?.getOrNull(selInsn + 1)?.text

    private fun reportCaret() {
        val insn = currentInsn() ?: return
        host.reportCaret(effLine[insn.offset]?.let { SyncTarget.Line(methodId, it) } ?: SyncTarget.MethodDecl(methodId))
    }

    private fun isWordChar(c: Char) = c.isLetterOrDigit() || c == '_' || c == '$'

    private fun wordAt(line: String, col: Int): String? {
        if (col > line.length) return null
        var s = col; while (s > 0 && isWordChar(line[s - 1])) s--
        var e = col; while (e < line.length && isWordChar(line[e])) e++
        return if (e > s) line.substring(s, e) else null
    }

    private fun localSymbolAt(line: String, col: Int): Symbol? {
        val word = wordAt(line, col) ?: return null
        val register = if (registerToken.matches(word)) word else renames.localRegister(methodKey, word) ?: return null
        return Symbol(SymbolKind.LOCAL, "$methodKey#$register")
    }

    private fun symbolAtSelection(): Symbol? {
        val text = currentText() ?: return null
        Symbol.at(text, selCol)?.let { return renames.toRaw(it) }
        localSymbolAt(text, selCol)?.let { return renames.toRaw(it) }
        return null
    }

    private fun moveSelection(delta: Int) {
        if (flat.isEmpty()) return
        val cur = flat.indexOf(selBlock to selInsn).takeIf { it >= 0 } ?: 0
        val next = (cur + delta).coerceIn(0, flat.size - 1)
        selBlock = flat[next].first; selInsn = flat[next].second; selCol = 0
        ensureSelectionVisible()
        reportCaret()
        repaint()
    }

    private fun ensureSelectionVisible() = ensureVisible(selBlock, selInsn)

    private fun ensureVisible(blockId: Int, insnIdx: Int) {
        val node = nodeByBlock[blockId] ?: return
        val ly = node.rect.y + padY + (insnIdx + 1) * lineH
        val vy = ly * scale + ty
        when {
            vy < 40 -> ty += 40 - vy
            vy > height - 40 -> ty -= vy - (height - 40)
        }
        val vx = node.rect.centerX * scale + tx
        when {
            vx < 40 -> tx += 40 - vx
            vx > width - 40 -> tx -= vx - (width - 40)
        }
    }

    fun followFromJava(target: SyncTarget): Boolean {
        val (blockId, insnIdx) = when (target) {
            is SyncTarget.Line -> if (target.methodId == methodId) locateLine(target.sourceLine) ?: methodStart() else return false
            is SyncTarget.MethodDecl -> if (target.methodId == methodId) methodStart() else return false
            else -> return false
        } ?: return true
        syncBlock = blockId; syncInsn = insnIdx
        ensureVisible(blockId, insnIdx)
        repaint()
        return true
    }

    fun clearSync() {
        syncBlock = -1; syncInsn = -1
        repaint()
    }

    private fun methodStart(): Pair<Int, Int>? = cfg.blocks.firstOrNull { it.insns.isNotEmpty() }?.let { it.id to 0 }

    private fun locateLine(sourceLine: Int): Pair<Int, Int>? {
        for (b in cfg.blocks) b.insns.forEachIndexed { i, insn ->
            if (insn.line == sourceLine) return b.id to i
        }
        return null
    }

    private fun goToDefinition() {
        if (gotoBranchTarget()) return
        val sym = symbolAtSelection() ?: return
        if (sym.kind == SymbolKind.RESOURCE) sym.resourceType?.let { t -> sym.resourceName?.let { n -> host.openResource(t, n) } }
        else host.goToDefinition(sym)
    }

    private fun gotoBranchTarget(): Boolean {
        val insn = currentInsn() ?: return false
        val mnem = insn.text.substringBefore(' ')
        if (!mnem.startsWith("goto") && !mnem.startsWith("if-")) return false
        val tgt = insn.text.trimEnd().substringAfterLast(' ').toIntOrNull(16) ?: return false
        val block = cfg.blocks.firstOrNull { it.startOffset == tgt } ?: return false
        selBlock = block.id; selInsn = 0; selCol = 0
        ensureVisible(selBlock, selInsn)
        reportCaret()
        repaint()
        return true
    }

    private fun findUsages() = symbolAtSelection()?.let { host.findUsages(it) }

    private fun renameSymbol() = symbolAtSelection()?.let { if (it.renameKey != null && renames.active) host.rename(it) }

    private fun addComment() {
        val insn = currentInsn() ?: return
        val anchor = "i:%08x".format(insn.addr)
        val input = JOptionPane.showInputDialog(this, "Comment:", commentCache[anchor] ?: "") ?: return
        val text = input.trim()
        host.comments.set(anchor, text.ifEmpty { null })
        if (text.isEmpty()) commentCache.remove(anchor) else commentCache[anchor] = text
        refresh()
    }

    private fun copyAddress() {
        val insn = currentInsn() ?: return
        java.awt.Toolkit.getDefaultToolkit().systemClipboard
            .setContents(java.awt.datatransfer.StringSelection("%08x".format(insn.addr)), null)
    }

    private fun copyReference() {
        val sym = symbolAtSelection() ?: return
        java.awt.Toolkit.getDefaultToolkit().systemClipboard.setContents(java.awt.datatransfer.StringSelection(sym.text), null)
    }

    private fun installInteraction() {
        val mouse = object : MouseAdapter() {
            private var last: Point? = null
            override fun mousePressed(e: MouseEvent) {
                last = e.point
                requestFocusInWindow()
                val c = toContent(e.point)
                if (e.isPopupTrigger) { selectAt(c); menu(e); return }
                if (selectAt(c)) {
                    repaint()
                    val onBranch = currentInsn()?.text?.substringBefore(' ')?.let { it.startsWith("goto") || it.startsWith("if-") } == true
                    if (onBranch || (e.modifiersEx and java.awt.Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx) != 0) goToDefinition()
                    return
                }
                val ei = edgeAt(c)
                if (ei >= 0) followEdge(ei)
            }
            override fun mouseReleased(e: MouseEvent) { if (e.isPopupTrigger) menu(e) }
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2 && !e.isPopupTrigger) { selectAt(toContent(e.point)); goToDefinition() }
            }
            override fun mouseDragged(e: MouseEvent) {
                last?.let { tx += (e.x - it.x).toDouble(); ty += (e.y - it.y).toDouble(); last = e.point; repaint() }
            }
            override fun mouseMoved(e: MouseEvent) {
                val c = toContent(e.point)
                hoverAt(c)
                val ei = edgeAt(c)
                if (ei != hoveredEdge) { hoveredEdge = ei; repaint() }
                val insn = nodeByBlock[hoverBlock]?.lines?.getOrNull(hoverInsn + 1)?.insn
                val branch = insn?.text?.substringBefore(' ')?.let { it.startsWith("goto") || it.startsWith("if-") } == true
                cursor = java.awt.Cursor.getPredefinedCursor(if (ei >= 0 || branch) java.awt.Cursor.HAND_CURSOR else java.awt.Cursor.DEFAULT_CURSOR)
            }
            override fun mouseExited(e: MouseEvent) {
                if (hoverBlock != -1 || hoveredEdge != -1) { hoverBlock = -1; hoverInsn = -1; hoveredEdge = -1; repaint() }
            }
        }
        addMouseListener(mouse)
        addMouseMotionListener(mouse)
        addMouseWheelListener { e: MouseWheelEvent ->
            val factor = if (e.wheelRotation < 0) 1.1 else 1 / 1.1
            val ns = (scale * factor).coerceIn(0.2, 3.0)
            tx = e.x - (e.x - tx) * (ns / scale)
            ty = e.y - (e.y - ty) * (ns / scale)
            scale = ns
            repaint()
        }
    }

    private fun installKeys() {
        fun bind(key: Int, name: String, action: () -> Unit) {
            getInputMap(WHEN_FOCUSED).put(KeyStroke.getKeyStroke(key, 0), name)
            actionMap.put(name, object : AbstractAction() { override fun actionPerformed(e: ActionEvent?) = action() })
        }
        bind(KeyEvent.VK_SPACE, "back") { host.back() }
        bind(KeyEvent.VK_ESCAPE, "back") { host.back() }
        bind(KeyEvent.VK_ENTER, "gotoDef") { goToDefinition() }
        bind(KeyEvent.VK_X, "xrefs") { findUsages() }
        bind(KeyEvent.VK_N, "rename") { renameSymbol() }
        bind(KeyEvent.VK_SLASH, "comment") { addComment() }
        bind(KeyEvent.VK_TAB, "decompile") { host.decompile(rawName) }
        bind(KeyEvent.VK_DOWN, "down") { moveSelection(1) }
        bind(KeyEvent.VK_UP, "up") { moveSelection(-1) }
    }

    private fun menu(e: MouseEvent) {
        val sym = symbolAtSelection()
        val onInsn = currentInsn() != null
        JPopupMenu().apply {
            add(item("Copy Reference", sym != null) { copyReference() })
            add(item("Copy Address", onInsn) { copyAddress() })
            addSeparator()
            add(item("Find Usages", sym != null) { findUsages() })
            add(item("Go to Definition", sym != null) { goToDefinition() })
            add(item("Go to Branch Target", currentInsn()?.text?.substringBefore(' ')?.let { it.startsWith("goto") || it.startsWith("if-") } == true) { gotoBranchTarget() })
            add(item("Rename…", sym?.renameKey != null && renames.active) { renameSymbol() })
            add(item("Add / Edit Comment", onInsn) { addComment() })
            addSeparator()
            add(item("Decompile to Java", true) { host.decompile(rawName) })
            add(item("Text View", true) { host.back() })
        }.show(this, e.x, e.y)
    }

    private fun item(text: String, enabled: Boolean, action: () -> Unit) =
        JMenuItem(text).apply { isEnabled = enabled; addActionListener { action() } }

    private fun fit() {
        if (fitted || width == 0 || contentW == 0.0) return
        fitted = true
        scale = minOf(width / contentW, height / contentH, 1.0).coerceAtLeast(0.2)
        tx = (width - contentW * scale) / 2
        ty = 16.0
    }

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        val theme = SyntaxThemes.theme()
        val bg = theme.bgColor ?: Color.WHITE
        val fg = SyntaxThemes.foregroundOf(theme)
        g2.color = bg
        g2.fillRect(0, 0, width, height)
        fit()
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
        g2.setRenderingHint(RenderingHints.KEY_FRACTIONALMETRICS, RenderingHints.VALUE_FRACTIONALMETRICS_ON)
        g2.transform(AffineTransform().apply { translate(tx, ty); scale(scale, scale) })
        paintEdges(g2)
        paintNodes(g2, bg, fg, theme.scheme)
        g2.dispose()
    }

    private fun edgeColor(kind: CfgEdgeKind): Color = when (kind) {
        CfgEdgeKind.COND_TRUE -> UiColors.success()
        CfgEdgeKind.COND_FALSE -> UiColors.error()
        CfgEdgeKind.GOTO, CfgEdgeKind.FALLTHROUGH -> UiColors.info()
        CfgEdgeKind.SWITCH_CASE -> UiColors.accent()
        CfgEdgeKind.EXCEPTION -> Color(0xC0, 0x80, 0x30)
    }

    private fun paintEdges(g2: Graphics2D) {
        for ((idx, p) in edgePaths.withIndex()) {
            val hot = idx == hoveredEdge
            g2.color = edgeColor(p.edge.kind)
            val w = if (hot) 3.0f else 1.6f
            g2.stroke = if (p.edge.kind == CfgEdgeKind.EXCEPTION)
                BasicStroke(w, BasicStroke.CAP_BUTT, BasicStroke.JOIN_ROUND, 1f, floatArrayOf(4f, 4f), 0f)
            else BasicStroke(w, BasicStroke.CAP_BUTT, BasicStroke.JOIN_ROUND)
            polyline(g2, p.xs, p.ys)
            arrow(g2, p.xs.last(), p.ys.last(), p.adx, p.ady)
        }
    }

    private fun edgeAt(c: Point2D.Double): Int {
        val tol = 6.0 / scale
        var best = -1; var bestD = tol
        for ((idx, p) in edgePaths.withIndex()) {
            var d = Double.MAX_VALUE
            for (i in 0 until p.xs.size - 1) d = minOf(d, distToSeg(c.x, c.y, p.xs[i], p.ys[i], p.xs[i + 1], p.ys[i + 1]))
            if (d < bestD) { bestD = d; best = idx }
        }
        return best
    }

    private fun distToSeg(px: Double, py: Double, x1: Double, y1: Double, x2: Double, y2: Double): Double {
        val dx = x2 - x1; val dy = y2 - y1
        val len2 = dx * dx + dy * dy
        if (len2 == 0.0) return Math.hypot(px - x1, py - y1)
        val t = (((px - x1) * dx + (py - y1) * dy) / len2).coerceIn(0.0, 1.0)
        return Math.hypot(px - (x1 + t * dx), py - (y1 + t * dy))
    }

    private fun followEdge(idx: Int) {
        val tgt = edgePaths[idx].edge.to
        if (nodeByBlock[tgt] == null) return
        selBlock = tgt; selInsn = 0; selCol = 0
        ensureVisible(selBlock, selInsn)
        reportCaret()
        repaint()
    }

    private fun polyline(g2: Graphics2D, xs: DoubleArray, ys: DoubleArray) {
        for (i in 0 until xs.size - 1) g2.drawLine(xs[i].toInt(), ys[i].toInt(), xs[i + 1].toInt(), ys[i + 1].toInt())
    }

    private fun arrow(g2: Graphics2D, x: Double, y: Double, dx: Double, dy: Double) {
        val ang = Math.atan2(dy, dx)
        val len = 9.0
        val spread = 0.45
        val head = Path2D.Double()
        head.moveTo(x, y)
        head.lineTo(x - len * Math.cos(ang - spread), y - len * Math.sin(ang - spread))
        head.lineTo(x - len * Math.cos(ang + spread), y - len * Math.sin(ang + spread))
        head.closePath()
        val stroke = g2.stroke
        g2.stroke = BasicStroke(1f)
        g2.fill(head)
        g2.stroke = stroke
    }

    private fun paintNodes(g2: Graphics2D, bg: Color, fg: Color, scheme: SyntaxScheme) {
        val blockBg = blend(bg, fg, 0.07)
        val border = UiColors.border()
        val headerFg = blend(bg, fg, 0.6)
        val commentFg = blend(bg, UiColors.success(), 0.85)
        val selBg = UiColors.alpha(UiColors.accent(), 64)
        val syncBg = UiColors.alpha(UiColors.accent(), 40)
        val hoverBg = blend(bg, fg, 0.16)
        g2.font = font
        for (n in nodes) {
            val r = n.rect
            g2.color = blockBg; g2.fillRoundRect(r.x.toInt(), r.y.toInt(), r.width.toInt(), r.height.toInt(), 8, 8)
            g2.color = border; g2.drawRoundRect(r.x.toInt(), r.y.toInt(), r.width.toInt(), r.height.toInt(), 8, 8)
            val x = (r.x + padX)
            n.lines.forEachIndexed { i, line ->
                val top = (r.y + padY + i * lineH)
                if (n.block == hoverBlock && i == hoverInsn + 1) { g2.color = hoverBg; g2.fillRect((r.x + 1).toInt(), top.toInt(), (r.width - 2).toInt(), lineH) }
                if (n.block == syncBlock && i == syncInsn + 1) { g2.color = syncBg; g2.fillRect((r.x + 1).toInt(), top.toInt(), (r.width - 2).toInt(), lineH) }
                if (n.block == selBlock && i == selInsn + 1) { g2.color = selBg; g2.fillRect((r.x + 1).toInt(), top.toInt(), (r.width - 2).toInt(), lineH) }
                val baseline = (top + fm.ascent).toFloat()
                if (i == 0) {
                    g2.color = headerFg
                    g2.drawString(line.text, x.toFloat(), baseline)
                } else {
                    paintTokens(g2, line.text, x.toFloat(), baseline, scheme, fg, bg)
                    line.comment?.let {
                        g2.color = commentFg
                        g2.drawString("    ; $it", (x + line.text.length * cw).toFloat(), baseline)
                    }
                }
            }
        }
    }

    private fun paintTokens(g2: Graphics2D, text: String, x: Float, baseline: Float, scheme: SyntaxScheme, fallback: Color, bg: Color) {
        if (text.isEmpty()) return
        val segment = Segment(text.toCharArray(), 0, text.length)
        var token = tokenMaker.getTokenList(segment, TokenTypes.NULL, 0)
        var col = 0
        while (token != null && token.isPaintable()) {
            val lexeme = token.lexeme
            g2.color = io.github.nitanmarcel.jdex.syntax.BytecodeStyle.color(token.type, scheme, fallback, bg)
            g2.drawString(lexeme, x + col * cw, baseline)
            col += lexeme.length
            token = token.nextToken
        }
    }

    private fun blend(a: Color, b: Color, t: Double): Color = Color(
        (a.red + (b.red - a.red) * t).toInt().coerceIn(0, 255),
        (a.green + (b.green - a.green) * t).toInt().coerceIn(0, 255),
        (a.blue + (b.blue - a.blue) * t).toInt().coerceIn(0, 255),
    )
}
