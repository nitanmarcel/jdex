package io.github.nitanmarcel.jdex.ui

import io.github.nitanmarcel.jdex.project.LineSource
import io.github.nitanmarcel.jdex.project.Symbol
import io.github.nitanmarcel.jdex.project.SyncTarget
import io.github.nitanmarcel.jdex.project.SymbolKind
import io.github.nitanmarcel.jdex.project.Syntax
import org.fife.ui.rsyntaxtextarea.SyntaxScheme
import org.fife.ui.rsyntaxtextarea.Theme
import org.fife.ui.rsyntaxtextarea.TokenMakerFactory
import org.fife.ui.rsyntaxtextarea.TokenTypes
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Dimension
import java.awt.Font
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.RenderingHints
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.awt.event.ActionEvent
import java.awt.event.ComponentAdapter
import java.awt.event.ComponentEvent
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.AbstractAction
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.JScrollBar
import javax.swing.JScrollPane
import javax.swing.JTextField
import javax.swing.KeyStroke
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities
import javax.swing.text.Segment

private data class Pos(val line: Int, val col: Int) : Comparable<Pos> {
    override fun compareTo(other: Pos) = compareValuesBy(this, other, Pos::line, Pos::col)
}

private fun Graphics.enableTextAntialiasing() {
    val g2 = this as Graphics2D
    val hints = Toolkit.getDefaultToolkit().getDesktopProperty("awt.font.desktophints") as? Map<*, *>
    if (hints != null) g2.setRenderingHints(hints) else g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
}

class VirtualCodeView(
    private val source: LineSource,
    syntax: Syntax,
    private val onDecompile: (className: String) -> Unit,
    private val onResource: (type: String, name: String) -> Unit = { _, _ -> },
    private val comments: io.github.nitanmarcel.jdex.project.CommentStore = io.github.nitanmarcel.jdex.project.NoComments,
    private val bookmarks: io.github.nitanmarcel.jdex.project.BookmarkStore = io.github.nitanmarcel.jdex.project.NoBookmarks,
    private val mainActivity: String? = null,
    private val onUsages: (Symbol) -> List<io.github.nitanmarcel.jdex.project.Usage>? = { null },
    private val renames: io.github.nitanmarcel.jdex.project.Renames = io.github.nitanmarcel.jdex.project.Renames(),
    private val onRenamed: () -> Unit = {},
    private val onCaret: (target: SyncTarget) -> Unit = {},
    private val cfgProvider: (rawName: String, shortId: String) -> io.github.nitanmarcel.jdex.project.MethodCfg? = { _, _ -> null },
) : JPanel(BorderLayout()) {

    private val commentCache = HashMap<String, String>()
    private val bookmarkLines = HashSet<Int>()
    private var highlight: String? = null
    private val backStack = ArrayDeque<Int>()
    private val forwardStack = ArrayDeque<Int>()

    private val codeFont = SyntaxThemes.editorFont()
    private val metrics = getFontMetrics(codeFont)
    private val lineHeight = metrics.height
    private val charWidth = metrics.charWidth('m')
    private val ascent = metrics.ascent

    private val tokenMaker = TokenMakerFactory.getDefaultInstance().getTokenMaker(SyntaxStyles.mime(syntax))
    private var scheme: SyntaxScheme = SyntaxScheme(true)
    private var background: Color = Color.WHITE
    private var foreground: Color = Color.BLACK
    private var selectionColor: Color = Color(0xAD, 0xD6, 0xFF)
    private var gutterColor: Color = Color.GRAY
    private var currentLineColor: Color = Color(0, 0, 0, 20)
    private var hoverColor: Color = Color(0, 0, 0, 16)
    private var hoverLine = -1
    private var hoverArrowSrc = -1
    private var hoverArrowTgt = -1
    private var commentColor: Color = Color(0x00, 0x80, 0x00)
    private var highlightColor: Color = Color(0xFF, 0xD5, 0x4F, 110)
    private var bookmarkColor: Color = Color(0x2E, 0x86, 0xDE)
    private var syncColor = Color(0xFF, 0xD5, 0x4F, 60)
    private var syncHighlightLine: Int? = null
    var syncApprox = false

    private var topLine = 0
    private var xOffset = 0
    private var maxWidth = 0
    private var anchor = Pos(0, 0)
    private var caret = Pos(0, 0)

    private val surface = Surface()
    private val gutter = Gutter()
    private val vBar = JScrollBar(JScrollBar.VERTICAL)
    private val hBar = JScrollBar(JScrollBar.HORIZONTAL)
    private var searchDialog: SearchDialog? = null
    private val scrollArea: JPanel
    private var graphView: GraphView? = null

    private val rethemeable = object : SyntaxThemes.Rethemeable {
        override fun retheme() {
            applyTheme()
            surface.repaint()
            gutter.repaint()
        }
    }

    private fun applyTheme() {
        val t = SyntaxThemes.theme()
        scheme = t.scheme
        background = t.bgColor ?: Color.WHITE
        foreground = SyntaxThemes.foregroundOf(t)
        selectionColor = t.selectionBG ?: Color(0xAD, 0xD6, 0xFF)
        gutterColor = Color(foreground.red, foreground.green, foreground.blue, 128)
        currentLineColor = Color(foreground.red, foreground.green, foreground.blue, 20)
        hoverColor = Color(foreground.red, foreground.green, foreground.blue, 45)
        commentColor = scheme.getStyle(TokenTypes.COMMENT_EOL)?.foreground ?: Color(0x00, 0x80, 0x00)
        val accent = UiColors.accent()
        highlightColor = UiColors.alpha(accent, 96)
        syncColor = UiColors.alpha(accent, 56)
        bookmarkColor = UiColors.info()
        surface.background = background
        surface.foreground = foreground
        gutter.background = background
        gutter.foreground = foreground
    }

    init {
        applyTheme()
        SyntaxThemes.register(rethemeable)
        commentCache.putAll(comments.all())
        bookmarkLines.addAll(bookmarks.bookmarks())

        scrollArea = JPanel(BorderLayout()).apply {
            add(JPanel(BorderLayout()).apply { add(gutter, BorderLayout.WEST); add(surface, BorderLayout.CENTER) }, BorderLayout.CENTER)
            add(vBar, BorderLayout.EAST)
            add(hBar, BorderLayout.SOUTH)
        }
        add(scrollArea, BorderLayout.CENTER)

        vBar.unitIncrement = 1
        vBar.addAdjustmentListener { topLine = vBar.value; surface.repaint(); gutter.repaint() }
        hBar.unitIncrement = charWidth
        hBar.addAdjustmentListener { xOffset = hBar.value; surface.repaint() }
        surface.addComponentListener(object : ComponentAdapter() {
            override fun componentResized(e: ComponentEvent) = updateScrollBars()
        })
        installMouse()
        installKeys()
    }

    private fun visibleLines() = (surface.height / lineHeight).coerceAtLeast(1)

    private fun updateScrollBars() {
        val visible = visibleLines()
        vBar.setValues(topLine.coerceIn(0, (source.lineCount - visible).coerceAtLeast(0)), visible, 0, source.lineCount)
        vBar.blockIncrement = visible
        hBar.setValues(xOffset, surface.width, 0, maxWidth.coerceAtLeast(surface.width))
        hBar.blockIncrement = surface.width
    }

    private fun rawLineText(index: Int): String =
        source.lines(index, 1).firstOrNull() ?: ""

    private fun displayLine(index: Int, raw: String): String =
        if (!renames.hasAny()) raw else renames.display(raw, { source.sectionAt(index) }, { methodKeyAt(index) })

    private fun methodKeyAt(index: Int): String? {
        val section = source.sectionAt(index) ?: return null
        val start = source.sectionStart(section) ?: return null
        val from = start
        var shortId: String? = null
        source.lines(from, index - from + 1).forEach {
            val t = it.trimStart()
            when {
                t.startsWith(".method") -> shortId = t.substringAfterLast(' ').takeIf { s -> '(' in s }
                t == ".end method" -> shortId = null
            }
        }
        return shortId?.let { "L${section.replace('.', '/')};->$it" }
    }

    private fun lineText(index: Int): String =
        displayLine(index, rawLineText(index)).replace("\t", "    ")

    private fun selection(): Pair<Pos, Pos>? {
        if (anchor == caret) return null
        return if (anchor <= caret) anchor to caret else caret to anchor
    }

    private fun posAt(x: Int, y: Int): Pos {
        val line = (topLine + y / lineHeight).coerceIn(0, (source.lineCount - 1).coerceAtLeast(0))
        val col = ((x + xOffset + charWidth / 2) / charWidth).coerceIn(0, lineText(line).length)
        return Pos(line, col)
    }

    private fun ensureCaretVisible() {
        val visible = visibleLines()
        when {
            caret.line < topLine -> vBar.value = caret.line
            caret.line >= topLine + visible -> vBar.value = caret.line - visible + 1
        }
    }

    private fun moveCaret(line: Int, col: Int, extend: Boolean) {
        val l = line.coerceIn(0, (source.lineCount - 1).coerceAtLeast(0))
        caret = Pos(l, col.coerceIn(0, lineText(l).length))
        if (!extend) anchor = caret
        if (!extend) highlight = wordAt(lineText(caret.line), caret.col)
        ensureCaretVisible()
        surface.repaint()
        gutter.repaint()
        reportCaret()
    }

    fun goToLine(line: Int, focusSurface: Boolean = true) {
        if (graphView != null) showText()
        if (caret.line != line.coerceIn(0, (source.lineCount - 1).coerceAtLeast(0))) {
            backStack.addLast(caret.line)
            forwardStack.clear()
        }
        moveTo(line, focusSurface)
    }

    private fun moveTo(line: Int, focusSurface: Boolean) {
        val l = line.coerceIn(0, (source.lineCount - 1).coerceAtLeast(0))
        caret = Pos(l, 0)
        anchor = caret
        val visible = visibleLines()
        vBar.value = (l - visible / 3).coerceIn(0, (source.lineCount - visible).coerceAtLeast(0))
        topLine = vBar.value
        surface.repaint()
        gutter.repaint()
        if (focusSurface) surface.requestFocusInWindow()
        reportCaret()
    }

    private var lastSyncLine = -1

    private fun reportCaret() {
        if (caret.line == lastSyncLine) return
        lastSyncLine = caret.line
        targetAt(caret.line)?.let { onCaret(it) }
    }

    private fun targetAt(index: Int): SyncTarget? {
        val t = rawLineText(index).trimStart()
        val section = source.sectionAt(index) ?: return null
        return when {
            t.startsWith("Class:") -> SyncTarget.ClassDecl(section)
            t.startsWith(".method") -> methodIdAt(index)?.let { SyncTarget.MethodDecl(it) }
            t.startsWith(".field") -> SyncTarget.FieldDecl(section, fieldNameOf(t))
            else -> methodIdAt(index)?.let { mid ->
                sourceLineAt(index)?.let { SyncTarget.Line(mid, it) } ?: if (syncApprox) SyncTarget.MethodDecl(mid) else null
            }
        }
    }

    private fun fieldNameOf(trimmedLine: String): String =
        trimmedLine.removePrefix(".field").substringBefore(" : ").trimEnd().substringAfterLast(' ')

    private fun sourceLineAt(index: Int): Int? {
        val start = source.sectionStart(source.sectionAt(index) ?: return null) ?: return null
        val from = start
        var sourceLine: Int? = null
        source.lines(from, index - from + 1).forEach {
            val t = it.trimStart()
            when {
                t.startsWith(".method") -> sourceLine = null
                t.startsWith(".line ") -> sourceLine = t.removePrefix(".line ").trim().toIntOrNull()
            }
        }
        return sourceLine
    }

    private fun methodIdAt(index: Int): String? {
        val section = source.sectionAt(index) ?: return null
        val methodKey = methodKeyAt(index) ?: return null
        return "$section#${methodKey.substringAfter("->")}"
    }

    fun followFromJava(target: SyncTarget) {
        graphView?.let { if (it.followFromJava(target)) return else showText() }
        when (target) {
            is SyncTarget.ClassDecl ->
                source.sectionStart(target.rawName)?.let { showSyncHighlight(it) }
            is SyncTarget.MethodDecl ->
                findInMethod(target.methodId.substringBefore('#'), target.methodId.substringAfter('#'), header = true) { false }
            is SyncTarget.FieldDecl ->
                findInSection(target.rawName) { it.startsWith(".field") && fieldNameOf(it) == target.fieldName }
            is SyncTarget.Line ->
                findInMethod(target.methodId.substringBefore('#'), target.methodId.substringAfter('#'), header = false) {
                    it == ".line ${target.sourceLine}"
                }
        }
    }

    private fun findInSection(rawName: String, match: (String) -> Boolean) {
        val start = source.sectionStart(rawName) ?: return
        background {
            var line = start
            var found: Int? = null
            while (line < source.lineCount) {
                val text = source.lines(line, 1).firstOrNull() ?: break
                if (line > start && text.startsWith("Class:")) break
                if (match(text.trimStart())) { found = line; break }
                line++
            }
            SwingUtilities.invokeLater { showSyncHighlight(found ?: start) }
        }
    }

    private fun findInMethod(rawName: String, shortId: String, header: Boolean, match: (String) -> Boolean) {
        val start = source.sectionStart(rawName) ?: return
        background {
            var line = start
            var inMethod = false
            var methodLine: Int? = null
            var found: Int? = null
            while (line < source.lineCount) {
                val text = source.lines(line, 1).firstOrNull() ?: break
                val t = text.trimStart()
                if (line > start && t.startsWith("Class:")) break
                if (t.startsWith(".method")) {
                    inMethod = t.substringAfterLast(' ') == shortId
                    if (inMethod) { methodLine = line; if (header) { found = line; break } }
                } else if (inMethod) {
                    if (t == ".end method") break
                    if (match(t)) { found = line; break }
                }
                line++
            }
            SwingUtilities.invokeLater { showSyncHighlight(found ?: methodLine ?: start) }
        }
    }

    fun clearSyncHighlight() {
        syncHighlightLine = null
        surface.repaint()
        graphView?.clearSync()
    }

    private fun showSyncHighlight(line: Int) {
        syncHighlightLine = line
        val visible = visibleLines()
        if (line < topLine || line >= topLine + visible) {
            vBar.value = (line - visible / 3).coerceIn(0, (source.lineCount - visible).coerceAtLeast(0))
        }
        surface.repaint()
    }

    private fun back() {
        if (backStack.isNotEmpty()) { forwardStack.addLast(caret.line); moveTo(backStack.removeLast(), true) }
    }

    private fun forward() {
        if (forwardStack.isNotEmpty()) { backStack.addLast(caret.line); moveTo(forwardStack.removeLast(), true) }
    }

    private inner class Surface : JComponent() {
        init {
            isOpaque = true
            isFocusable = true
            focusTraversalKeysEnabled = false
            background = this@VirtualCodeView.background
        }

        override fun paintComponent(g: Graphics) {
            g.color = background
            g.fillRect(0, 0, width, height)
            g.font = codeFont
            g.enableTextAntialiasing()

            val visible = height / lineHeight + 1
            val lines = source.lines(topLine, visible)
            val sel = selection()
            var grew = maxWidth
            val locals = renames.hasLocals()
            var curMethod = if (locals) methodKeyAt(topLine) else null

            for (k in 0 until visible) {
                val index = topLine + k
                if (index >= source.lineCount) break
                val raw = lines.getOrNull(k) ?: ""
                if (locals) {
                    val t = raw.trimStart()
                    when {
                        t.startsWith("Class:") -> curMethod = null
                        t.startsWith(".method") -> curMethod = t.substringAfterLast(' ').takeIf { '(' in it }?.let { "L${(source.sectionAt(index) ?: "").replace('.', '/')};->$it" }
                        t == ".end method" -> curMethod = null
                    }
                }
                val line = (if (!renames.hasAny()) raw else renames.display(raw, { source.sectionAt(index) }, { curMethod })).replace("\t", "    ")
                val y = k * lineHeight

                if ((index == hoverLine || index == hoverArrowSrc || index == hoverArrowTgt) && index != caret.line) {
                    g.color = hoverColor
                    g.fillRect(0, y, width, lineHeight)
                }
                if (index == syncHighlightLine) {
                    g.color = syncColor
                    g.fillRect(0, y, width, lineHeight)
                }
                if (index == caret.line) {
                    g.color = currentLineColor
                    g.fillRect(0, y, width, lineHeight)
                }

                highlight?.let { h ->
                    var idx = line.indexOf(h)
                    while (idx >= 0) {
                        if (isWholeWord(line, idx, h.length)) {
                            g.color = highlightColor
                            g.fillRect(idx * charWidth - xOffset, y, h.length * charWidth, lineHeight)
                        }
                        idx = line.indexOf(h, idx + 1)
                    }
                }

                sel?.let { (s, e) ->
                    if (index in s.line..e.line) {
                        val start = if (index == s.line) s.col else 0
                        val end = if (index == e.line) e.col else line.length
                        g.color = selectionColor
                        g.fillRect(start * charWidth - xOffset, y, (end - start).coerceAtLeast(0) * charWidth, lineHeight)
                    }
                }
                paintTokens(g, line, y + ascent)
                anchorOf(raw, index)?.let { anchor ->
                    commentCache[anchor]?.let { c ->
                        g.color = commentColor
                        g.drawString("    ; $c", line.length * charWidth - xOffset, y + ascent)
                    }
                }
                grew = maxOf(grew, line.length * charWidth)
            }

            if (caret.line in topLine until topLine + visible) {
                g.color = foreground
                val cx = caret.col * charWidth - xOffset
                g.fillRect(cx, (caret.line - topLine) * lineHeight, 2, lineHeight)
            }

            if (grew > maxWidth) {
                maxWidth = grew
                updateScrollBars()
            }
        }

        private fun paintTokens(g: Graphics, line: String, baseline: Int) {
            if (line.isEmpty()) return
            val segment = Segment(line.toCharArray(), 0, line.length)
            var token = tokenMaker.getTokenList(segment, TokenTypes.NULL, 0)
            var col = 0
            while (token != null && token.isPaintable()) {
                val text = token.lexeme
                g.color = io.github.nitanmarcel.jdex.syntax.BytecodeStyle.color(token.type, scheme, foreground, background)
                g.drawString(text, col * charWidth - xOffset, baseline)
                col += text.length
                token = token.nextToken
            }
        }
    }

    private inner class Gutter : JComponent() {
        private val maxLanes = 4
        private val laneStep = 6
        private val arrowStrip = 12 + maxLanes * laneStep
        private val digitsW = getFontMetrics(codeFont).charWidth('0') * (source.lineCount.coerceAtLeast(1).toString().length + 2)
        private val width = digitsW + arrowStrip

        private var hovered = -1

        init {
            isOpaque = true
            val mouse = object : MouseAdapter() {
                override fun mouseClicked(e: MouseEvent) {
                    val idx = arrowAt(e.x, e.y)
                    if (idx >= 0) { goToLine(arrowList[idx][1]); return }
                    val line = topLine + e.y / lineHeight
                    if (line in 0 until source.lineCount) gotoBranchFrom(line)
                }

                override fun mouseMoved(e: MouseEvent) {
                    val idx = arrowAt(e.x, e.y)
                    if (idx != hovered) {
                        hovered = idx
                        if (idx >= 0) { hoverArrowSrc = arrowList[idx][0]; hoverArrowTgt = arrowList[idx][1] }
                        else { hoverArrowSrc = -1; hoverArrowTgt = -1 }
                        repaint(); surface.repaint()
                    }
                    val line = topLine + e.y / lineHeight
                    val branchRow = line in 0 until source.lineCount && (branchTarget(rawLineText(line))?.get(1) ?: -1) >= 0
                    cursor = java.awt.Cursor.getPredefinedCursor(if (idx >= 0 || branchRow) java.awt.Cursor.HAND_CURSOR else java.awt.Cursor.DEFAULT_CURSOR)
                }

                override fun mouseExited(e: MouseEvent) {
                    if (hovered != -1) { hovered = -1; hoverArrowSrc = -1; hoverArrowTgt = -1; repaint(); surface.repaint() }
                }
            }
            addMouseListener(mouse)
            addMouseMotionListener(mouse)
        }

        private fun laneXof(lane: Int) = digitsW + 5 + lane * laneStep

        private fun arrowAt(mx: Int, my: Int): Int {
            val arrows = branchArrows(height / lineHeight + 1)
            for ((idx, a) in arrows.withIndex()) {
                val laneX = laneXof(a[3])
                val srcY = (a[0] - topLine) * lineHeight + lineHeight / 2
                val tgtY = (a[1] - topLine) * lineHeight + lineHeight / 2
                val top = minOf(srcY, tgtY).coerceAtLeast(0)
                val bot = maxOf(srcY, tgtY).coerceAtMost(height)
                if (kotlin.math.abs(mx - laneX) <= 4 && my in (top - 2)..(bot + 2)) return idx
                if (mx in laneX..width && (kotlin.math.abs(my - srcY) <= 3 || kotlin.math.abs(my - tgtY) <= 3)) return idx
            }
            return -1
        }

        override fun getPreferredSize() = Dimension(width, 0)

        override fun paintComponent(g: Graphics) {
            g.color = background
            g.fillRect(0, 0, getWidth(), height)
            g.font = codeFont
            g.enableTextAntialiasing()
            val visible = height / lineHeight + 1
            val fm = g.fontMetrics
            for (k in 0 until visible) {
                val index = topLine + k
                if (index >= source.lineCount) break
                if (index in bookmarkLines) {
                    g.color = bookmarkColor
                    g.fillOval(2, k * lineHeight + (lineHeight - 6) / 2, 6, 6)
                }
                g.color = if (index == caret.line) foreground else gutterColor
                val label = (index + 1).toString()
                g.drawString(label, digitsW - fm.charWidth('0') - fm.stringWidth(label), k * lineHeight + ascent)
            }
            paintBranchArrows(g as Graphics2D, visible)
        }

        private var arrowTop = -2
        private var arrowVisible = -1
        private var arrowList: List<IntArray> = emptyList()

        private fun branchArrows(visible: Int): List<IntArray> {
            if (topLine == arrowTop && visible == arrowVisible) return arrowList
            arrowTop = topLine; arrowVisible = visible
            val pad = 300
            val winStart = (topLine - pad).coerceAtLeast(0)
            val winEnd = (topLine + visible + pad).coerceAtMost(source.lineCount)
            val winLen = winEnd - winStart
            arrowList = if (winLen <= 0) emptyList() else {
                val wlines = source.lines(winStart, winLen)
                val offToAbs = HashMap<Long, Int>()
                val branches = ArrayList<IntArray>()
                var methodId = 0
                for (j in 0 until winLen) {
                    val line = wlines.getOrNull(j) ?: continue
                    if (line.trimStart().startsWith(".method")) methodId++
                    val bd = branchTarget(line) ?: continue
                    offToAbs[(methodId.toLong() shl 20) or bd[0].toLong()] = winStart + j
                    if (bd[1] >= 0) branches.add(intArrayOf(winStart + j, bd[0], bd[1], methodId))
                }
                val viewBot = topLine + visible
                val base = branches.mapNotNull { b ->
                    val tgtAbs = offToAbs[(b[3].toLong() shl 20) or b[2].toLong()] ?: return@mapNotNull null
                    val lo = minOf(b[0], tgtAbs); val hi = maxOf(b[0], tgtAbs)
                    if (hi < topLine || lo > viewBot) null
                    else intArrayOf(b[0], tgtAbs, if (b[2] < b[1]) 1 else 0)
                }.sortedBy { minOf(it[0], it[1]) }
                val laneUntil = IntArray(maxLanes) { Int.MIN_VALUE }
                base.map { a ->
                    val loK = minOf(a[0], a[1]).coerceAtLeast(topLine) - topLine
                    val hiK = (maxOf(a[0], a[1]) - topLine).coerceAtMost(visible)
                    var lane = 0
                    while (lane < maxLanes - 1 && laneUntil[lane] >= loK) lane++
                    laneUntil[lane] = hiK
                    intArrayOf(a[0], a[1], a[2], lane)
                }
            }
            return arrowList
        }

        private fun paintBranchArrows(g: Graphics2D, visible: Int) {
            val arrows = branchArrows(visible)
            if (arrows.isEmpty()) return
            for ((idx, a) in arrows.withIndex()) {
                val srcK = a[0] - topLine; val tgtK = a[1] - topLine; val back = a[2] == 1
                val hot = idx == hovered
                g.color = if (hot) UiColors.accent()
                    else if (back) UiColors.alpha(UiColors.accent(), 170) else UiColors.alpha(UiColors.info(), 150)
                g.stroke = java.awt.BasicStroke(if (hot) 2.4f else 1f)
                val laneX = laneXof(a[3])
                val srcY = srcK * lineHeight + lineHeight / 2
                val tgtY = tgtK * lineHeight + lineHeight / 2
                g.drawLine(laneX, minOf(srcY, tgtY).coerceAtLeast(0), laneX, maxOf(srcY, tgtY).coerceAtMost(height))
                if (srcK in 0 until visible) g.drawLine(width - 1, srcY, laneX, srcY)
                if (tgtK in 0 until visible) {
                    g.drawLine(laneX, tgtY, width - 1, tgtY)
                    g.drawLine(width - 1, tgtY, width - 4, tgtY - 3)
                    g.drawLine(width - 1, tgtY, width - 4, tgtY + 3)
                } else {
                    val edgeY = if (tgtY < 0) 0 else height
                    val dy = if (tgtY < 0) 3 else -3
                    g.drawLine(laneX, edgeY, laneX - 3, edgeY + dy)
                    g.drawLine(laneX, edgeY, laneX + 3, edgeY + dy)
                }
            }
        }
    }

    private fun branchTarget(raw: String): IntArray? {
        val t = raw.trimStart()
        if (t.length < 36 || t[8] != ':' || t[33] != ':') return null
        val codeOff = t.substring(29, 33).toIntOrNull(16) ?: return null
        val body = t.substring(35)
        val mnem = body.takeWhile { it != ' ' }
        val target = if (mnem.startsWith("goto") || mnem.startsWith("if-"))
            (body.trimEnd().substringAfterLast(' ').toIntOrNull(16) ?: -1) else -1
        return intArrayOf(codeOff, target)
    }

    private fun scrollBy(lines: Int) {
        vBar.value = (vBar.value + lines).coerceIn(0, (source.lineCount - visibleLines()).coerceAtLeast(0))
    }

    private val typeDesc = Regex("""L[\w/$]+;""")

    private fun anchorOf(line: String, lineIndex: Int): String? {
        val t = line.trimStart()
        return when {
            t.length >= 9 && t[8] == ':' && t.take(8).all { it.isDigit() || it in 'a'..'f' } -> "i:${t.take(8)}"
            t.startsWith("Class:") -> source.sectionAt(lineIndex)?.let { "c:$it" }
            t.startsWith(".method") -> source.sectionAt(lineIndex)?.let { "m:$it#${t.substringAfterLast(' ')}" }
            else -> null
        }
    }

    fun rerender() {
        surface.repaint()
        gutter.repaint()
        graphView?.refresh()
    }

    private fun renameSymbol() = symbolAtCaret()?.let { renameSymbol(it) }

    private fun renameSymbol(symbol: Symbol) {
        if (!renames.active) return
        val key = symbol.renameKey ?: return
        val original = symbol.simpleName
        val current = renames.nameFor(key) ?: original ?: return
        val input = JOptionPane.showInputDialog(this, "Rename ${symbol.kind.name.lowercase()}:", current) ?: return
        val name = input.trim()
        renames.store.setRename(key, if (name.isEmpty() || name == original) null else name)
        onRenamed()
    }

    private fun addComment() {
        val anchor = anchorOf(rawLineText(caret.line), caret.line) ?: return
        val existing = commentCache[anchor] ?: ""
        val input = JOptionPane.showInputDialog(this, "Comment:", existing) ?: return
        val text = input.trim()
        comments.set(anchor, text.ifEmpty { null })
        if (text.isEmpty()) commentCache.remove(anchor) else commentCache[anchor] = text
        surface.repaint()
    }

    private fun isWordChar(c: Char) = c.isLetterOrDigit() || c == '_' || c == '$'

    private fun wordAt(line: String, col: Int): String? {
        if (col > line.length) return null
        var s = col
        while (s > 0 && isWordChar(line[s - 1])) s--
        var e = col
        while (e < line.length && isWordChar(line[e])) e++
        return if (e > s) line.substring(s, e) else null
    }

    private fun isWholeWord(line: String, start: Int, len: Int): Boolean {
        val before = start == 0 || !isWordChar(line[start - 1])
        val after = start + len >= line.length || !isWordChar(line[start + len])
        return before && after
    }

    private fun toggleBookmark() {
        val line = caret.line
        if (bookmarks.toggle(line)) bookmarkLines.add(line) else bookmarkLines.remove(line)
        gutter.repaint()
    }

    private fun showBookmarks() {
        val lines = bookmarkLines.sorted()
        if (lines.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No bookmarks", "Bookmarks", JOptionPane.INFORMATION_MESSAGE)
            return
        }
        val labels = lines.map { "${it + 1}:  ${source.lines(it, 1).firstOrNull()?.trim() ?: ""}" }
        val list = JList(labels.toTypedArray()).apply { selectionMode = ListSelectionModel.SINGLE_SELECTION; font = codeFont }
        val dialog = JOptionPane(JScrollPane(list).apply { preferredSize = Dimension(640, 320) }, JOptionPane.PLAIN_MESSAGE).createDialog(this, "Bookmarks")
        list.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2 && list.selectedIndex >= 0) { goToLine(lines[list.selectedIndex]); dialog.dispose() }
            }
        })
        dialog.isVisible = true
    }

    private fun copyAddress() {
        val t = lineText(caret.line).trimStart()
        if (t.length < 9 || t[8] != ':') return
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(t.take(8)), null)
    }

    private fun copyReference() {
        val symbol = symbolAtCaret() ?: return
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(symbol.text), null)
    }

    private fun goToMainActivity() {
        val activity = mainActivity ?: return run {
            JOptionPane.showMessageDialog(this, "No launcher activity found", "Go to Main Activity", JOptionPane.INFORMATION_MESSAGE)
        }
        val line = source.sectionStart(activity) ?: return run {
            JOptionPane.showMessageDialog(this, "$activity not found in bytecode", "Go to Main Activity", JOptionPane.INFORMATION_MESSAGE)
        }
        goToLine(line)
    }

    private data class ViewAction(val name: String, val run: () -> Unit)

    private fun viewActions(): List<ViewAction> = listOf(
        ViewAction("Copy") { copySelection() },
        ViewAction("Copy Address") { copyAddress() },
        ViewAction("Copy Reference") { copyReference() },
        ViewAction("Select Method/Class") { selectEnclosing() },
        ViewAction("Copy Method") { copyMethod() },
        ViewAction("Next Method") { gotoMethod(true) },
        ViewAction("Previous Method") { gotoMethod(false) },
        ViewAction("Find…") { openSearch() },
        ViewAction("Find Usages") { findUsages() },
        ViewAction("Go to Definition") { goToDefinition() },
        ViewAction("Go to Address…") { goToAddress() },
        ViewAction("Go to Main Activity") { goToMainActivity() },
        ViewAction("Back") { back() },
        ViewAction("Forward") { forward() },
        ViewAction("Add / Edit Comment") { addComment() },
        ViewAction("Toggle Bookmark") { toggleBookmark() },
        ViewAction("Show Bookmarks…") { showBookmarks() },
        ViewAction("Decompile to Java") { decompile() },
    )

    private fun findAction() {
        val actions = viewActions()
        val dialog = javax.swing.JDialog(javax.swing.SwingUtilities.getWindowAncestor(this), "Find Action", java.awt.Dialog.ModalityType.MODELESS)
        val field = JTextField()
        val model = javax.swing.DefaultListModel<String>()
        val list = JList(model).apply { selectionMode = ListSelectionModel.SINGLE_SELECTION }
        fun refresh() {
            val matches = actions.filter { it.name.contains(field.text, ignoreCase = true) }
            model.clear()
            matches.forEach { model.addElement(it.name) }
            if (model.size() > 0) list.selectedIndex = 0
        }
        fun runSelected() {
            val name = list.selectedValue
            dialog.dispose()
            name?.let { n -> actions.firstOrNull { it.name == n }?.run?.invoke() }
        }
        refresh()
        field.document.addDocumentListener(object : javax.swing.event.DocumentListener {
            override fun insertUpdate(e: javax.swing.event.DocumentEvent) = refresh()
            override fun removeUpdate(e: javax.swing.event.DocumentEvent) = refresh()
            override fun changedUpdate(e: javax.swing.event.DocumentEvent) = refresh()
        })
        field.addActionListener { runSelected() }
        field.addKeyListener(object : java.awt.event.KeyAdapter() {
            override fun keyPressed(e: KeyEvent) {
                when (e.keyCode) {
                    KeyEvent.VK_DOWN -> if (list.selectedIndex < model.size() - 1) list.selectedIndex++
                    KeyEvent.VK_UP -> if (list.selectedIndex > 0) list.selectedIndex--
                    KeyEvent.VK_ESCAPE -> dialog.dispose()
                }
            }
        })
        list.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) { if (e.clickCount == 2) runSelected() }
        })
        dialog.layout = BorderLayout()
        dialog.add(field, BorderLayout.NORTH)
        dialog.add(JScrollPane(list), BorderLayout.CENTER)
        dialog.setSize(380, 340)
        dialog.setLocationRelativeTo(this)
        dialog.isVisible = true
        field.requestFocusInWindow()
    }

    private fun symbolAtCaret(): Symbol? = displaySymbolAtCaret()?.let { renames.toRaw(it) }

    private val registerToken = Regex("[vp]\\d+")

    private fun localSymbolAt(line: String, col: Int): Symbol? {
        val t = line.trimStart()
        if (!(t.length >= 9 && t[8] == ':') && !t.startsWith(".local") && !t.startsWith(".param")) return null
        val word = wordAt(line, col) ?: return null
        val methodKey = methodKeyAt(caret.line) ?: return null
        val register = if (registerToken.matches(word)) word else renames.localRegister(methodKey, word) ?: return null
        return Symbol(SymbolKind.LOCAL, "$methodKey#$register")
    }

    private fun displaySymbolAtCaret(): Symbol? {
        val line = lineText(caret.line)
        Symbol.at(line, caret.col)?.let { return it }
        localSymbolAt(line, caret.col)?.let { return it }

        val trimmed = line.trimStart()
        if (!trimmed.startsWith(".method") && !trimmed.startsWith(".field") && !trimmed.startsWith("Class:")) return null
        val sectionName = source.sectionAt(caret.line) ?: return null
        val header = source.sectionStart(sectionName)?.let { source.lines(it, 1).firstOrNull() } ?: return null
        val classDesc = typeDesc.find(header)?.value ?: return null
        return when {
            trimmed.startsWith("Class:") -> Symbol(SymbolKind.TYPE, classDesc)
            trimmed.startsWith(".method") -> trimmed.substringAfterLast(' ').takeIf { '(' in it }?.let { Symbol(SymbolKind.METHOD, "$classDesc->$it") }
            trimmed.startsWith(".field") -> {
                val type = trimmed.substringAfter(" : ", "").trim()
                if (type.isNotEmpty()) Symbol(SymbolKind.FIELD, "$classDesc->${fieldNameOf(trimmed)}:$type") else null
            }
            else -> null
        }
    }

    private var dragX = 0
    private var dragY = 0
    private val autoScroll = javax.swing.Timer(50) {
        when {
            dragY < 0 -> scrollBy(-2)
            dragY > surface.height -> scrollBy(2)
        }
        when {
            dragX < 0 -> hBar.value -= charWidth * 2
            dragX > surface.width -> hBar.value += charWidth * 2
        }
        caret = posAt(dragX.coerceIn(0, surface.width - 1), dragY.coerceIn(0, surface.height - 1))
        surface.repaint()
    }

    private fun installMouse() {
        val handler = object : MouseAdapter() {
            override fun mousePressed(e: MouseEvent) {
                surface.requestFocusInWindow()
                if (e.isPopupTrigger) { showMenu(e); return }
                caret = posAt(e.x, e.y)
                anchor = caret
                highlight = wordAt(lineText(caret.line), caret.col)
                surface.repaint()
                reportCaret()
                val onBranch = (branchTarget(rawLineText(caret.line))?.get(1) ?: -1) >= 0
                if (onBranch || e.clickCount == 2 || (e.modifiersEx and Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx) != 0) goToDefinition()
            }

            override fun mouseReleased(e: MouseEvent) {
                autoScroll.stop()
                if (e.isPopupTrigger) showMenu(e)
            }

            override fun mouseMoved(e: MouseEvent) {
                val line = topLine + e.y / lineHeight
                val h = if (line in 0 until source.lineCount) line else -1
                if (h != hoverLine) { hoverLine = h; surface.repaint() }
                val branch = h >= 0 && (branchTarget(rawLineText(h))?.get(1) ?: -1) >= 0
                surface.cursor = java.awt.Cursor.getPredefinedCursor(if (branch) java.awt.Cursor.HAND_CURSOR else java.awt.Cursor.TEXT_CURSOR)
            }

            override fun mouseExited(e: MouseEvent) {
                if (hoverLine != -1) { hoverLine = -1; surface.repaint() }
            }

            override fun mouseDragged(e: MouseEvent) {
                dragX = e.x
                dragY = e.y
                caret = posAt(e.x.coerceIn(0, surface.width - 1), e.y.coerceIn(0, surface.height - 1))
                surface.repaint()
                val outside = e.y < 0 || e.y > surface.height || e.x < 0 || e.x > surface.width
                if (outside) autoScroll.start() else autoScroll.stop()
            }
        }
        surface.addMouseListener(handler)
        surface.addMouseMotionListener(handler)
        surface.addMouseWheelListener { scrollBy(it.wheelRotation * 3) }
    }

    private fun installKeys() {
        val shortcut = Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx
        fun bind(key: Int, mod: Int, name: String, action: () -> Unit) {
            surface.inputMap.put(KeyStroke.getKeyStroke(key, mod), name)
            surface.actionMap.put(name, object : AbstractAction() {
                override fun actionPerformed(e: ActionEvent?) = action()
            })
        }
        bind('C'.code, shortcut, "copy") { copySelection() }
        bind('A'.code, shortcut, "selectEnclosing") { selectEnclosing() }
        bind('F'.code, shortcut, "find") { openSearch() }
        bind('G'.code, shortcut, "goToAddress") { goToAddress() }
        bind(KeyEvent.VK_X, 0, "xrefs") { findUsages() }
        bind(KeyEvent.VK_ENTER, 0, "gotoDef") { goToDefinition() }
        bind(KeyEvent.VK_TAB, 0, "decompile") { decompile() }
        bind(KeyEvent.VK_SPACE, 0, "toggleGraph") { toggleGraph() }
        bind(KeyEvent.VK_DOWN, shortcut, "nextMethod") { gotoMethod(true) }
        bind(KeyEvent.VK_UP, shortcut, "prevMethod") { gotoMethod(false) }
        bind('C'.code, shortcut or KeyEvent.SHIFT_DOWN_MASK, "copyMethod") { copyMethod() }
        bind(KeyEvent.VK_SLASH, 0, "comment") { addComment() }
        bind(KeyEvent.VK_N, 0, "rename") { renameSymbol() }
        bind('B'.code, shortcut, "bookmark") { toggleBookmark() }
        bind('A'.code, shortcut or KeyEvent.SHIFT_DOWN_MASK, "findAction") { findAction() }
        bind(KeyEvent.VK_LEFT, KeyEvent.ALT_DOWN_MASK, "back") { back() }
        bind(KeyEvent.VK_RIGHT, KeyEvent.ALT_DOWN_MASK, "forward") { forward() }
        bind(KeyEvent.VK_DOWN, 0, "down") { moveCaret(caret.line + 1, caret.col, false) }
        bind(KeyEvent.VK_UP, 0, "up") { moveCaret(caret.line - 1, caret.col, false) }
        bind(KeyEvent.VK_DOWN, KeyEvent.SHIFT_DOWN_MASK, "downSel") { moveCaret(caret.line + 1, caret.col, true) }
        bind(KeyEvent.VK_UP, KeyEvent.SHIFT_DOWN_MASK, "upSel") { moveCaret(caret.line - 1, caret.col, true) }
        bind(KeyEvent.VK_LEFT, 0, "left") { moveCaret(caret.line, caret.col - 1, false) }
        bind(KeyEvent.VK_RIGHT, 0, "right") { moveCaret(caret.line, caret.col + 1, false) }
        bind(KeyEvent.VK_HOME, 0, "home") { moveCaret(caret.line, 0, false) }
        bind(KeyEvent.VK_END, 0, "end") { moveCaret(caret.line, lineText(caret.line).length, false) }
        bind(KeyEvent.VK_PAGE_DOWN, 0, "pageDown") { moveCaret(caret.line + visibleLines(), caret.col, false) }
        bind(KeyEvent.VK_PAGE_UP, 0, "pageUp") { moveCaret(caret.line - visibleLines(), caret.col, false) }
    }

    private fun menuItem(text: String, key: Int, mod: Int, enabled: Boolean = true, action: () -> Unit) =
        JMenuItem(text).apply {
            accelerator = KeyStroke.getKeyStroke(key, mod)
            isEnabled = enabled
            addActionListener { action() }
        }

    private fun menuItem(text: String, enabled: Boolean = true, action: () -> Unit) =
        JMenuItem(text).apply {
            isEnabled = enabled
            addActionListener { action() }
        }

    private fun showMenu(e: MouseEvent) {
        val symbol = symbolAtCaret()
        val shortcut = Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx
        val onInstruction = lineText(caret.line).trimStart().let { it.length >= 9 && it[8] == ':' }
        JPopupMenu().apply {
            add(menuItem("Copy", 'C'.code, shortcut, enabled = selection() != null) { copySelection() })
            add(menuItem("Copy Address", enabled = onInstruction) { copyAddress() })
            add(menuItem("Copy Reference", enabled = symbol != null) { copyReference() })
            add(menuItem("Select Method/Class", 'A'.code, shortcut) { selectEnclosing() })
            add(menuItem("Copy Method", 'C'.code, shortcut or KeyEvent.SHIFT_DOWN_MASK, enabled = currentMethod() != null) { copyMethod() })
            add(menuItem("Graph View", KeyEvent.VK_SPACE, 0, enabled = currentMethod() != null) { showGraph() })
            addSeparator()
            add(menuItem("Find…", 'F'.code, shortcut) { openSearch() })
            add(menuItem("Find Usages", KeyEvent.VK_X, 0, enabled = symbol != null) { findUsages() })
            add(menuItem("Go to Definition", KeyEvent.VK_ENTER, 0, enabled = symbol != null) { goToDefinition() })
            add(menuItem("Go to Branch Target", enabled = (branchTarget(rawLineText(caret.line))?.get(1) ?: -1) >= 0) { gotoBranchTarget() })
            add(menuItem("Go to Address…", 'G'.code, shortcut) { goToAddress() })
            add(menuItem("Go to Main Activity") { goToMainActivity() })
            addSeparator()
            add(menuItem("Toggle Bookmark", 'B'.code, shortcut) { toggleBookmark() })
            add(menuItem("Show Bookmarks…") { showBookmarks() })
            add(menuItem("Add / Edit Comment", KeyEvent.VK_SLASH, 0, enabled = anchorOf(rawLineText(caret.line), caret.line) != null) { addComment() })
            add(menuItem("Rename…", KeyEvent.VK_N, 0, enabled = symbol?.renameKey != null && renames.active) { renameSymbol() })
            addSeparator()
            add(menuItem("Find Action…", 'A'.code, shortcut or KeyEvent.SHIFT_DOWN_MASK) { findAction() })
            add(menuItem("Decompile to Java", KeyEvent.VK_TAB, 0) { decompile() })
        }.show(surface, e.x, e.y)
    }

    private fun selectEnclosing() {
        val (start, end) = enclosingMethod(caret.line) ?: classBounds(caret.line)
        anchor = Pos(start, 0)
        caret = Pos(end, lineText(end).length)
        ensureCaretVisible()
        surface.repaint()
        gutter.repaint()
    }

    private fun enclosingMethod(line: Int): Pair<Int, Int>? {
        var start = line
        while (start >= 0) {
            val trimmed = (source.lines(start, 1).firstOrNull() ?: "").trimStart()
            if (trimmed.startsWith(".method")) break
            if (trimmed.startsWith("Class:")) return null
            if (trimmed.startsWith(".end method") && start != line) return null
            start--
        }
        if (start < 0) return null
        var end = line.coerceAtLeast(start)
        while (end < source.lineCount) {
            if ((source.lines(end, 1).firstOrNull() ?: "").trimStart().startsWith(".end method")) break
            end++
        }
        return start to end.coerceAtMost((source.lineCount - 1).coerceAtLeast(0))
    }

    private fun classBounds(line: Int): Pair<Int, Int> {
        val start = source.sectionAt(line)?.let { source.sectionStart(it) } ?: 0
        return start to source.sectionEnd(line)
    }

    private fun copySelection() {
        val (s, e) = selection() ?: return
        val lines = source.lines(s.line, e.line - s.line + 1)
        val text = buildString {
            for (li in s.line..e.line) {
                val line = (lines.getOrNull(li - s.line) ?: "").replace("\t", "    ")
                val a = (if (li == s.line) s.col else 0).coerceIn(0, line.length)
                val b = (if (li == e.line) e.col else line.length).coerceIn(0, line.length)
                append(line.substring(a, b))
                if (li != e.line) append('\n')
            }
        }
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(text), null)
    }

    private fun decompile() {
        source.sectionAt(caret.line)?.let(onDecompile)
    }

    private fun gotoMethod(forward: Boolean) {
        val step = if (forward) 1 else -1
        var l = caret.line + step
        while (l in 0 until source.lineCount) {
            val t = rawLineText(l).trimStart()
            if (t.startsWith(".method")) { goToLine(l); return }
            if (t.startsWith("Class:") && !forward) return
            l += step
        }
    }

    private fun copyMethod() {
        val (start, end) = enclosingMethod(caret.line) ?: return
        val text = source.lines(start, end - start + 1).joinToString("\n") { it.replace("\t", "    ") }
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(text), null)
    }

    private fun currentMethod(): Pair<String, String>? {
        val raw = source.sectionAt(caret.line) ?: return null
        val shortId = methodKeyAt(caret.line)?.substringAfter("->") ?: return null
        return raw to shortId
    }

    private fun toggleGraph() {
        if (graphView != null) showText() else showGraph()
    }

    private fun showGraph() {
        if (graphView != null) return
        val (raw, shortId) = currentMethod() ?: return
        val cfg = cfgProvider(raw, shortId) ?: return
        val host = object : GraphHost {
            override val renames get() = this@VirtualCodeView.renames
            override val comments get() = this@VirtualCodeView.comments
            override fun goToDefinition(symbol: Symbol) = this@VirtualCodeView.goToDefinition(symbol)
            override fun findUsages(symbol: Symbol) = this@VirtualCodeView.findUsages(symbol)
            override fun rename(symbol: Symbol) = this@VirtualCodeView.renameSymbol(symbol)
            override fun openResource(type: String, name: String) = onResource(type, name)
            override fun decompile(rawName: String) = onDecompile(rawName)
            override fun reportCaret(target: SyncTarget) = onCaret(target)
            override fun back() = showText()
        }
        val view = GraphView(cfg, raw, host)
        graphView = view
        remove(scrollArea)
        add(view, BorderLayout.CENTER)
        revalidate()
        repaint()
        view.requestFocusInWindow()
    }

    private fun showText() {
        val view = graphView ?: return
        graphView = null
        remove(view)
        add(scrollArea, BorderLayout.CENTER)
        revalidate()
        repaint()
        surface.requestFocusInWindow()
    }

    fun revealOffset(offset: Long) {
        val token = "%08x:".format(offset)
        background {
            val line = source.search(token, 0, true, false)
            SwingUtilities.invokeLater { if (line != null) goToLine(line) }
        }
    }

    private fun goToAddress() {
        val input = JOptionPane.showInputDialog(this, "File offset (hex):", "Go to Address", JOptionPane.PLAIN_MESSAGE) ?: return
        revealOffset(input.trim().removePrefix("0x").toLongOrNull(16) ?: return)
    }

    private fun goToDefinition() {
        if (gotoBranchTarget()) return
        symbolAtCaret()?.let { goToDefinition(it) }
    }

    private fun gotoBranchTarget(): Boolean = gotoBranchFrom(caret.line)

    private fun gotoBranchFrom(line: Int): Boolean {
        val bd = branchTarget(rawLineText(line)) ?: return false
        if (bd[1] < 0) return false
        val (start, end) = enclosingMethod(line) ?: return false
        val lines = source.lines(start, end - start + 1)
        for (i in lines.indices) {
            val b = branchTarget(lines[i]) ?: continue
            if (b[0] == bd[1]) { goToLine(start + i); return true }
        }
        return false
    }

    private fun goToDefinition(symbol: Symbol) {
        if (symbol.kind == SymbolKind.RESOURCE) {
            val type = symbol.resourceType
            val name = symbol.resourceName
            if (type != null && name != null) onResource(type, name)
            return
        }
        val className = symbol.declaringClassName() ?: return
        val sectionStart = source.sectionStart(className)
        if (sectionStart == null) {
            findUsages()
            return
        }
        if (symbol.kind == SymbolKind.TYPE) {
            goToLine(sectionStart)
            return
        }
        val memberName = symbol.member?.substringBefore('(')?.substringBefore(':') ?: return
        background {
            var line = sectionStart + 1
            var found: Int? = null
            while (line < source.lineCount && found == null) {
                val text = source.lines(line, 1).firstOrNull() ?: break
                if (text.startsWith("Class:")) break
                val trimmed = text.trimStart()
                if ((trimmed.startsWith(".method") || trimmed.startsWith(".field")) && text.contains(memberName)) found = line
                line++
            }
            val target = found ?: sectionStart
            SwingUtilities.invokeLater { goToLine(target) }
        }
    }

    private fun findUsages() = symbolAtCaret()?.let { findUsages(it) }

    private fun findUsages(symbol: Symbol) {
        background {
            val semantic = onUsages(symbol)
            if (semantic != null) {
                SwingUtilities.invokeLater { showSemanticUsages(symbol.text, semantic) }
            } else {
                val hits = source.findFrom(symbol.text, 0, 2000, false)
                val entries = hits.map { line -> line to (source.lines(line, 1).firstOrNull()?.trim() ?: "") }
                SwingUtilities.invokeLater { showUsages(symbol.text, entries) }
            }
        }
    }

    private fun showSemanticUsages(query: String, usages: List<io.github.nitanmarcel.jdex.project.Usage>) {
        if (usages.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No usages found for:\n$query", "Find Usages", JOptionPane.INFORMATION_MESSAGE)
            return
        }
        val list = JList(usages.map { it.display }.toTypedArray()).apply { selectionMode = ListSelectionModel.SINGLE_SELECTION; font = codeFont }
        val dialog = JOptionPane(JScrollPane(list).apply { preferredSize = Dimension(700, 320) }, JOptionPane.PLAIN_MESSAGE)
            .createDialog(this, "${usages.size} usages of $query")
        list.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2 && list.selectedIndex >= 0) {
                    val u = usages[list.selectedIndex]
                    when {
                        u.shortId != null -> revealMethod(u.rawName, u.shortId)
                        u.fieldName != null -> revealField(u.rawName, u.fieldName)
                        else -> revealClass(u.rawName)
                    }
                    dialog.dispose()
                }
            }
        })
        dialog.isVisible = true
    }

    private fun showUsages(query: String, entries: List<Pair<Int, String>>) {
        if (entries.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No usages found for:\n$query", "Find Usages", JOptionPane.INFORMATION_MESSAGE)
            return
        }
        val labels = entries.map { (line, text) -> "${line + 1}: $text" }
        val list = JList(labels.toTypedArray()).apply { selectionMode = ListSelectionModel.SINGLE_SELECTION; font = codeFont }
        val dialog = JOptionPane(JScrollPane(list).apply { preferredSize = Dimension(700, 320) }, JOptionPane.PLAIN_MESSAGE)
            .createDialog(this, "${entries.size} usages of $query")
        list.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2 && list.selectedIndex >= 0) {
                    goToLine(entries[list.selectedIndex].first)
                    dialog.dispose()
                }
            }
        })
        dialog.isVisible = true
    }

    private fun background(work: () -> Unit) {
        Thread(work, "bytecode-search").apply { isDaemon = true }.start()
    }

    private fun openSearch() {
        searchDialog?.let { it.toFront(); it.field.requestFocusInWindow(); it.field.selectAll(); return }
        val dialog = SearchDialog(javax.swing.SwingUtilities.getWindowAncestor(this))
        searchDialog = dialog
        dialog.isVisible = true
    }

    fun search(query: String) {
        openSearch()
        searchDialog?.searchFor(query)
    }

    fun revealClass(fullName: String) {
        source.sectionStart(fullName)?.let { goToLine(it) }
    }

    fun revealMethod(fullName: String, shortId: String) {
        val start = source.sectionStart(fullName) ?: return
        background {
            var line = start + 1
            var found: Int? = null
            while (line < source.lineCount && found == null) {
                val text = source.lines(line, 1).firstOrNull() ?: break
                if (text.startsWith("Class:")) break
                if (text.trimStart().startsWith(".method") && text.contains(shortId)) found = line
                line++
            }
            val target = found ?: start
            SwingUtilities.invokeLater { goToLine(target) }
        }
    }

    fun revealField(fullName: String, name: String) {
        val start = source.sectionStart(fullName) ?: return
        background {
            var line = start + 1
            var found: Int? = null
            while (line < source.lineCount && found == null) {
                val text = source.lines(line, 1).firstOrNull() ?: break
                if (text.startsWith("Class:")) break
                if (text.trimStart().startsWith(".field") && text.substringBefore(" : ").trimEnd().endsWith(name)) found = line
                line++
            }
            val target = found ?: start
            SwingUtilities.invokeLater { goToLine(target) }
        }
    }

    private inner class SearchDialog(owner: java.awt.Window?) :
        javax.swing.JDialog(owner, "Find in Bytecode", java.awt.Dialog.ModalityType.MODELESS) {

        private val page = 200
        val field = JTextField(28)
        private val caseCheck = javax.swing.JCheckBox("Case sensitive")
        private val status = JLabel(" ")
        private val model = javax.swing.DefaultListModel<String>()
        private val list = JList(model).apply { font = codeFont; selectionMode = ListSelectionModel.SINGLE_SELECTION }
        private val loadMore = JButton("Load More").apply { isEnabled = false }
        private val loadAll = JButton("Load All").apply { isEnabled = false }
        private val hits = ArrayList<Int>()
        private var complete = true

        init {
            defaultCloseOperation = DISPOSE_ON_CLOSE
            layout = BorderLayout()
            add(JPanel(BorderLayout(6, 0)).apply {
                border = BorderFactory.createEmptyBorder(6, 6, 6, 6)
                add(JLabel("Find:"), BorderLayout.WEST)
                add(field, BorderLayout.CENTER)
                add(JPanel().apply { add(caseCheck); add(JButton("Search").apply { addActionListener { newSearch() } }) }, BorderLayout.EAST)
            }, BorderLayout.NORTH)
            add(JScrollPane(list), BorderLayout.CENTER)
            add(JPanel(BorderLayout()).apply {
                border = BorderFactory.createEmptyBorder(2, 6, 4, 6)
                add(status, BorderLayout.WEST)
                add(JPanel().apply { add(loadMore); add(loadAll) }, BorderLayout.EAST)
            }, BorderLayout.SOUTH)

            field.addActionListener { newSearch() }
            loadMore.addActionListener { if (hits.isNotEmpty()) fetch(hits.last() + 1, page) }
            loadAll.addActionListener { if (hits.isNotEmpty()) fetch(hits.last() + 1, Int.MAX_VALUE) }
            list.addListSelectionListener {
                if (!it.valueIsAdjusting && list.selectedIndex in hits.indices) goToLine(hits[list.selectedIndex], focusSurface = false)
            }
            addWindowListener(object : java.awt.event.WindowAdapter() {
                override fun windowClosed(e: java.awt.event.WindowEvent) { searchDialog = null }
            })
            setSize(680, 440)
            setLocationRelativeTo(this@VirtualCodeView)
        }

        fun searchFor(query: String) {
            field.text = query
            newSearch()
        }

        private fun newSearch() {
            if (field.text.isEmpty()) return
            hits.clear()
            model.clear()
            list.clearSelection()
            fetch(0, page)
        }

        private fun fetch(fromLine: Int, limit: Int) {
            val query = field.text
            val ignoreCase = !caseCheck.isSelected
            status.text = "Searching…"
            loadMore.isEnabled = false
            loadAll.isEnabled = false
            background {
                val found = source.findFrom(query, fromLine, limit, ignoreCase) { i, t -> displayLine(i, t) }
                SwingUtilities.invokeLater {
                    val first = hits.isEmpty()
                    found.forEach { hits.add(it); model.addElement("${it + 1}:  ${displayLine(it, source.lines(it, 1).firstOrNull() ?: "").trim()}") }
                    complete = found.size < limit
                    loadMore.isEnabled = !complete
                    loadAll.isEnabled = !complete
                    status.text = if (hits.isEmpty()) "No matches" else "${hits.size} matches" + if (!complete) " (more available)" else ""
                    if (first && hits.isNotEmpty()) list.selectedIndex = 0
                }
            }
        }
    }
}
