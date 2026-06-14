package io.github.nitanmarcel.jdex.ui

import io.github.andrewauclair.moderndocking.Dockable
import io.github.andrewauclair.moderndocking.app.Docking
import io.github.nitanmarcel.jdex.project.ScriptApi
import io.github.nitanmarcel.jdex.project.ScriptEngine
import io.github.nitanmarcel.jdex.syntax.OptimizedPythonTokenMaker
import org.fife.ui.rsyntaxtextarea.AbstractTokenMakerFactory
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea
import org.fife.ui.rsyntaxtextarea.TokenMakerFactory
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Font
import java.awt.event.FocusAdapter
import java.awt.event.FocusEvent
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.io.File
import java.io.OutputStream
import javax.swing.AbstractAction
import javax.swing.BorderFactory
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JFileChooser
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.JToolBar
import javax.swing.KeyStroke
import javax.swing.ListSelectionModel
import javax.swing.Popup
import javax.swing.PopupFactory
import javax.swing.SwingUtilities

class ScriptPanel(private val api: ScriptApi) : JPanel(BorderLayout()), Dockable, AutoCloseable {

    private val mono = Font(Font.MONOSPACED, Font.PLAIN, 12)
    private val console = RSyntaxTextArea().apply {
        font = mono
        focusTraversalKeysEnabled = false
        lineWrap = true
        wrapStyleWord = false
        syntaxEditingStyle = OptimizedPythonTokenMaker.MIME
        highlightCurrentLine = false
        antiAliasingEnabled = true
        isCodeFoldingEnabled = false
    }
    private val buffer = ConsoleDocument(console)
    private val stream = object : OutputStream() {
        override fun write(b: Int) = appendOutput(String(byteArrayOf(b.toByte()), Charsets.UTF_8))
        override fun write(bytes: ByteArray, off: Int, len: Int) = appendOutput(String(bytes, off, len, Charsets.UTF_8))
    }

    private val history = ArrayList<String>()
    private var historyAnchor: String? = null
    private var browseHits: List<Int> = emptyList()
    private var browsePos = 0
    private var hintPopup: Popup? = null
    @Volatile private var engine: ScriptEngine? = null

    private val candidateModel = DefaultListModel<String>()
    private val candidateList = JList(candidateModel).apply {
        font = mono
        isFocusable = false
        selectionMode = ListSelectionModel.SINGLE_SELECTION
    }
    private val docArea = JTextArea(4, 36).apply {
        font = mono
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
    }
    private var popup: Popup? = null
    private var completionValues: List<String> = emptyList()
    private var completionStart = 0
    private var completionLen = 0

    init {
        Docking.registerDockable(this)

        val toolbar = JToolBar().apply {
            isFloatable = false
            add(JButton("Reset").apply { addActionListener { reset() } })
            add(JButton("Clear").apply { addActionListener { clear() } })
            add(JButton("Stub…").apply { addActionListener { exportStub() } })
        }

        bind(KeyEvent.VK_ENTER, "submit") { submit() }
        bind(KeyEvent.VK_UP, "prev") { recall(-1) }
        bind(KeyEvent.VK_DOWN, "next") { recall(1) }
        bind(KeyEvent.VK_TAB, "complete") { complete() }
        bind(KeyEvent.VK_ESCAPE, "dismiss") { hidePopup(); hideHint() }
        bind(KeyEvent.VK_HOME, "home") { console.caretPosition = buffer.inputStart }
        bind(KeyEvent.VK_LEFT, "left") {
            val pos = console.caretPosition
            if (pos > buffer.inputStart) console.caretPosition = pos - 1
        }

        console.addKeyListener(object : KeyAdapter() {
            override fun keyPressed(e: KeyEvent) {
                when (e.keyCode) {
                    KeyEvent.VK_UP, KeyEvent.VK_DOWN, KeyEvent.VK_SHIFT, KeyEvent.VK_CONTROL, KeyEvent.VK_ALT, KeyEvent.VK_META -> {}
                    else -> { historyAnchor = null; hideHint() }
                }
                if (popup == null) return
                when (e.keyCode) {
                    KeyEvent.VK_UP, KeyEvent.VK_DOWN, KeyEvent.VK_TAB, KeyEvent.VK_ENTER, KeyEvent.VK_ESCAPE,
                    KeyEvent.VK_SHIFT, KeyEvent.VK_CONTROL, KeyEvent.VK_ALT, KeyEvent.VK_META -> {}
                    else -> hidePopup()
                }
            }

            override fun keyTyped(e: KeyEvent) {
                when (e.keyChar) {
                    '.' -> SwingUtilities.invokeLater { completeOnDot() }
                    '(' -> SwingUtilities.invokeLater { hintSignature() }
                }
            }
        })
        console.addFocusListener(object : FocusAdapter() {
            override fun focusLost(e: FocusEvent) { if (!e.isTemporary) { hidePopup(); hideHint() } }
        })
        candidateList.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) { if (e.clickCount >= 2) acceptSelection() }
        })
        candidateList.addListSelectionListener { e -> if (!e.valueIsAdjusting) refreshDoc() }

        add(toolbar, BorderLayout.NORTH)
        add(JScrollPane(console), BorderLayout.CENTER)

        buffer.write("jdex Python — `jdex` is bound (try jdex.<Tab>), `jdex.jadx()` for raw access.\n")
        buffer.prompt(PS1)

        background { engine() }
    }

    fun runFile(file: File) = SwingUtilities.invokeLater {
        if (buffer.running) return@invokeLater
        buffer.setInput("")
        buffer.appendOutput("run ${file.name}\n")
        buffer.running = true
        background {
            runCatching { engine().runFile(file) }
                .onFailure { appendOutput("${it.message ?: it::class.java.simpleName}\n") }
            SwingUtilities.invokeLater { buffer.running = false; buffer.prompt(PS1) }
        }
    }

    private fun submit() {
        if (popup != null) { acceptSelection(); return }
        if (buffer.running) return
        val line = buffer.input()
        buffer.write("\n")
        buffer.endInput()
        if (line.isNotBlank()) history.add(line)
        historyAnchor = null
        buffer.running = true
        background {
            val more = runCatching { engine().feed(line) }
                .onFailure { appendOutput("${it.message ?: it::class.java.simpleName}\n") }
                .getOrDefault(false)
            SwingUtilities.invokeLater { buffer.running = false; buffer.prompt(if (more) PS2 else PS1) }
        }
    }

    private fun recall(direction: Int) {
        if (popup != null) { moveSelection(direction); return }
        if (buffer.running || history.isEmpty()) return
        val anchor = historyAnchor ?: buffer.input().also {
            historyAnchor = it
            browseHits = history.indices.filter { i -> history[i].startsWith(it) }
            browsePos = browseHits.size
        }
        if (browseHits.isEmpty()) return
        browsePos = (browsePos + direction).coerceIn(0, browseHits.size)
        buffer.setInput(if (browsePos == browseHits.size) anchor else history[browseHits[browsePos]])
    }

    private fun complete() = runCompletion(autoInsert = true, indentOnEmpty = true, requireIdentStart = false)

    private fun completeOnDot() = runCompletion(autoInsert = false, indentOnEmpty = false, requireIdentStart = true)

    private fun runCompletion(autoInsert: Boolean, indentOnEmpty: Boolean, requireIdentStart: Boolean) {
        if (popup != null) { moveSelection(1); return }
        if (buffer.running) return
        val caret = console.caretPosition.coerceAtLeast(buffer.inputStart)
        val head = console.document.getText(buffer.inputStart, caret - buffer.inputStart)
        val token = head.takeLastWhile { it.isLetterOrDigit() || it == '_' || it == '.' }
        if (token.isEmpty()) { if (indentOnEmpty) buffer.replace(caret, 0, "    "); return }
        if (requireIdentStart && !(token[0].isLetter() || token[0] == '_')) return
        background {
            val candidates = ArrayList<String>()
            var i = 0
            while (i < 500) {
                val c = engine().complete(token, i++) ?: break
                if (c !in candidates) candidates.add(c)
            }
            SwingUtilities.invokeLater { showCompletions(caret, token, candidates, autoInsert) }
        }
    }

    private fun showCompletions(caret: Int, token: String, candidates: List<String>, autoInsert: Boolean) {
        if (candidates.isEmpty()) return
        val start = caret - token.length
        if (autoInsert && candidates.size == 1) { buffer.replace(start, token.length, candidates[0]); return }
        var len = token.length
        if (autoInsert) {
            val prefix = commonPrefix(candidates)
            if (prefix.length > token.length) { buffer.replace(start, token.length, prefix); len = prefix.length }
        }
        completionValues = candidates
        completionStart = start
        completionLen = len
        candidateModel.clear()
        candidates.forEach { candidateModel.addElement(it.substringAfterLast('.')) }
        candidateList.selectedIndex = 0
        candidateList.visibleRowCount = minOf(8, candidates.size)
        showPopupAtCaret()
    }

    private fun showPopupAtCaret() {
        hideHint()
        val rect = runCatching { console.modelToView2D(console.caretPosition) }.getOrNull() ?: return
        val loc = console.locationOnScreen
        val x = loc.x + rect.x.toInt()
        val y = loc.y + rect.y.toInt() + rect.height.toInt()
        docArea.text = ""
        val content = JPanel(BorderLayout()).apply {
            add(JScrollPane(candidateList), BorderLayout.CENTER)
            add(JScrollPane(docArea).apply { border = BorderFactory.createMatteBorder(1, 0, 0, 0, Color.GRAY) }, BorderLayout.SOUTH)
        }
        popup = PopupFactory.getSharedInstance().getPopup(console, content, x, y).also { it.show() }
        refreshDoc()
    }

    private fun refreshDoc() {
        if (popup == null) return
        val idx = candidateList.selectedIndex
        if (idx !in completionValues.indices) { docArea.text = ""; return }
        val expr = completionValues[idx].substringBefore('(').substringBefore('[').trimEnd('.')
        background {
            val text = engine().doc(expr)
            SwingUtilities.invokeLater {
                if (popup != null && candidateList.selectedIndex == idx) {
                    docArea.text = text ?: ""
                    docArea.caretPosition = 0
                }
            }
        }
    }

    private fun moveSelection(delta: Int) {
        val n = candidateModel.size()
        if (n == 0) return
        val idx = ((candidateList.selectedIndex + delta) % n + n) % n
        candidateList.selectedIndex = idx
        candidateList.ensureIndexIsVisible(idx)
    }

    private fun acceptSelection() {
        val idx = candidateList.selectedIndex
        hidePopup()
        if (idx in completionValues.indices) buffer.replace(completionStart, completionLen, completionValues[idx])
    }

    private fun hidePopup() {
        popup?.hide()
        popup = null
    }

    private fun hintSignature() {
        if (buffer.running) return
        val caret = console.caretPosition.coerceAtLeast(buffer.inputStart)
        val head = console.document.getText(buffer.inputStart, caret - buffer.inputStart)
        val token = head.dropLast(1).takeLastWhile { it.isLetterOrDigit() || it == '_' || it == '.' }
        if (token.isEmpty() || !(token[0].isLetter() || token[0] == '_')) return
        background {
            val sig = engine().signature(token)
            SwingUtilities.invokeLater { showHint(sig) }
        }
    }

    private fun showHint(text: String?) {
        hideHint()
        if (text.isNullOrBlank() || popup != null) return
        val label = JLabel(text).apply {
            font = mono
            isOpaque = true
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Color.GRAY),
                BorderFactory.createEmptyBorder(2, 6, 2, 6),
            )
        }
        val rect = runCatching { console.modelToView2D(console.caretPosition) }.getOrNull() ?: return
        val loc = console.locationOnScreen
        hintPopup = PopupFactory.getSharedInstance()
            .getPopup(console, label, loc.x + rect.x.toInt(), loc.y + rect.y.toInt() + rect.height.toInt())
            .also { it.show() }
    }

    private fun hideHint() {
        hintPopup?.hide()
        hintPopup = null
    }

    private fun commonPrefix(values: List<String>): String {
        var prefix = values[0]
        for (v in values) while (!v.startsWith(prefix)) prefix = prefix.dropLast(1)
        return prefix
    }

    private fun reset() {
        if (buffer.running) return
        background {
            engine?.close()
            engine = null
            engine()
            SwingUtilities.invokeLater {
                buffer.setInput("")
                buffer.appendOutput("\n— interpreter reset —\n")
                buffer.prompt(PS1)
            }
        }
    }

    private fun clear() {
        buffer.clear()
        buffer.prompt(PS1)
    }

    private fun exportStub() {
        val chooser = JFileChooser().apply { selectedFile = File("jdex.pyi") }
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return
        runCatching { chooser.selectedFile.writeText(ScriptEngine.STUB) }
            .onSuccess { appendOutput("wrote stub to ${chooser.selectedFile}\n") }
            .onFailure { appendOutput("stub export failed: ${it.message}\n") }
    }

    private fun appendOutput(text: String) = SwingUtilities.invokeLater { buffer.appendOutput(text) }

    private fun background(action: () -> Unit) {
        Thread({
            runCatching { action() }
                .onFailure { appendOutput("${it.message ?: it::class.java.simpleName}\n") }
        }, "jdex-script").apply { isDaemon = true }.start()
    }

    private fun engine(): ScriptEngine {
        engine?.let { return it }
        return synchronized(this) { engine ?: ScriptEngine(api, stream).also { engine = it } }
    }

    private fun bind(keyCode: Int, name: String, action: () -> Unit) {
        console.inputMap.put(KeyStroke.getKeyStroke(keyCode, 0), name)
        console.actionMap.put(name, object : AbstractAction() {
            override fun actionPerformed(e: java.awt.event.ActionEvent) = action()
        })
    }

    override fun close() {
        hideHint()
        hidePopup()
        runCatching { engine?.close() }
        engine = null
    }

    override fun isWrappableInScrollpane() = false

    override fun getPersistentID() = "scripting"

    override fun getTabText() = "Scripting"

    companion object {
        private const val PS1 = ">>> "
        private const val PS2 = "... "

        init {
            (TokenMakerFactory.getDefaultInstance() as AbstractTokenMakerFactory)
                .putMapping(OptimizedPythonTokenMaker.MIME, OptimizedPythonTokenMaker::class.java.name)
        }
    }
}
