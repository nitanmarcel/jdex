package io.github.nitanmarcel.jdex.ui

import com.formdev.flatlaf.extras.components.FlatTriStateCheckBox
import com.formdev.flatlaf.extras.components.FlatTriStateCheckBox.State
import io.github.nitanmarcel.jdex.project.CodeSync
import io.github.nitanmarcel.jdex.project.SyncTarget
import io.github.nitanmarcel.jdex.project.Syntax
import org.fife.ui.rtextarea.SearchContext
import org.fife.ui.rtextarea.SearchEngine
import org.fife.ui.rtextarea.RTextScrollPane
import java.awt.BorderLayout
import java.awt.Color
import java.awt.FlowLayout
import java.awt.Toolkit
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import javax.swing.AbstractAction
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.KeyStroke

class JavaView(
    code: String,
    private val sync: CodeSync = CodeSync.EMPTY,
    private val onCaret: (target: SyncTarget) -> Unit = {},
    syncInitial: State = State.UNSELECTED,
    private val onSyncToggle: (State) -> Unit = {},
) : JPanel(BorderLayout()) {

    private val area = CodeTextArea(code, Syntax.JAVA)
    private val findBar = FindBar()
    private val syncColor get() = UiColors.alpha(UiColors.accent(), 80)
    private var highlightTag: Any? = null
    private val syncCheck = FlatTriStateCheckBox("Sync caret", syncInitial).apply {
        toolTipText = "Off  ·  checked = exact sync  ·  filled = also snap to nearest line"
    }

    private val syncOn get() = syncCheck.state != State.UNSELECTED
    private val approx get() = syncCheck.state == State.INDETERMINATE

    init {
        add(RTextScrollPane(area), BorderLayout.CENTER)
        add(findBar, BorderLayout.SOUTH)
        add(JPanel(FlowLayout(FlowLayout.LEFT, 4, 1)).apply { add(syncCheck) }, BorderLayout.NORTH)

        val shortcut = Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx
        area.inputMap.put(KeyStroke.getKeyStroke('F'.code, shortcut), "find")
        area.actionMap.put("find", object : AbstractAction() {
            override fun actionPerformed(e: ActionEvent?) = findBar.open()
        })

        syncCheck.addActionListener {
            onSyncToggle(syncCheck.state)
            if (!syncOn) clearHighlight()
        }
        area.addCaretListener { e ->
            if (!syncOn) return@addCaretListener
            val javaLine = runCatching { area.getLineOfOffset(e.dot) + 1 }.getOrNull() ?: return@addCaretListener
            sync.locate(javaLine, approx)?.let { onCaret(it) }
        }
    }

    fun followTo(target: SyncTarget) {
        if (!syncOn) return
        val javaLine = sync.javaLineFor(target, approx) ?: return
        val line = javaLine - 1
        if (line < 0 || line >= area.lineCount) return
        clearHighlight()
        highlightTag = runCatching { area.addLineHighlight(line, syncColor) }.getOrNull()
        runCatching { area.modelToView(area.getLineStartOffset(line))?.let { area.scrollRectToVisible(it) } }
    }

    private fun clearHighlight() {
        highlightTag?.let { runCatching { area.removeLineHighlight(it) } }
        highlightTag = null
    }

    private inner class FindBar : JPanel(BorderLayout()) {
        private val field = JTextField()
        private val status = JLabel(" ")

        init {
            isVisible = false
            border = BorderFactory.createEmptyBorder(2, 4, 2, 4)
            add(JLabel("Find: "), BorderLayout.WEST)
            add(field, BorderLayout.CENTER)
            add(JPanel().apply {
                add(status)
                add(JButton("Prev").apply { addActionListener { find(false) } })
                add(JButton("Next").apply { addActionListener { find(true) } })
                add(JButton("✕").apply { addActionListener { close() } })
            }, BorderLayout.EAST)
            field.addActionListener { find(true) }
            field.inputMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "close")
            field.actionMap.put("close", object : AbstractAction() {
                override fun actionPerformed(e: ActionEvent?) = close()
            })
        }

        fun open() {
            isVisible = true
            revalidate()
            field.requestFocusInWindow()
            field.selectAll()
        }

        private fun close() {
            isVisible = false
            revalidate()
            area.requestFocusInWindow()
        }

        private fun find(forward: Boolean) {
            val query = field.text
            if (query.isEmpty()) return
            val context = SearchContext(query).apply { searchForward = forward; matchCase = false }
            val result = SearchEngine.find(area, context)
            status.text = if (result.wasFound()) " " else "Not found"
        }
    }
}
