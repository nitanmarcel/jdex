package io.github.nitanmarcel.jdex.ui

import org.fife.ui.rtextarea.RTextScrollPane
import org.fife.ui.rtextarea.SearchContext
import org.fife.ui.rtextarea.SearchEngine
import java.awt.BorderLayout
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

class SearchableTextPane(val area: CodeTextArea) : JPanel(BorderLayout()) {

    private val findBar = FindBar()

    init {
        add(RTextScrollPane(area), BorderLayout.CENTER)
        add(findBar, BorderLayout.SOUTH)
        val shortcut = Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx
        area.inputMap.put(KeyStroke.getKeyStroke('F'.code, shortcut), "find")
        area.actionMap.put("find", object : AbstractAction() {
            override fun actionPerformed(e: ActionEvent?) = findBar.open()
        })
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
