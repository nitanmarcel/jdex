package org.example.ui

import io.github.andrewauclair.moderndocking.Dockable
import io.github.andrewauclair.moderndocking.app.Docking
import java.awt.BorderLayout
import java.awt.Font
import java.util.logging.Handler
import java.util.logging.LogRecord
import java.util.logging.Logger
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.SwingUtilities

class LoggerPanel : JPanel(BorderLayout()), Dockable {

    private val area = JTextArea().apply {
        isEditable = false
        font = Font(Font.MONOSPACED, Font.PLAIN, 12)
    }

    init {
        Docking.registerDockable(this)
        add(JScrollPane(area), BorderLayout.CENTER)

        Logger.getLogger("").addHandler(object : Handler() {
            override fun publish(record: LogRecord) {
                val line = "[${record.level}] ${record.message}"
                SwingUtilities.invokeLater {
                    area.append(line + "\n")
                    area.caretPosition = area.document.length
                }
            }

            override fun flush() = Unit

            override fun close() = Unit
        })
    }

    override fun getPersistentID() = "logger"

    override fun getTabText() = "Logger"
}
