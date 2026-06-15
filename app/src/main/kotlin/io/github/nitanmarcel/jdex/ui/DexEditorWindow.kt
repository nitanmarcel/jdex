package io.github.nitanmarcel.jdex.ui

import io.github.nitanmarcel.jdex.project.Dex
import io.github.nitanmarcel.jdex.project.MalformedDex
import org.exbin.auxiliary.binary_data.array.ByteArrayEditableData
import org.exbin.bined.EditMode
import org.exbin.bined.swing.basic.CodeArea
import java.awt.BorderLayout
import java.awt.Color
import java.awt.FlowLayout
import java.awt.Font
import javax.swing.JButton
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.Timer

class DexEditorWindow(
    private val dex: MalformedDex,
    private val onSave: (MalformedDex, edited: ByteArray) -> Unit,
) : JFrame("Edit DEX — ${dex.name}") {

    private val codeArea = CodeArea().apply {
        editMode = EditMode.EXPANDING
        setCodeFont(Font(Font.MONOSPACED, Font.PLAIN, 12))
        setContentData(ByteArrayEditableData(dex.effective))
        resetColors()
    }
    private val status = JLabel()
    private val recheck = Timer(400) { updateStatus() }.apply { isRepeats = false }

    init {
        defaultCloseOperation = DISPOSE_ON_CLOSE
        layout = BorderLayout()
        add(JPanel(FlowLayout(FlowLayout.LEFT, 6, 4)).apply {
            add(JButton("Auto-fix").apply { addActionListener { autoFix() } })
            add(JButton("Save").apply { addActionListener { save() } })
            add(status)
        }, BorderLayout.NORTH)
        add(codeArea, BorderLayout.CENTER)
        codeArea.addKeyListener(object : java.awt.event.KeyAdapter() {
            override fun keyReleased(e: java.awt.event.KeyEvent) = recheck.restart()
        })
        updateStatus()
        setSize(940, 600)
        setLocationRelativeTo(null)
    }

    private fun currentBytes(): ByteArray {
        val data = codeArea.contentData
        val size = data.dataSize.toInt()
        return ByteArray(size).also { if (size > 0) data.copyToArray(0L, it, 0, size) }
    }

    private fun autoFix() {
        runCatching { Dex.repair(currentBytes()) }
            .onSuccess { codeArea.setContentData(ByteArrayEditableData(it)); updateStatus() }
            .onFailure { status.text = "Cannot auto-fix: ${it.message}"; status.foreground = UiColors.error() }
    }

    private fun save() {
        onSave(dex, currentBytes())
        updateStatus()
    }

    private fun updateStatus() {
        val problems = Dex.validate(currentBytes())
        if (problems.isEmpty()) {
            status.text = "✓ Valid DEX"
            status.foreground = UiColors.success()
        } else {
            status.text = "✗ ${problems.joinToString(", ")}"
            status.foreground = UiColors.error()
        }
    }
}
