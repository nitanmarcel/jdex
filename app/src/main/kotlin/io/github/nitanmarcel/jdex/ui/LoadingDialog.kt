package io.github.nitanmarcel.jdex.ui

import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Frame
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JProgressBar

class LoadingDialog(owner: Frame, title: String, private val unit: String = "items", private val onCancel: () -> Unit) :
    JDialog(owner, title, true) {

    private val bar = JProgressBar().apply { isIndeterminate = true }
    private val label = JLabel("Starting…")

    init {
        defaultCloseOperation = DO_NOTHING_ON_CLOSE
        addWindowListener(object : WindowAdapter() {
            override fun windowClosing(e: WindowEvent) = cancel()
        })

        val content = JPanel(BorderLayout(0, 12)).apply {
            border = BorderFactory.createEmptyBorder(16, 16, 16, 16)
            add(label, BorderLayout.NORTH)
            add(bar.apply { preferredSize = Dimension(320, preferredSize.height) }, BorderLayout.CENTER)
            add(JPanel(FlowLayout(FlowLayout.RIGHT, 0, 0)).apply {
                add(JButton("Cancel").apply { addActionListener { cancel() } })
            }, BorderLayout.SOUTH)
        }
        contentPane = content
        pack()
        setLocationRelativeTo(owner)
    }

    fun progress(current: Int, total: Int) {
        bar.isIndeterminate = false
        bar.maximum = total
        bar.value = current
        label.text = "$current / $total $unit"
    }

    private fun cancel() {
        onCancel()
        dispose()
    }
}
