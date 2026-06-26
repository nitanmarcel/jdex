package io.github.nitanmarcel.jdex.ui

import java.awt.BorderLayout
import java.awt.Dialog
import java.awt.FlowLayout
import java.awt.Window
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JDialog
import javax.swing.JPanel
import javax.swing.JTextArea
import javax.swing.UIManager

object RootDebugDialog {

    data class Choice(val proceed: Boolean, val dontShowAgain: Boolean)

    fun show(owner: Window?, pkg: String): Choice {
        val dialog = JDialog(owner, "Non-debuggable app", Dialog.ModalityType.APPLICATION_MODAL)
        var proceed = false

        val text = JTextArea(
            "$pkg is marked non-debuggable.\n\n" +
                "On a normal device you can't attach a debugger to it — you need a rooted device or an emulator. " +
                "Otherwise, regenerate and install a debuggable build of the APK.\n\n" +
                "Press OK to try debugging it on this device."
        ).apply {
            isEditable = false
            lineWrap = true
            wrapStyleWord = true
            isOpaque = false
            columns = 42
            font = UIManager.getFont("Label.font")
            border = BorderFactory.createEmptyBorder(10, 12, 4, 12)
        }

        val dontShow = JCheckBox("Do not show this again")
        val ok = JButton("OK").apply { addActionListener { proceed = true; dialog.dispose() } }
        val cancel = JButton("Cancel").apply { addActionListener { dialog.dispose() } }

        dialog.contentPane.add(text, BorderLayout.CENTER)
        dialog.contentPane.add(JPanel(BorderLayout()).apply {
            add(JPanel(FlowLayout(FlowLayout.LEFT)).apply { add(dontShow) }, BorderLayout.WEST)
            add(JPanel(FlowLayout(FlowLayout.RIGHT)).apply { add(cancel); add(ok) }, BorderLayout.EAST)
        }, BorderLayout.SOUTH)
        dialog.rootPane.defaultButton = ok
        dialog.pack()
        dialog.setLocationRelativeTo(owner)
        dialog.isVisible = true
        return Choice(proceed, dontShow.isSelected)
    }
}
