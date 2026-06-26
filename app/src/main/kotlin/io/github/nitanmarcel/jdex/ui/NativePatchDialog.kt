package io.github.nitanmarcel.jdex.ui

import io.github.nitanmarcel.jdex.disasm.CapstoneDisassembler
import io.github.nitanmarcel.jdex.disasm.ElfArch
import io.github.nitanmarcel.jdex.disasm.KeystoneAssembler
import java.awt.BorderLayout
import java.awt.Dialog
import java.awt.Window
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

object NativePatchDialog {
    fun show(owner: Window?, addr: Long, arch: ElfArch, currentAsm: String): ByteArray? {
        val dialog = JDialog(owner, "Patch @ 0x${addr.toString(16)}", Dialog.ModalityType.APPLICATION_MODAL)
        var result: ByteArray? = null

        val field = JTextField(currentAsm, 36)
        val preview = JLabel(" ")
        val ok = JButton("Patch")

        fun assemble() = KeystoneAssembler.assemble(field.text.trim(), addr, arch)
        fun refresh() {
            if (field.text.isBlank()) { ok.isEnabled = false; preview.text = " "; return }
            assemble().fold(
                onSuccess = { b ->
                    val dis = CapstoneDisassembler.disassemble(b, addr, arch, false).joinToString("; ") { "${it.mnemonic} ${it.operands}".trim() }
                    preview.text = "<html>${b.size} bytes: ${b.joinToString(" ") { "%02x".format(it) }}<br/>$dis</html>"
                    ok.isEnabled = b.isNotEmpty()
                },
                onFailure = { preview.text = "<html><font color=red>${it.message}</font></html>"; ok.isEnabled = false },
            )
        }
        field.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = refresh()
            override fun removeUpdate(e: DocumentEvent) = refresh()
            override fun changedUpdate(e: DocumentEvent) = refresh()
        })

        ok.addActionListener { assemble().getOrNull()?.let { result = it; dialog.dispose() } }
        val cancel = JButton("Cancel").apply { addActionListener { dialog.dispose() } }

        dialog.contentPane.add(JPanel(BorderLayout(0, 6)).apply {
            border = BorderFactory.createEmptyBorder(10, 12, 6, 12)
            add(field, BorderLayout.NORTH)
            add(preview, BorderLayout.CENTER)
        }, BorderLayout.CENTER)
        dialog.contentPane.add(JPanel(java.awt.FlowLayout(java.awt.FlowLayout.RIGHT)).apply { add(cancel); add(ok) }, BorderLayout.SOUTH)
        dialog.rootPane.defaultButton = ok
        refresh()
        dialog.pack()
        dialog.setLocationRelativeTo(owner)
        dialog.isVisible = true
        return result
    }
}
