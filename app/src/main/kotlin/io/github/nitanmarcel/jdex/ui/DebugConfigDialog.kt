package io.github.nitanmarcel.jdex.ui

import io.github.nitanmarcel.jdex.debug.NativeDebug
import io.github.nitanmarcel.jdex.debug.NdkLldb
import java.awt.BorderLayout
import java.awt.Dialog
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.Window
import java.io.File
import java.util.prefs.Preferences
import javax.swing.BorderFactory
import javax.swing.ButtonGroup
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JRadioButton
import javax.swing.JTextField
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

object DebugConfigDialog {

    private val prefs = Preferences.userRoot().node("jdex/ui/debugconfig")

    fun remembered(): Boolean = prefs.getBoolean("remember", false)

    fun build(abi: String): NativeDebug? = when (prefs.get("type", "managed")) {
        "remote" -> NativeDebug.Remote(prefs.get("host", "127.0.0.1"), prefs.getInt("port", 5039))
        else -> {
            val ndk = prefs.get("ndk", "").ifEmpty { NdkLldb.defaultNdkRoot()?.absolutePath }
            ndk?.let { NdkLldb.lldbServer(File(it), abi) }?.let { NativeDebug.Managed(it) }
        }
    }

    fun show(owner: Window?, abi: String, settings: Boolean = false): NativeDebug? {
        val dialog = JDialog(owner, if (settings) "Debugger settings" else "Native debugger", Dialog.ModalityType.APPLICATION_MODAL)
        var result: NativeDebug? = null

        val isManaged = prefs.get("type", "managed") != "remote"
        val managed = JRadioButton("Managed — jdex pushes & runs lldb-server", isManaged)
        val remote = JRadioButton("Remote — connect to a gdb-remote server you started", !isManaged)
        ButtonGroup().apply { add(managed); add(remote) }

        val ndkField = JTextField(prefs.get("ndk", "").ifEmpty { NdkLldb.defaultNdkRoot()?.absolutePath ?: "" })
        val hostField = JTextField(prefs.get("host", "127.0.0.1"))
        val portField = JTextField(prefs.getInt("port", 5039).toString())
        val remember = JCheckBox("Remember these settings (don't ask on each session)", prefs.getBoolean("remember", false))
        val status = JLabel(" ")
        val ok = JButton(if (settings) "Save" else "Attach")

        fun refresh() {
            val m = managed.isSelected
            ndkField.isEnabled = m; hostField.isEnabled = !m; portField.isEnabled = !m
            if (m) {
                val path = ndkField.text.trim().takeIf { it.isNotEmpty() }?.let { if (abi.isNotEmpty()) NdkLldb.lldbServer(File(it), abi) else File(it) }
                ok.isEnabled = settings && ndkField.text.isNotBlank() || path != null
                status.text = when {
                    abi.isEmpty() -> " "
                    path != null -> "lldb-server ($abi) found"
                    else -> "no lldb-server for $abi under this NDK"
                }
            } else {
                ok.isEnabled = hostField.text.isNotBlank() && portField.text.trim().toIntOrNull() != null
                status.text = " "
            }
        }
        val watcher = object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = refresh()
            override fun removeUpdate(e: DocumentEvent) = refresh()
            override fun changedUpdate(e: DocumentEvent) = refresh()
        }
        ndkField.document.addDocumentListener(watcher)
        hostField.document.addDocumentListener(watcher)
        portField.document.addDocumentListener(watcher)
        managed.addActionListener { refresh() }
        remote.addActionListener { refresh() }

        val gbc = GridBagConstraints().apply { insets = Insets(3, 4, 3, 4); fill = GridBagConstraints.HORIZONTAL; weightx = 1.0; gridwidth = 2; gridx = 0 }
        val form = JPanel(GridBagLayout()).apply {
            border = BorderFactory.createEmptyBorder(10, 12, 4, 12)
            add(managed, gbc.apply { gridy = 0 })
            add(JLabel("NDK root:"), GridBagConstraints().apply { gridx = 0; gridy = 1; insets = Insets(3, 22, 3, 4) })
            add(ndkField, GridBagConstraints().apply { gridx = 1; gridy = 1; weightx = 1.0; fill = GridBagConstraints.HORIZONTAL; insets = Insets(3, 4, 3, 4) })
            add(remote, gbc.apply { gridy = 2 })
            add(JLabel("Host:"), GridBagConstraints().apply { gridx = 0; gridy = 3; insets = Insets(3, 22, 3, 4) })
            add(hostField, GridBagConstraints().apply { gridx = 1; gridy = 3; weightx = 1.0; fill = GridBagConstraints.HORIZONTAL; insets = Insets(3, 4, 3, 4) })
            add(JLabel("Port:"), GridBagConstraints().apply { gridx = 0; gridy = 4; insets = Insets(3, 22, 3, 4) })
            add(portField, GridBagConstraints().apply { gridx = 1; gridy = 4; weightx = 1.0; fill = GridBagConstraints.HORIZONTAL; insets = Insets(3, 4, 3, 4) })
            add(remember, gbc.apply { gridy = 5 })
            add(status, gbc.apply { gridy = 6 })
        }

        fun persist() {
            prefs.put("type", if (managed.isSelected) "managed" else "remote")
            prefs.put("ndk", ndkField.text.trim())
            prefs.put("host", hostField.text.trim())
            portField.text.trim().toIntOrNull()?.let { prefs.putInt("port", it) }
            prefs.putBoolean("remember", remember.isSelected)
        }

        ok.addActionListener {
            persist()
            if (settings) { dialog.dispose(); return@addActionListener }
            result = if (managed.isSelected) {
                NdkLldb.lldbServer(File(ndkField.text.trim()), abi)?.let { NativeDebug.Managed(it) }
            } else {
                portField.text.trim().toIntOrNull()?.let { NativeDebug.Remote(hostField.text.trim(), it) }
            }
            if (result != null) dialog.dispose()
        }
        val cancel = JButton("Cancel").apply { addActionListener { dialog.dispose() } }

        dialog.contentPane.add(form, BorderLayout.CENTER)
        dialog.contentPane.add(JPanel(java.awt.FlowLayout(java.awt.FlowLayout.RIGHT)).apply { add(cancel); add(ok) }, BorderLayout.SOUTH)
        dialog.rootPane.defaultButton = ok
        refresh()
        dialog.pack()
        dialog.setLocationRelativeTo(owner)
        dialog.isVisible = true
        return result
    }
}
