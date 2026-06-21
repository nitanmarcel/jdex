package io.github.nitanmarcel.jdex.ui

import io.github.nitanmarcel.jdex.disasm.Disassembler
import io.github.nitanmarcel.jdex.disasm.Disassemblers
import io.github.nitanmarcel.jdex.disasm.ElfArch
import io.github.nitanmarcel.jdex.disasm.ElfFile
import java.awt.BorderLayout
import java.awt.Dialog
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.GridLayout
import java.awt.Window
import javax.swing.BorderFactory
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JPanel

object DisassemblerDialog {

    class Choice(val disassembler: Disassembler, val arch: ElfArch, val littleEndian: Boolean)

    fun show(owner: Window?, name: String, elf: ElfFile): Choice? {
        val dialog = JDialog(owner, "Disassemble — $name", Dialog.ModalityType.APPLICATION_MODAL)
        var result: Choice? = null

        val arches = ElfArch.entries.filter { it != ElfArch.UNKNOWN }
        val archCombo = JComboBox(arches.map { it.display }.toTypedArray()).apply {
            selectedIndex = arches.indexOf(elf.arch).let { if (it >= 0) it else arches.indexOf(ElfArch.ARM64) }
        }
        val disasmCombo = JComboBox(Disassemblers.all.map { it.displayName }.toTypedArray())
        val endianCombo = JComboBox(arrayOf("Little-endian", "Big-endian")).apply {
            selectedIndex = if (elf.littleEndian) 0 else 1
        }
        val status = JLabel(" ")

        val form = JPanel(GridLayout(0, 2, 8, 8)).apply {
            border = BorderFactory.createEmptyBorder(12, 12, 4, 12)
            add(JLabel("Disassembler:")); add(disasmCombo)
            add(JLabel("Architecture:")); add(archCombo)
            add(JLabel("Endianness:")); add(endianCombo)
        }
        val detected = JLabel("Detected: ${elf.arch.display}, ${if (elf.littleEndian) "little" else "big"}-endian, ${if (elf.is64) "64-bit" else "32-bit"}").apply {
            border = BorderFactory.createEmptyBorder(0, 12, 0, 12)
        }

        val ok = JButton("Disassemble")
        val cancel = JButton("Cancel")
        fun chosen(): Triple<Disassembler, ElfArch, Boolean> =
            Triple(Disassemblers.all[disasmCombo.selectedIndex], arches[archCombo.selectedIndex], endianCombo.selectedIndex == 0)
        fun validate() {
            val (d, arch, _) = chosen()
            val supported = d.supports(arch)
            ok.isEnabled = supported
            status.text = if (supported) " " else "${d.displayName} does not support ${arch.display}"
        }
        archCombo.addActionListener { validate() }
        disasmCombo.addActionListener { validate() }
        validate()

        ok.addActionListener {
            val (d, arch, le) = chosen()
            if (d.supports(arch)) { result = Choice(d, arch, le); dialog.dispose() }
        }
        cancel.addActionListener { dialog.dispose() }

        val buttons = JPanel(FlowLayout(FlowLayout.RIGHT)).apply { add(cancel); add(ok) }
        val south = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(status.apply { border = BorderFactory.createEmptyBorder(2, 12, 2, 12) })
            add(buttons)
        }

        dialog.contentPane.layout = BorderLayout()
        dialog.contentPane.add(detected, BorderLayout.NORTH)
        dialog.contentPane.add(form, BorderLayout.CENTER)
        dialog.contentPane.add(south, BorderLayout.SOUTH)
        dialog.rootPane.defaultButton = ok
        dialog.minimumSize = Dimension(360, 0)
        dialog.pack()
        dialog.setLocationRelativeTo(owner)
        dialog.isVisible = true
        return result
    }
}
