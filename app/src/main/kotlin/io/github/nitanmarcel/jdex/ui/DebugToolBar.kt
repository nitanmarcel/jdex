package io.github.nitanmarcel.jdex.ui

import io.github.nitanmarcel.jdex.debug.DebugDevice
import io.github.nitanmarcel.jdex.debug.DebugProcess
import io.github.nitanmarcel.jdex.debug.DebugState
import io.github.nitanmarcel.jdex.debug.DeviceBridge
import java.awt.Component
import java.awt.Dimension
import javax.swing.DefaultComboBoxModel
import javax.swing.DefaultListCellRenderer
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JSeparator
import javax.swing.JToolBar
import javax.swing.SwingUtilities
import javax.swing.event.PopupMenuEvent
import javax.swing.event.PopupMenuListener

class DebugToolBar(
    private val onAttach: (DebugDevice, DebugProcess) -> Unit = { _, _ -> },
    private val onResume: () -> Unit = {},
    private val onPause: () -> Unit = {},
    private val onStepInto: () -> Unit = {},
    private val onStepOver: () -> Unit = {},
    private val onStepOut: () -> Unit = {},
    private val onDetach: () -> Unit = {},
    private val onExceptionBreak: (Boolean) -> Unit = {},
    private val packageHint: () -> String? = { null },
    private val log: (String) -> Unit = {},
) : JToolBar() {

    private val separator = DebugProcess(-1, "")

    private val deviceCombo = JComboBox<DebugDevice>().apply {
        maximumSize = Dimension(240, 26)
        prototypeDisplayValue = DebugDevice("emulator-5554", "Pixel 7", true)
        putClientProperty("JTextField.placeholderText", "Select device")
    }
    private val processCombo = JComboBox<DebugProcess>().apply {
        maximumSize = Dimension(280, 26)
        prototypeDisplayValue = DebugProcess(0, "io.github.nitanmarcel.jdexdbg")
        putClientProperty("JTextField.placeholderText", "Select process")
    }
    private val refreshBtn = JButton(Icons.REFRESH).apply { toolTipText = "Refresh devices" }
    private val attachBtn = JButton("Attach", Icons.DEBUG_CONTINUE).apply { toolTipText = "Attach debugger to the selected process"; isEnabled = false }
    private val statusLabel = JLabel(" detached ")

    private val resumeBtn = control(Icons.DEBUG_CONTINUE, "Resume") { onResume() }
    private val pauseBtn = control(Icons.DEBUG_PAUSE, "Pause") { onPause() }
    private val stepInBtn = control(Icons.DEBUG_STEP_INTO, "Step into") { onStepInto() }
    private val stepOverBtn = control(Icons.DEBUG_STEP_OVER, "Step over") { onStepOver() }
    private val stepOutBtn = control(Icons.DEBUG_STEP_OUT, "Step out") { onStepOut() }
    private val detachBtn = control(Icons.DEBUG_STOP, "Detach") { onDetach() }
    private val exceptionToggle = javax.swing.JToggleButton(Icons.DEBUG_EXCEPTION).apply {
        toolTipText = "Pause on uncaught exceptions"
        isSelected = true
    }

    init {
        isFloatable = false
        isOpaque = false
        border = javax.swing.BorderFactory.createEmptyBorder()
        deviceCombo.renderer = renderer<DebugDevice> { d -> if (d.online) "${d.label} (${d.serial})" else "${d.label} (${d.serial}) — offline" }
        processCombo.renderer = object : DefaultListCellRenderer() {
            override fun getListCellRendererComponent(list: JList<*>?, value: Any?, index: Int, selected: Boolean, focus: Boolean): Component {
                if (value is DebugProcess && value.pid < 0) return JSeparator(JSeparator.HORIZONTAL)
                val c = super.getListCellRendererComponent(list, value, index, selected, focus)
                (value as? DebugProcess)?.let { (c as JLabel).text = "${it.name} (pid ${it.pid})" }
                return c
            }
        }
        add(JLabel(" Device: "))
        add(deviceCombo)
        add(refreshBtn)
        add(JLabel("  Process: "))
        add(processCombo)
        add(attachBtn)
        addSeparator()
        listOf(resumeBtn, pauseBtn, stepInBtn, stepOverBtn, stepOutBtn, detachBtn).forEach { add(it) }
        addSeparator()
        add(exceptionToggle)
        addSeparator()
        add(statusLabel)

        exceptionToggle.addActionListener { onExceptionBreak(exceptionToggle.isSelected) }

        refreshBtn.addActionListener { refreshDevices() }
        deviceCombo.addActionListener { refreshProcesses(autoSelect = true) }
        processCombo.addActionListener {
            val sel = processCombo.selectedItem as? DebugProcess
            if (sel != null && sel.pid < 0) {
                val i = processCombo.selectedIndex
                processCombo.selectedIndex = if (i + 1 < processCombo.itemCount) i + 1 else (i - 1).coerceAtLeast(0)
                return@addActionListener
            }
            attachBtn.isEnabled = deviceCombo.isEnabled && sel != null && sel.pid >= 0
        }
        deviceCombo.addPopupMenuListener(onPopupOpen { if (deviceCombo.isEnabled) refreshDevices() })
        processCombo.addPopupMenuListener(onPopupOpen { if (processCombo.isEnabled) refreshProcesses(autoSelect = false) })
        attachBtn.addActionListener {
            val dev = deviceCombo.selectedItem as? DebugDevice ?: return@addActionListener
            val proc = processCombo.selectedItem as? DebugProcess ?: return@addActionListener
            onAttach(dev, proc)
        }
        setState(DebugState.Detached)
    }

    fun exceptionBreakEnabled(): Boolean = exceptionToggle.isSelected

    fun setState(state: DebugState) {
        val attached = state != DebugState.Detached
        val stopped = state is DebugState.Stopped
        deviceCombo.isEnabled = !attached
        processCombo.isEnabled = !attached
        refreshBtn.isEnabled = !attached
        attachBtn.isEnabled = !attached && processCombo.selectedItem != null
        resumeBtn.isEnabled = stopped
        stepInBtn.isEnabled = stopped
        stepOverBtn.isEnabled = stopped
        stepOutBtn.isEnabled = stopped
        pauseBtn.isEnabled = state == DebugState.Running
        detachBtn.isEnabled = attached
        statusLabel.text = when (state) {
            DebugState.Detached -> " detached "
            DebugState.Running -> " running "
            is DebugState.Stopped -> " stopped "
        }
    }

    fun refreshDevices() {
        refreshBtn.isEnabled = false
        Thread {
            val list = runCatching { DeviceBridge.devices() }.getOrElse { log("Device list failed: ${it.message}"); emptyList() }
            SwingUtilities.invokeLater {
                refreshBtn.isEnabled = true
                if (list != comboItems(deviceCombo)) {
                    val prev = (deviceCombo.selectedItem as? DebugDevice)?.serial
                    deviceCombo.model = DefaultComboBoxModel(list.toTypedArray())
                    list.firstOrNull { it.serial == prev }?.let { deviceCombo.selectedItem = it }
                    if (list.isEmpty()) log("No devices/emulators connected")
                }
                refreshProcesses(autoSelect = true)
            }
        }.start()
    }

    private fun refreshProcesses(autoSelect: Boolean = false) {
        val dev = deviceCombo.selectedItem as? DebugDevice
        if (dev == null || !dev.online) {
            processCombo.model = DefaultComboBoxModel()
            attachBtn.isEnabled = false
            return
        }
        Thread {
            val all = runCatching { DeviceBridge.processes(dev.serial) }.getOrElse { emptyList() }
            val pkg = packageHint()?.takeIf { it.isNotEmpty() }
            val matching = if (pkg == null) emptyList()
                else all.filter { it.name.contains(pkg) }.sortedWith(compareByDescending<DebugProcess> { it.name == pkg }.thenBy { it.name })
            val others = all.filter { it !in matching }.sortedBy { it.name }
            val items = when {
                matching.isEmpty() -> others
                others.isEmpty() -> matching
                else -> matching + separator + others
            }
            SwingUtilities.invokeLater {
                if (items != comboItems(processCombo)) {
                    val prevPid = (processCombo.selectedItem as? DebugProcess)?.pid
                    processCombo.model = DefaultComboBoxModel(items.toTypedArray())
                    val pick = if (autoSelect && matching.isNotEmpty()) matching.first()
                        else items.firstOrNull { it.pid == prevPid } ?: matching.firstOrNull() ?: items.firstOrNull { it.pid >= 0 }
                    pick?.let { processCombo.selectedItem = it }
                } else if (autoSelect && matching.isNotEmpty()) {
                    processCombo.selectedItem = matching.first()
                }
                attachBtn.isEnabled = deviceCombo.isEnabled && (processCombo.selectedItem as? DebugProcess)?.let { it.pid >= 0 } == true
            }
        }.start()
    }

    private fun <T> comboItems(combo: JComboBox<T>): List<T> = (0 until combo.itemCount).map { combo.getItemAt(it) }

    private fun onPopupOpen(action: () -> Unit) = object : PopupMenuListener {
        override fun popupMenuWillBecomeVisible(e: PopupMenuEvent) = action()
        override fun popupMenuWillBecomeInvisible(e: PopupMenuEvent) {}
        override fun popupMenuCanceled(e: PopupMenuEvent) {}
    }

    private fun control(icon: javax.swing.Icon, tip: String, action: () -> Unit) =
        JButton(icon).apply { toolTipText = tip; isEnabled = false; addActionListener { action() } }

    private fun <T> renderer(text: (T) -> String) = object : DefaultListCellRenderer() {
        override fun getListCellRendererComponent(
            list: JList<*>?, value: Any?, index: Int, selected: Boolean, focus: Boolean,
        ): Component {
            val c = super.getListCellRendererComponent(list, value, index, selected, focus)
            @Suppress("UNCHECKED_CAST")
            (value as? T)?.let { (c as JLabel).text = text(it) }
            return c
        }
    }
}
