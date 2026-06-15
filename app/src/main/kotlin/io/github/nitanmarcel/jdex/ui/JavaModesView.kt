package io.github.nitanmarcel.jdex.ui

import com.formdev.flatlaf.extras.components.FlatTriStateCheckBox.State
import io.github.nitanmarcel.jdex.project.ApkSession
import io.github.nitanmarcel.jdex.project.ApkSession.DecompileMode
import io.github.nitanmarcel.jdex.project.CodeSync
import io.github.nitanmarcel.jdex.project.SyncTarget
import java.awt.BorderLayout
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTabbedPane
import javax.swing.SwingConstants

class JavaModesView(
    private val decompile: (mode: DecompileMode, onResult: (ApkSession.Decompiled?) -> Unit) -> Unit,
    private val onCaret: (SyncTarget) -> Unit,
    private var syncState: State,
    private val onSyncToggle: (State) -> Unit,
) : JPanel(BorderLayout()) {

    private val modes = DecompileMode.values()
    private val tabs = JTabbedPane()
    private val views = HashMap<DecompileMode, JavaView>()
    private val loading = HashSet<DecompileMode>()

    init {
        modes.forEach { tabs.addTab(it.label, JPanel(BorderLayout())) }
        tabs.addChangeListener { ensureLoaded(modes[tabs.selectedIndex]) }
        add(tabs, BorderLayout.CENTER)
        ensureLoaded(modes[0])
    }

    private fun container(mode: DecompileMode) = tabs.getComponentAt(modes.indexOf(mode)) as JPanel

    private fun ensureLoaded(mode: DecompileMode) {
        if (mode in views || mode in loading) return
        loading.add(mode)
        val container = container(mode)
        container.removeAll()
        container.add(JLabel("Decompiling…", SwingConstants.CENTER), BorderLayout.CENTER)
        container.revalidate(); container.repaint()
        decompile(mode) { result ->
            loading.remove(mode)
            container.removeAll()
            if (result == null) {
                container.add(JLabel("Failed to decompile", SwingConstants.CENTER), BorderLayout.CENTER)
            } else {
                val view = JavaView(
                    result.code,
                    if (mode.sync) result.sync else CodeSync.EMPTY,
                    onCaret = { target -> if (modes[tabs.selectedIndex] == mode) onCaret(target) },
                    syncInitial = syncState,
                    onSyncToggle = { state -> syncChanged(mode, state) },
                )
                views[mode] = view
                container.add(view, BorderLayout.CENTER)
            }
            container.revalidate(); container.repaint()
        }
    }

    private fun syncChanged(source: DecompileMode, state: State) {
        syncState = state
        views.forEach { (mode, view) -> if (mode != source) view.setSyncState(state) }
        onSyncToggle(state)
    }

    fun followTo(target: SyncTarget) {
        views[modes[tabs.selectedIndex]]?.followTo(target)
    }
}
