package io.github.nitanmarcel.jdex.ui

import io.github.andrewauclair.moderndocking.Dockable
import io.github.andrewauclair.moderndocking.app.Docking
import java.awt.BorderLayout
import javax.swing.JComponent
import javax.swing.JPanel

class EditorTab(
    private val id: String,
    private val title: String,
    content: JComponent,
    private val closeable: AutoCloseable? = null,
    private val icon: javax.swing.Icon? = null,
) : JPanel(BorderLayout()), Dockable {

    init {
        Docking.registerDockable(this)
        add(content, BorderLayout.CENTER)
    }

    fun dispose() {
        closeable?.close()
    }

    override fun isWrappableInScrollpane() = false

    override fun getIcon(): javax.swing.Icon? = icon

    override fun getPersistentID() = id

    override fun getTabText() = title
}
