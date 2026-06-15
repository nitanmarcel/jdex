package io.github.nitanmarcel.jdex.ui

import io.github.andrewauclair.moderndocking.Dockable
import io.github.andrewauclair.moderndocking.app.Docking
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea
import org.fife.ui.rtextarea.RTextScrollPane
import java.awt.BorderLayout
import javax.swing.JPanel

class EditorAnchor : JPanel(BorderLayout()), Dockable {

    init {
        Docking.registerDockingAnchor(this)

        add(RTextScrollPane(RSyntaxTextArea().also { SyntaxThemes.attach(it) }), BorderLayout.CENTER)
    }

    override fun isWrappableInScrollpane() = false

    override fun getPersistentID() = "editors"

    override fun getTabText() = ""
}
