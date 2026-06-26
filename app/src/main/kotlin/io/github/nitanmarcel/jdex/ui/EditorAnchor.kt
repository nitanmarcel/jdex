package io.github.nitanmarcel.jdex.ui

import io.github.andrewauclair.moderndocking.Dockable
import io.github.andrewauclair.moderndocking.app.Docking
import java.awt.BorderLayout
import javax.swing.JPanel

class EditorAnchor : JPanel(BorderLayout()), Dockable {

    init {
        Docking.registerDockingAnchor(this)

        add(EmptyState("file-binary", "No file open"), BorderLayout.CENTER)
    }

    override fun isWrappableInScrollpane() = false

    override fun isClosable() = false

    override fun getPersistentID() = "editors"

    override fun getTabText() = ""
}
