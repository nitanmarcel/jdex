package org.example.ui

import io.github.andrewauclair.moderndocking.Dockable
import io.github.andrewauclair.moderndocking.app.Docking
import java.awt.BorderLayout
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTree
import javax.swing.tree.DefaultMutableTreeNode

class FilesPanel : JPanel(BorderLayout()), Dockable {

    init {
        Docking.registerDockable(this)

        val tree = JTree(DefaultMutableTreeNode()).apply { isRootVisible = false }
        add(JScrollPane(tree), BorderLayout.CENTER)
    }

    override fun getPersistentID() = "project_explorer"

    override fun getTabText() = "Project Explorer"
}
