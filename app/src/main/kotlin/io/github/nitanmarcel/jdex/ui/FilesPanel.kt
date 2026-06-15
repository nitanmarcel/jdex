package io.github.nitanmarcel.jdex.ui

import io.github.andrewauclair.moderndocking.Dockable
import io.github.andrewauclair.moderndocking.app.Docking
import io.github.nitanmarcel.jdex.project.Content
import io.github.nitanmarcel.jdex.project.MalformedDex
import io.github.nitanmarcel.jdex.project.ProjectNode
import java.awt.BorderLayout
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.AbstractAction
import javax.swing.JMenuItem
import javax.swing.KeyStroke
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.JScrollPane
import javax.swing.JTree
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel
import javax.swing.tree.TreePath

class FilesPanel(
    private val onOpen: (id: String, title: String, load: () -> Content) -> Unit,
    private val onFindUsages: (query: String) -> Unit = {},
    private val onOpenDex: (MalformedDex) -> Unit = {},
) : JPanel(BorderLayout()), Dockable {

    private val root = DefaultMutableTreeNode()
    private val model = DefaultTreeModel(root)
    private val tree = JTree(model).apply { isRootVisible = false; cellRenderer = NodeRenderer() }

    init {
        Docking.registerDockable(this)
        add(JScrollPane(tree), BorderLayout.CENTER)

        tree.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount != 2) return
                val node = nodeAt(e) ?: return
                open(node)
            }

            override fun mousePressed(e: MouseEvent) = maybeMenu(e)
            override fun mouseReleased(e: MouseEvent) = maybeMenu(e)
        })

        tree.inputMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "open")
        tree.actionMap.put("open", object : AbstractAction() {
            override fun actionPerformed(e: ActionEvent?) {
                val node = tree.lastSelectedPathComponent as? DefaultMutableTreeNode ?: return
                val project = node.userObject as? ProjectNode
                if (project?.dex != null || project?.open != null) {
                    open(node)
                } else {
                    val path = TreePath(node.path)
                    if (tree.isExpanded(path)) tree.collapsePath(path) else tree.expandPath(path)
                }
            }
        })
    }

    private fun nodeAt(e: MouseEvent): DefaultMutableTreeNode? =
        (tree.getPathForLocation(e.x, e.y)?.lastPathComponent as? DefaultMutableTreeNode)

    private fun maybeMenu(e: MouseEvent) {
        if (!e.isPopupTrigger) return
        val path = tree.getPathForLocation(e.x, e.y) ?: return
        tree.selectionPath = path
        val node = path.lastPathComponent as DefaultMutableTreeNode
        val project = node.userObject as? ProjectNode ?: return
        val menu = JPopupMenu()
        if (project.dex != null) menu.add(JMenuItem("Edit DEX…").apply { addActionListener { onOpenDex(project.dex!!) } })
        if (project.open != null) menu.add(JMenuItem("Open").apply { addActionListener { open(node) } })
        resourceRef(path)?.let { ref ->
            menu.add(JMenuItem("Find usages in Bytecode").apply { addActionListener { onFindUsages(ref) } })
        }
        if (menu.componentCount > 0) menu.show(tree, e.x, e.y)
    }

    private fun resourceRef(path: TreePath): String? {
        val labels = path.path.mapNotNull { (it as? DefaultMutableTreeNode)?.userObject as? ProjectNode }.map { it.label }
        if ("Resources" !in labels || labels.size < 2) return null
        val leaf = labels.last()
        if (!leaf.contains('.')) return null
        val type = labels[labels.size - 2].substringBefore('-')
        return "@$type/${leaf.substringBeforeLast('.')}"
    }

    private fun open(node: DefaultMutableTreeNode) {
        val project = node.userObject as? ProjectNode ?: return
        project.dex?.let { onOpenDex(it); return }
        val load = project.open ?: return
        val id = TreePath(node.path).path.drop(1).joinToString("/") { it.toString() }
        onOpen(id, project.label, load)
    }

    fun openResource(type: String, name: String) {
        val match = findResource(type, name) ?: findLeaf("resources.arsc")
        match?.let {
            tree.selectionPath = TreePath(it.path)
            tree.scrollPathToVisible(TreePath(it.path))
            open(it)
        }
    }

    private fun findResource(type: String, name: String): DefaultMutableTreeNode? {
        fun dfs(node: DefaultMutableTreeNode, parent: String?): DefaultMutableTreeNode? {
            val project = node.userObject as? ProjectNode
            if (project?.open != null && parent?.substringBefore('-') == type && project.label.substringBeforeLast('.') == name) return node
            for (i in 0 until node.childCount) dfs(node.getChildAt(i) as DefaultMutableTreeNode, project?.label)?.let { return it }
            return null
        }
        return dfs(root, null)
    }

    private fun findLeaf(label: String): DefaultMutableTreeNode? {
        fun dfs(node: DefaultMutableTreeNode): DefaultMutableTreeNode? {
            if ((node.userObject as? ProjectNode)?.label == label) return node
            for (i in 0 until node.childCount) dfs(node.getChildAt(i) as DefaultMutableTreeNode)?.let { return it }
            return null
        }
        return dfs(root)
    }

    fun clear() {
        root.removeAllChildren()
        model.reload()
    }

    fun bytecode(): Triple<String, String, () -> Content>? {
        fun search(node: DefaultMutableTreeNode, path: List<String>): Triple<String, String, () -> Content>? {
            val project = node.userObject as? ProjectNode
            val here = if (project != null) path + project.label else path
            val load = project?.open
            if (project?.label == "Bytecode" && load != null) return Triple(here.joinToString("/"), project.label, load)
            for (i in 0 until node.childCount) search(node.getChildAt(i) as DefaultMutableTreeNode, here)?.let { return it }
            return null
        }
        return search(root, emptyList())
    }

    fun show(node: ProjectNode) {
        root.removeAllChildren()
        root.add(toTreeNode(node))
        model.reload()
        tree.expandRow(0)
        tree.expandRow(1)
        tree.expandRow(2)
    }

    private fun toTreeNode(node: ProjectNode): DefaultMutableTreeNode =
        DefaultMutableTreeNode(node).apply {
            node.children.forEach { add(toTreeNode(it)) }
        }

    private inner class NodeRenderer : javax.swing.tree.DefaultTreeCellRenderer() {
        override fun getTreeCellRendererComponent(
            tree: JTree, value: Any?, sel: Boolean, expanded: Boolean, leaf: Boolean, row: Int, focus: Boolean,
        ): java.awt.Component {
            super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, focus)
            ((value as? DefaultMutableTreeNode)?.userObject as? ProjectNode)?.let { icon = iconFor(it, expanded) }
            return this
        }
    }

    private fun iconFor(node: ProjectNode, expanded: Boolean): javax.swing.Icon = when {
        node.dex != null -> Icons.FILE_BINARY
        node.open == null -> if (expanded) Icons.FOLDER_OPEN else Icons.FOLDER
        node.label == "Bytecode" || node.label == "Manifest" -> Icons.FILE_CODE
        node.label.startsWith("Certificate") -> Icons.of("shield")
        node.label.endsWith(".json") -> Icons.JSON
        node.label.substringAfterLast('.', "").lowercase() in CODE_EXT -> Icons.FILE_CODE
        else -> Icons.FILE
    }

    override fun isWrappableInScrollpane() = false

    override fun getPersistentID() = "project_explorer"

    override fun getTabText() = "Project Explorer"

    private companion object {
        val CODE_EXT = setOf("xml", "html", "htm", "js", "css", "smali", "java", "kt", "properties", "json", "txt")
    }
}
