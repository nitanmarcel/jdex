package io.github.nitanmarcel.jdex.ui

import io.github.andrewauclair.moderndocking.Dockable
import io.github.andrewauclair.moderndocking.app.Docking
import io.github.nitanmarcel.jdex.project.HClass
import io.github.nitanmarcel.jdex.project.HField
import io.github.nitanmarcel.jdex.project.HMembers
import io.github.nitanmarcel.jdex.project.HMethod
import io.github.nitanmarcel.jdex.project.Renames
import java.awt.BorderLayout
import java.awt.Component
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.JScrollPane
import javax.swing.JTree
import javax.swing.event.TreeExpansionEvent
import javax.swing.event.TreeWillExpandListener
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeCellRenderer
import javax.swing.tree.DefaultTreeModel

class HierarchyPanel(
    private val onClass: (rawName: String) -> Unit,
    private val onMethod: (rawName: String, shortId: String) -> Unit,
    private val onField: (rawName: String, name: String) -> Unit,
    private val onDecompile: (fullName: String) -> Unit,
    private val loadMembers: (fullName: String) -> HMembers,
    private val renames: Renames = Renames(),
    private val onRenamed: () -> Unit = {},
) : JPanel(BorderLayout()), Dockable {

    private val root = DefaultMutableTreeNode()
    private val model = DefaultTreeModel(root)
    private val tree = JTree(model).apply { isRootVisible = false; showsRootHandles = true; cellRenderer = RenameRenderer() }

    init {
        Docking.registerDockable(this)
        add(JScrollPane(tree), BorderLayout.CENTER)

        tree.addTreeWillExpandListener(object : TreeWillExpandListener {
            override fun treeWillExpand(e: TreeExpansionEvent) {
                when (val node = e.path.lastPathComponent) {
                    is ClassTreeNode -> loadClass(node)
                    is MethodTreeNode -> loadMethod(node)
                }
            }

            override fun treeWillCollapse(e: TreeExpansionEvent) = Unit
        })
        tree.addTreeSelectionListener {
            when (val obj = (tree.lastSelectedPathComponent as? DefaultMutableTreeNode)?.userObject) {
                is HClass -> onClass(obj.rawName)
                is HMethod -> onMethod(obj.declaringRawName, obj.shortId)
                is HField -> onField(obj.declaringRawName, obj.name)
                is NativeSym -> obj.go()
            }
        }
        tree.addMouseListener(object : MouseAdapter() {
            override fun mousePressed(e: MouseEvent) = popup(e)
            override fun mouseReleased(e: MouseEvent) = popup(e)

            private fun popup(e: MouseEvent) {
                if (!e.isPopupTrigger) return
                val path = tree.getPathForLocation(e.x, e.y) ?: return
                tree.selectionPath = path
                val obj = (path.lastPathComponent as? DefaultMutableTreeNode)?.userObject
                val menu = JPopupMenu()
                if (obj is HClass) menu.add(JMenuItem("Decompile to Java").apply { addActionListener { onDecompile(obj.rawName) } })
                if (renames.active && (obj is HClass || obj is HMethod || obj is HField)) {
                    menu.add(JMenuItem("Rename…").apply { addActionListener { renameNode(obj) } })
                }
                if (menu.componentCount > 0) menu.show(tree, e.x, e.y)
            }
        })
    }

    private fun renameNode(obj: Any) {
        val (key, original) = when (obj) {
            is HClass -> classKey(obj.rawName) to obj.rawName.substringAfterLast('.')
            is HMethod -> "${classKey(obj.declaringRawName)}->${obj.shortId}" to obj.shortId.substringBefore('(')
            is HField -> "${classKey(obj.declaringRawName)}->${obj.name}" to obj.name
            else -> return
        }
        val current = renames.nameFor(key) ?: original
        val input = JOptionPane.showInputDialog(this, "Rename:", current) ?: return
        val name = input.trim()
        renames.store.setRename(key, if (name.isEmpty() || name == original) null else name)
        onRenamed()
    }

    fun clear() {
        root.removeAllChildren()
        model.reload()
    }

    class NativeSym(val label: String, val go: () -> Unit) {
        override fun toString() = label
    }

    fun showNativeSymbols(entries: List<Pair<String, () -> Unit>>) {
        root.removeAllChildren()
        entries.forEach { (label, go) -> root.add(DefaultMutableTreeNode(NativeSym(label, go))) }
        model.reload()
    }

    fun show(classes: List<HClass>) {
        root.removeAllChildren()
        val packages = HashMap<String, DefaultMutableTreeNode>()

        fun packageNode(pkg: String): DefaultMutableTreeNode {
            if (pkg.isEmpty()) return root
            packages[pkg]?.let { return it }
            val parent = packageNode(pkg.substringBeforeLast('.', ""))
            val node = DefaultMutableTreeNode(PackageLabel(pkg.substringAfterLast('.')))
            parent.add(node)
            packages[pkg] = node
            return node
        }

        classes.forEach { packageNode(it.pkg).add(ClassTreeNode(it)) }
        sortTree(root)
        model.reload()
    }

    private fun loadClass(node: ClassTreeNode) {
        if (node.loaded) return
        node.loaded = true
        node.removeAllChildren()
        val members = loadMembers((node.userObject as HClass).rawName)
        members.fields.forEach { node.add(DefaultMutableTreeNode(it)) }
        members.methods.forEach { node.add(MethodTreeNode(it, members.innersByMethod[it.shortId] ?: emptyList())) }
        members.looseInners.forEach { node.add(ClassTreeNode(it)) }
        sortChildren(node)
        model.nodeStructureChanged(node)
    }

    private fun loadMethod(node: MethodTreeNode) {
        if (node.loaded) return
        node.loaded = true
        node.removeAllChildren()
        node.inners.forEach { node.add(ClassTreeNode(it)) }
        sortChildren(node)
        model.nodeStructureChanged(node)
    }

    private fun sortTree(node: DefaultMutableTreeNode) {
        sortChildren(node)
        (0 until node.childCount).map { node.getChildAt(it) as DefaultMutableTreeNode }
            .forEach { if (it.userObject is PackageLabel) sortTree(it) }
    }

    private fun sortChildren(node: DefaultMutableTreeNode) {
        val children = (0 until node.childCount).map { node.getChildAt(it) as DefaultMutableTreeNode }
        val sorted = children.sortedWith(compareBy({ rank(it) }, { it.userObject.toString().lowercase() }))
        node.removeAllChildren()
        sorted.forEach { node.add(it) }
    }

    private fun rank(node: DefaultMutableTreeNode) = when (node.userObject) {
        is PackageLabel -> 0
        is HField -> 1
        is HMethod -> 2
        is HClass -> 3
        else -> 4
    }

    private class PackageLabel(val name: String) {
        override fun toString() = name
    }

    private inner class ClassTreeNode(hClass: HClass) : DefaultMutableTreeNode(hClass) {
        var loaded = false

        init {
            add(DefaultMutableTreeNode("…"))
        }
    }

    private inner class MethodTreeNode(hMethod: HMethod, val inners: List<HClass>) : DefaultMutableTreeNode(hMethod) {
        var loaded = false

        init {
            if (inners.isNotEmpty()) add(DefaultMutableTreeNode("…"))
        }
    }

    private fun classKey(rawName: String) = "L${rawName.replace('.', '/')};"

    fun refresh() = tree.repaint()

    private inner class RenameRenderer : DefaultTreeCellRenderer() {
        override fun getTreeCellRendererComponent(
            tree: JTree, value: Any?, sel: Boolean, expanded: Boolean, leaf: Boolean, row: Int, hasFocus: Boolean,
        ): Component {
            super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus)
            when (val obj = (value as? DefaultMutableTreeNode)?.userObject) {
                is NativeSym -> icon = Icons.METHOD
                is PackageLabel -> icon = Icons.PACKAGE
                is HClass -> {
                    icon = Icons.CLASS
                    renames.nameFor(classKey(obj.rawName))?.let { text = it }
                }
                is HMethod -> {
                    icon = Icons.METHOD
                    renames.nameFor("${classKey(obj.declaringRawName)}->${obj.shortId}")?.let {
                        val rest = obj.display.indexOf('(')
                        text = if (rest >= 0) it + obj.display.substring(rest) else it
                    }
                }
                is HField -> {
                    icon = Icons.FIELD
                    renames.nameFor("${classKey(obj.declaringRawName)}->${obj.name}")?.let {
                        val rest = obj.display.indexOf(' ')
                        text = if (rest >= 0) it + obj.display.substring(rest) else it
                    }
                }
            }
            return this
        }
    }

    override fun isWrappableInScrollpane() = false

    override fun getPersistentID() = "hierarchy"

    override fun getTabText() = "Hierarchy"
}
