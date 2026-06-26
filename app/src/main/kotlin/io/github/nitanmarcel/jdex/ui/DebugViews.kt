package io.github.nitanmarcel.jdex.ui

import io.github.andrewauclair.moderndocking.Dockable
import io.github.andrewauclair.moderndocking.app.Docking
import io.github.nitanmarcel.jdex.debug.DebugLocation
import io.github.nitanmarcel.jdex.debug.DebugVar
import io.github.nitanmarcel.jdex.debug.Frame
import io.github.nitanmarcel.jdex.debug.LoadedModule
import io.github.nitanmarcel.jdex.debug.ThreadInfo
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Font
import javax.swing.DefaultListCellRenderer
import javax.swing.DefaultListModel
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTree
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities
import javax.swing.event.TreeExpansionEvent
import javax.swing.event.TreeWillExpandListener
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeCellRenderer
import javax.swing.tree.DefaultTreeModel
import javax.swing.tree.TreeSelectionModel

class DebugViews(
    private val onFrameSelected: (Int, DebugLocation, List<DebugVar>) -> Unit = { _, _, _ -> },
    onSetValue: (String, String) -> Boolean = { _, _ -> false },
    onOpenModule: (LoadedModule) -> Unit = {},
    isPointer: (Long) -> Boolean = { false },
) {

    private var framesFor: (Long) -> List<Frame> = { emptyList() }
    private var variablesFor: (Long, Int) -> List<DebugVar> = { _, _ -> emptyList() }
    private var childrenFor: (Long) -> List<DebugVar> = { emptyList() }
    private var loading = false
    private var lastFrameKey: Pair<Long, Int>? = null
    private var lastValues: Map<String, String> = emptyMap()

    private var currentFrame = -1
    private var threadsProvider: () -> List<ThreadInfo> = { emptyList() }
    private val worker = java.util.concurrent.Executors.newSingleThreadExecutor {
        java.lang.Thread(it, "jdex-debug-vars").apply { isDaemon = true }
    }

    val threads = DebugThreadsView { if (!loading) onThread(it.id) }
    val frames = DebugFramesView { if (!loading) onFrame(it) }
    val memory = DebugMemoryView()
    val libraries = DebugLibrariesView({ addr -> memory.go(addr); Docking.bringToFront(memory) }, onOpenModule)
    val variables = DebugVarsView({ childrenFor(it) }, onSetValue, { reloadCurrentFrame() }, isPointer) { addr ->
        memory.go(addr); Docking.bringToFront(memory)
    }

    val dockables: List<Dockable> get() = listOf(threads, frames, variables, libraries, memory)

    fun showStopped(
        threadsProvider: () -> List<ThreadInfo>,
        framesFor: (Long) -> List<Frame>,
        variablesFor: (Long, Int) -> List<DebugVar>,
        childrenFor: (Long) -> List<DebugVar>,
        modulesProvider: () -> List<LoadedModule> = { emptyList() },
    ) {
        this.threadsProvider = threadsProvider
        this.framesFor = framesFor
        this.variablesFor = variablesFor
        this.childrenFor = childrenFor
        worker.submit {
            val threadList = runCatching { threadsProvider() }.getOrDefault(emptyList())
            val moduleList = runCatching { modulesProvider() }.getOrDefault(emptyList())
            SwingUtilities.invokeLater {
                loading = true
                threads.set(threadList)
                libraries.set(moduleList)
                memory.refresh()
                val current = threadList.firstOrNull { it.current } ?: threadList.firstOrNull()
                threads.select(current)
                loading = false
                if (current != null) onThread(current.id) else { frames.clear(); variables.clear() }
            }
        }
    }

    fun clear() {
        threadsProvider = { emptyList() }
        framesFor = { emptyList() }
        variablesFor = { _, _ -> emptyList() }
        childrenFor = { emptyList() }
        currentFrame = -1
        SwingUtilities.invokeLater {
            loading = true
            threads.clear()
            frames.clear()
            variables.clear()
            libraries.clear()
            memory.clear()
            loading = false
        }
    }

    private fun onThread(threadId: Long) {
        worker.submit {
            val list = runCatching { framesFor(threadId) }.getOrDefault(emptyList())
            SwingUtilities.invokeLater {
                loading = true
                frames.set(list)
                loading = false
                if (frames.count() > 0) frames.select(0) else variables.clear()
            }
        }
    }

    private fun onFrame(index: Int) {
        val threadId = threads.selectedId() ?: return
        currentFrame = index
        worker.submit {
            val vars = runCatching { variablesFor(threadId, index) }.getOrDefault(emptyList())
            SwingUtilities.invokeLater {
                val key = threadId to index
                val changed = if (key == lastFrameKey) vars.filter { lastValues[it.name] != it.value }.map { it.name }.toHashSet() else emptySet()
                lastValues = vars.associate { it.name to it.value }
                lastFrameKey = key
                variables.set(vars, changed)
                frames.locationAt(index)?.let { onFrameSelected(index, it, vars) }
            }
        }
    }

    private fun reloadCurrentFrame() {
        if (currentFrame >= 0) SwingUtilities.invokeLater { onFrame(currentFrame) }
    }
}

class DebugThreadsView(private val onSelect: (ThreadInfo) -> Unit) : JPanel(BorderLayout()), Dockable {
    private val model = DefaultListModel<ThreadInfo>()
    private val list = JList(model).apply {
        selectionMode = ListSelectionModel.SINGLE_SELECTION
        cellRenderer = listRenderer<ThreadInfo> { "${if (it.current) "● " else ""}${it.name} [${it.state}]" }
    }

    init {
        Docking.registerDockable(this)
        add(JScrollPane(list), BorderLayout.CENTER)
        list.addListSelectionListener { if (!it.valueIsAdjusting) list.selectedValue?.let(onSelect) }
    }

    fun set(items: List<ThreadInfo>) { model.clear(); items.forEach { model.addElement(it) } }
    fun select(t: ThreadInfo?) { list.setSelectedValue(t, true) }
    fun selectedId(): Long? = list.selectedValue?.id
    fun clear() = model.clear()

    override fun isWrappableInScrollpane() = false
    override fun getPersistentID() = "debug-threads"
    override fun getTabText() = "Threads"
}

class DebugLibrariesView(
    private val onViewMemory: (Long) -> Unit = {},
    private val onOpenInDisasm: (LoadedModule) -> Unit = {},
) : JPanel(BorderLayout()), Dockable {
    private val model = DefaultListModel<LoadedModule>()
    private val all = ArrayList<LoadedModule>()
    private val list = JList(model).apply {
        selectionMode = ListSelectionModel.SINGLE_SELECTION
        cellRenderer = listRenderer<LoadedModule> { "%016x  %s".format(it.base, it.name) }
    }
    private val searchField = javax.swing.JTextField()
    private val searchBar = JPanel(BorderLayout()).apply {
        isVisible = false
        border = javax.swing.BorderFactory.createEmptyBorder(2, 4, 2, 4)
        add(JLabel("Find: "), BorderLayout.WEST)
        add(searchField, BorderLayout.CENTER)
        add(javax.swing.JButton("✕").apply { addActionListener { closeSearch() } }, BorderLayout.EAST)
    }

    init {
        Docking.registerDockable(this)
        add(JScrollPane(list), BorderLayout.CENTER)
        add(searchBar, BorderLayout.SOUTH)
        list.addMouseListener(object : java.awt.event.MouseAdapter() {
            override fun mousePressed(e: java.awt.event.MouseEvent) = popup(e)
            override fun mouseReleased(e: java.awt.event.MouseEvent) = popup(e)
            override fun mouseClicked(e: java.awt.event.MouseEvent) {
                if (e.clickCount != 2 || !javax.swing.SwingUtilities.isLeftMouseButton(e)) return
                val i = list.locationToIndex(e.point).takeIf { it >= 0 } ?: return
                val m = model[i]
                if (m.path.endsWith(".so")) onOpenInDisasm(m) else onViewMemory(m.base)
            }
            private fun popup(e: java.awt.event.MouseEvent) {
                if (!e.isPopupTrigger) return
                val i = list.locationToIndex(e.point).takeIf { it >= 0 } ?: return
                list.selectedIndex = i
                val m = model[i]
                javax.swing.JPopupMenu().apply {
                    if (m.path.endsWith(".so")) add(javax.swing.JMenuItem("Open in Disassembler").apply { addActionListener { onOpenInDisasm(m) } })
                    add(javax.swing.JMenuItem("View in Memory").apply { addActionListener { onViewMemory(m.base) } })
                }.show(list, e.x, e.y)
            }
        })

        bind(this, javax.swing.JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT,
            javax.swing.KeyStroke.getKeyStroke('F'.code, java.awt.Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx)) { openSearch() }
        bind(searchField, javax.swing.JComponent.WHEN_FOCUSED, javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ESCAPE, 0)) { closeSearch() }
        bind(searchField, javax.swing.JComponent.WHEN_FOCUSED, javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_DOWN, 0)) { focusResults() }
        bind(searchField, javax.swing.JComponent.WHEN_FOCUSED, javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ENTER, 0)) { focusResults() }
        searchField.document.addDocumentListener(object : javax.swing.event.DocumentListener {
            override fun insertUpdate(e: javax.swing.event.DocumentEvent) = applyFilter()
            override fun removeUpdate(e: javax.swing.event.DocumentEvent) = applyFilter()
            override fun changedUpdate(e: javax.swing.event.DocumentEvent) = applyFilter()
        })
    }

    private fun bind(c: javax.swing.JComponent, condition: Int, key: javax.swing.KeyStroke, action: () -> Unit) {
        val name = key.toString()
        c.getInputMap(condition).put(key, name)
        c.actionMap.put(name, object : javax.swing.AbstractAction() {
            override fun actionPerformed(e: java.awt.event.ActionEvent?) = action()
        })
    }

    private fun openSearch() {
        searchBar.isVisible = true
        revalidate()
        searchField.requestFocusInWindow()
        searchField.selectAll()
    }

    private fun closeSearch() {
        searchBar.isVisible = false
        searchField.text = ""
        applyFilter()
        revalidate()
        list.requestFocusInWindow()
    }

    private fun focusResults() {
        if (model.size() > 0) { list.selectedIndex = 0; list.ensureIndexIsVisible(0); list.requestFocusInWindow() }
    }

    private fun applyFilter() {
        val q = searchField.text.trim().lowercase()
        model.clear()
        all.filter { q.isEmpty() || q in it.name.lowercase() || q in it.path.lowercase() || q in "%016x".format(it.base) }
            .forEach { model.addElement(it) }
    }

    fun set(items: List<LoadedModule>) {
        all.clear()
        all.addAll(items.sortedBy { it.name })
        applyFilter()
    }
    fun clear() { all.clear(); model.clear() }

    override fun isWrappableInScrollpane() = false
    override fun getPersistentID() = "debug-libraries"
    override fun getTabText() = "Libraries"
}

class DebugMemoryView : JPanel(BorderLayout()), Dockable {
    var readMem: (Long, Int) -> ByteArray? = { _, _ -> null }
    var addrResolver: (String) -> Long? = ::numeric
    private val pageSize = 2048
    private var baseAddr = 0L
    private val addrField = javax.swing.JTextField(20)
    private val status = JLabel(" ")
    private val area = org.exbin.bined.swing.basic.CodeArea().apply {
        editMode = org.exbin.bined.EditMode.READ_ONLY
        setCodeFont(SyntaxThemes.editorFont())
        resetColors()
    }

    init {
        Docking.registerDockable(this)
        val top = JPanel(java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 4, 4))
        top.add(JLabel("Address:"))
        top.add(addrField)
        addrField.toolTipText = "0x… / decimal, or module+offset (e.g. libjdexdbg.so+0x1768)"
        addrField.addActionListener { goInput() }
        top.add(button("Go") { goInput() })
        top.add(button("◀") { page(-pageSize.toLong()) })
        top.add(button("▶") { page(pageSize.toLong()) })
        top.add(button("⟳") { refresh() })
        add(top, BorderLayout.NORTH)
        add(area, BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
        area.addMouseListener(object : java.awt.event.MouseAdapter() {
            override fun mouseReleased(e: java.awt.event.MouseEvent) = SwingUtilities.invokeLater { showCaret() }
        })
    }

    fun go(addr: Long) {
        baseAddr = addr
        addrField.text = "0x" + addr.toULong().toString(16)
        refresh()
    }

    fun refresh() {
        if (baseAddr == 0L) return
        val bytes = readPage(baseAddr, pageSize)
        area.setContentData(org.exbin.auxiliary.binary_data.array.ByteArrayData(bytes))
        status.text = if (bytes.isEmpty()) " 0x${baseAddr.toULong().toString(16)}: <unreadable>"
        else " base 0x${baseAddr.toULong().toString(16)} · ${bytes.size} bytes"
    }

    fun clear() {
        area.setContentData(org.exbin.auxiliary.binary_data.array.ByteArrayData(ByteArray(0)))
        baseAddr = 0L; addrField.text = ""; status.text = " "
    }

    private fun goInput() {
        val a = addrResolver(addrField.text)
        if (a == null) { status.text = " ? cannot resolve '${addrField.text.trim()}'" } else go(a)
    }

    private fun page(delta: Long) {
        if (baseAddr == 0L) return
        go((baseAddr + delta).coerceAtLeast(0))
    }

    private fun showCaret() {
        if (baseAddr == 0L) return
        val pos = runCatching { area.dataPosition }.getOrDefault(0L)
        status.text = " 0x${(baseAddr + pos).toString(16)}  (base +0x${pos.toString(16)})"
    }

    private fun button(text: String, action: () -> Unit) = javax.swing.JButton(text).apply {
        margin = java.awt.Insets(2, 6, 2, 6); addActionListener { action() }
    }

    private fun readPage(addr: Long, total: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        var off = 0
        while (off < total) {
            val n = minOf(512, total - off)
            val b = readMem(addr + off, n) ?: break
            out.write(b)
            if (b.size < n) break
            off += n
        }
        return out.toByteArray()
    }

    private fun numeric(s: String): Long? {
        val t = s.trim()
        return t.removePrefix("0x").removePrefix("0X").toULongOrNull(16)?.toLong() ?: t.toLongOrNull()
    }

    override fun isWrappableInScrollpane() = false
    override fun getPersistentID() = "debug-memory"
    override fun getTabText() = "Memory"
}

class DebugFramesView(private val onSelect: (Int) -> Unit) : JPanel(BorderLayout()), Dockable {
    private val model = DefaultListModel<Frame>()
    private val list = JList(model).apply {
        selectionMode = ListSelectionModel.SINGLE_SELECTION
        cellRenderer = listRenderer<Frame> { f ->
            val loc = f.location as? DebugLocation.Dex
            val at = if (loc != null) "  @%04x".format(loc.dexPc) else ""
            "${if (f.index == 0) "▶ " else "   "}${f.description}$at"
        }
    }

    init {
        Docking.registerDockable(this)
        add(JScrollPane(list), BorderLayout.CENTER)
        list.addListSelectionListener {
            if (!it.valueIsAdjusting && list.selectedIndex >= 0) onSelect(list.selectedIndex)
        }
    }

    fun set(items: List<Frame>) { model.clear(); items.forEach { model.addElement(it) } }
    fun select(index: Int) { if (index in 0 until model.size()) list.selectedIndex = index }
    fun count() = model.size()
    fun locationAt(index: Int): DebugLocation? = if (index in 0 until model.size()) model[index].location else null
    fun clear() = model.clear()

    override fun isWrappableInScrollpane() = false
    override fun getPersistentID() = "debug-frames"
    override fun getTabText() = "Call Stack"
}

class DebugVarsView(
    private val childrenFor: (Long) -> List<DebugVar>,
    private val onSetValue: (String, String) -> Boolean = { _, _ -> false },
    private val onAfterSet: () -> Unit = {},
    private val isPointer: (Long) -> Boolean = { false },
    private val onViewMemory: (Long) -> Unit = {},
) : JPanel(BorderLayout()), Dockable {
    private val root = DefaultMutableTreeNode()
    private val treeModel = DefaultTreeModel(root)
    private val tree = JTree(treeModel).apply {
        isRootVisible = false
        showsRootHandles = true
        selectionModel.selectionMode = TreeSelectionModel.SINGLE_TREE_SELECTION
        cellRenderer = VarRenderer()
    }
    private val expander = java.util.concurrent.Executors.newSingleThreadExecutor {
        java.lang.Thread(it, "jdex-debug-expand").apply { isDaemon = true }
    }

    init {
        Docking.registerDockable(this)
        add(JScrollPane(tree), BorderLayout.CENTER)
        tree.addTreeWillExpandListener(object : TreeWillExpandListener {
            override fun treeWillExpand(event: TreeExpansionEvent) {
                val node = event.path.lastPathComponent as? DefaultMutableTreeNode ?: return
                val v = node.userObject as? DebugVar ?: return
                if (node.childCount == 1 && (node.firstChild as DefaultMutableTreeNode).userObject === PLACEHOLDER) {
                    node.removeAllChildren()
                    node.add(DefaultMutableTreeNode("loading…"))
                    treeModel.nodeStructureChanged(node)
                    val ref = v.ref
                    expander.submit {
                        val kids = childrenFor(ref)
                        SwingUtilities.invokeLater {
                            if (node.root !== root) return@invokeLater
                            node.removeAllChildren()
                            kids.forEach { node.add(nodeFor(it)) }
                            treeModel.nodeStructureChanged(node)
                        }
                    }
                }
            }

            override fun treeWillCollapse(event: TreeExpansionEvent) {}
        })
        tree.addMouseListener(object : java.awt.event.MouseAdapter() {
            override fun mousePressed(e: java.awt.event.MouseEvent) = maybePopup(e)
            override fun mouseReleased(e: java.awt.event.MouseEvent) = maybePopup(e)
            override fun mouseClicked(e: java.awt.event.MouseEvent) {
                if (e.clickCount != 2 || e.isPopupTrigger) return
                val v = (tree.getPathForLocation(e.x, e.y)?.lastPathComponent as? DefaultMutableTreeNode)?.userObject as? DebugVar ?: return
                if (v.editKey != null) { editNode(v); e.consume() }
            }
        })
        tree.inputMap.put(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_H, java.awt.event.InputEvent.ALT_DOWN_MASK), "toggleHex")
        tree.actionMap.put("toggleHex", object : javax.swing.AbstractAction() {
            override fun actionPerformed(e: java.awt.event.ActionEvent?) = toggleHex()
        })
    }

    private fun maybePopup(e: java.awt.event.MouseEvent) {
        if (!e.isPopupTrigger) return
        val path = tree.getPathForLocation(e.x, e.y)
        if (path != null) tree.selectionPath = path
        val v = (path?.lastPathComponent as? DefaultMutableTreeNode)?.userObject as? DebugVar
        javax.swing.JPopupMenu().apply {
            if (v?.editKey != null) {
                add(javax.swing.JMenuItem("Set value…").apply { addActionListener { editNode(v) } })
                addSeparator()
            }
            v?.let { memAddr(it) }?.let { addr ->
                add(javax.swing.JMenuItem("View in Memory").apply { addActionListener { onViewMemory(addr) } })
                addSeparator()
            }
            add(javax.swing.JCheckBoxMenuItem("Hexadecimal", io.github.nitanmarcel.jdex.debug.DebugFormat.hex).apply {
                addActionListener { toggleHex() }
            })
        }.show(tree, e.x, e.y)
    }

    private fun memAddr(v: DebugVar): Long? {
        val tok = (v.editValue ?: v.value).trim().takeWhile { it != ' ' }
        if (!tok.startsWith("0x")) return null
        val a = tok.removePrefix("0x").toULongOrNull(16)?.toLong() ?: return null
        return a.takeIf { isPointer(it) }
    }

    private fun editNode(v: DebugVar) {
        val key = v.editKey ?: return
        val input = javax.swing.JOptionPane.showInputDialog(this, "New value for ${v.name}:", v.editValue ?: v.value) ?: return
        if (onSetValue(key, input)) onAfterSet()
        else javax.swing.JOptionPane.showMessageDialog(this, "Could not set ${v.name}", "Set value", javax.swing.JOptionPane.ERROR_MESSAGE)
    }

    private fun toggleHex() {
        io.github.nitanmarcel.jdex.debug.DebugFormat.hex = !io.github.nitanmarcel.jdex.debug.DebugFormat.hex
        onAfterSet()
    }

    private var changedNames: Set<String> = emptySet()

    fun set(vars: List<DebugVar>, changed: Set<String> = emptySet()) {
        changedNames = changed
        root.removeAllChildren()
        vars.forEach { root.add(nodeFor(it)) }
        treeModel.nodeStructureChanged(root)
    }

    fun clear() {
        changedNames = emptySet()
        root.removeAllChildren()
        treeModel.nodeStructureChanged(root)
    }

    private fun nodeFor(v: DebugVar): DefaultMutableTreeNode {
        val node = DefaultMutableTreeNode(v)
        if (v.ref != 0L) node.add(DefaultMutableTreeNode(PLACEHOLDER))
        return node
    }

    private inner class VarRenderer : DefaultTreeCellRenderer() {
        private var base: Font? = null

        override fun getTreeCellRendererComponent(
            tree: JTree?, value: Any?, sel: Boolean, expanded: Boolean, leaf: Boolean, row: Int, focus: Boolean,
        ): Component {
            val c = super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, focus)
            if (base == null) base = font
            val v = ((value as? DefaultMutableTreeNode)?.userObject as? DebugVar) ?: return c
            text = "${v.name} = ${escapeForLine(v.value)}"
            val typeTip = if (v.id != 0L) "${v.type} (id=${v.id})" else v.type
            toolTipText = if (v.editKey != null) "$typeTip · double-click to edit" else typeTip
            val isChanged = v.name in changedNames
            font = base?.deriveFont(if (!v.available) Font.ITALIC else if (isChanged) Font.BOLD else Font.PLAIN)
            if (!sel) foreground = when {
                isChanged -> UiColors.warning()
                !v.available -> UiColors.disabled()
                else -> foreground
            }
            icon = if (v.editKey != null) Icons.EDIT else null
            return c
        }
    }

    override fun isWrappableInScrollpane() = false
    override fun getPersistentID() = "debug-variables"
    override fun getTabText() = "Variables"

    companion object {
        private val PLACEHOLDER = Any()
    }
}

internal fun escapeForLine(s: String): String =
    s.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")

private fun <T> listRenderer(text: (T) -> String) = object : DefaultListCellRenderer() {
    override fun getListCellRendererComponent(
        list: JList<*>?, value: Any?, index: Int, selected: Boolean, focus: Boolean,
    ): Component {
        val c = super.getListCellRendererComponent(list, value, index, selected, focus)
        @Suppress("UNCHECKED_CAST")
        (value as? T)?.let { (c as JLabel).text = text(it) }
        return c
    }
}
