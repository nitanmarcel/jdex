package io.github.nitanmarcel.jdex.ui

import com.formdev.flatlaf.extras.components.FlatTriStateCheckBox
import io.github.andrewauclair.moderndocking.DockingRegion
import io.github.andrewauclair.moderndocking.app.AppState
import io.github.andrewauclair.moderndocking.Dockable
import io.github.andrewauclair.moderndocking.app.Docking
import io.github.andrewauclair.moderndocking.app.RootDockingPanel
import io.github.andrewauclair.moderndocking.app.WindowLayoutBuilder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.swing.Swing
import kotlinx.coroutines.withContext
import io.github.nitanmarcel.jdex.RecentFiles
import io.github.nitanmarcel.jdex.debug.Breakpoint
import io.github.nitanmarcel.jdex.debug.DebugDevice
import io.github.nitanmarcel.jdex.debug.DebugLocation
import io.github.nitanmarcel.jdex.debug.DebugProcess
import io.github.nitanmarcel.jdex.debug.DebugSession
import io.github.nitanmarcel.jdex.debug.DebugState
import io.github.nitanmarcel.jdex.debug.DebugVar
import io.github.nitanmarcel.jdex.debug.ArtSession
import io.github.nitanmarcel.jdex.debug.NativeSession
import io.github.nitanmarcel.jdex.debug.MixedSession
import io.github.nitanmarcel.jdex.debug.NativeDebug
import io.github.nitanmarcel.jdex.debug.DeviceBridge
import io.github.nitanmarcel.jdex.debug.RegisterMeta
import io.github.nitanmarcel.jdex.project.DebugControl
import io.github.nitanmarcel.jdex.disasm.CapstoneDisassembler
import io.github.nitanmarcel.jdex.disasm.JniName
import io.github.nitanmarcel.jdex.disasm.KeystoneAssembler
import io.github.nitanmarcel.jdex.project.ApkSession
import io.github.nitanmarcel.jdex.project.BinaryContent
import io.github.nitanmarcel.jdex.project.SyncTarget
import io.github.nitanmarcel.jdex.project.CodeContent
import io.github.nitanmarcel.jdex.project.Content
import io.github.nitanmarcel.jdex.project.NativeContent
import io.github.nitanmarcel.jdex.project.Syntax
import io.github.nitanmarcel.jdex.project.Dex
import io.github.nitanmarcel.jdex.project.DexPatch
import io.github.nitanmarcel.jdex.project.HMembers
import io.github.nitanmarcel.jdex.project.MalformedDex
import io.github.nitanmarcel.jdex.project.BreakpointStore
import io.github.nitanmarcel.jdex.project.NoBookmarks
import io.github.nitanmarcel.jdex.project.NoBreakpoints
import io.github.nitanmarcel.jdex.project.NoComments
import io.github.nitanmarcel.jdex.project.NoDexStore
import io.github.nitanmarcel.jdex.project.NoRenames
import io.github.nitanmarcel.jdex.project.Project
import io.github.nitanmarcel.jdex.project.Renames
import io.github.nitanmarcel.jdex.project.ScriptApi
import io.github.nitanmarcel.jdex.project.ScriptUi
import io.github.nitanmarcel.jdex.project.TextContent
import java.awt.Dimension
import java.awt.Toolkit
import java.awt.event.KeyEvent
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.logging.Level
import java.util.logging.Logger
import java.awt.Color
import javax.swing.ButtonGroup
import javax.swing.JColorChooser
import javax.swing.JFileChooser
import javax.swing.JOptionPane
import javax.swing.SwingUtilities
import javax.swing.JFrame
import javax.swing.JMenu
import javax.swing.JMenuBar
import javax.swing.JMenuItem
import javax.swing.JRadioButtonMenuItem
import javax.swing.KeyStroke
import javax.swing.filechooser.FileNameExtensionFilter

class MainWindow : JFrame("jdex") {

    private val log = Logger.getLogger("jdex")
    private val recentFiles = RecentFiles()
    private val recentMenu = JMenu("Open Recent")
    private val saveItem = JMenuItem("Save")
    private val saveAsItem = JMenuItem("Save As…")
    private var projectName: String? = null
    private val scope = CoroutineScope(Dispatchers.Swing)
    private val openTabs = LinkedHashMap<String, EditorTab>()
    private val nativeViews = ArrayList<Triple<EditorTab, VirtualCodeView, io.github.nitanmarcel.jdex.project.LineSource>>()
    private lateinit var explorer: FilesPanel
    private lateinit var hierarchy: HierarchyPanel
    private var project: Project? = null
    private var session: ApkSession? = null
    private val renames = Renames()
    private var javaTab: EditorTab? = null
    private var pseudoTab: EditorTab? = null
    private var javaModes: JavaModesView? = null
    private var javaClass: String? = null
    private var syncState = FlatTriStateCheckBox.State.UNSELECTED
    private var bytecodeTab: EditorTab? = null
    private var bytecodeView: VirtualCodeView? = null
    private var activeCodeView: VirtualCodeView? = null
    private val codeActionItems = ArrayList<Pair<JMenuItem, VirtualCodeView.CodeAction>>()
    private var dexBytecodeTab: EditorTab? = null
    private var dexBytecodeView: VirtualCodeView? = null
    private var hierarchyClasses: List<io.github.nitanmarcel.jdex.project.HClass> = emptyList()
    private var hierarchyNativeView: VirtualCodeView? = null
    private val nativeViewByBase = HashMap<String, Pair<EditorTab, VirtualCodeView>>()
    private val nativeAnalyses = HashMap<String, io.github.nitanmarcel.jdex.disasm.NativeJni.Analysis>()
    private val nativeExports = HashMap<String, Map<String, Long>>()
    private val nativeSymbols = HashMap<String, List<io.github.nitanmarcel.jdex.disasm.ElfSymbol>>()
    private val nativeArch = HashMap<String, io.github.nitanmarcel.jdex.disasm.ElfArch>()
    private lateinit var scripting: ScriptPanel
    private lateinit var debugBar: DebugToolBar
    private val statusBar = StatusBar()
    private lateinit var debugViews: DebugViews
    @Volatile private var debugSession: DebugSession? = null
    private var attaching = false
    private var enablingNative = false
    private var attachedDevice: DebugDevice? = null
    private var attachedProc: DebugProcess? = null
    private val debugPrefs = java.util.prefs.Preferences.userRoot().node("jdex/ui/debug")

    private val debugControl = object : DebugControl {
        override fun attach(serial: String, pid: Int): Boolean {
            if (debugSession != null) { log.warning("Already attached; detach first"); return false }
            val dev = runCatching { DeviceBridge.devices() }.getOrNull()?.firstOrNull { it.serial == serial }
                ?: DebugDevice(serial, serial, true)
            val s = runCatching { ArtSession.attach(dev, DeviceBridge.androidRelease(dev.serial), pid, ::registerMetaFor) }.getOrElse { e ->
                log.warning("Attach failed: ${e.message}"); return false
            }
            onEdt {
                debugSession = s
                s.onStateChange { st -> SwingUtilities.invokeLater { onDebugState(st) } }
                breakpointStore().breakpoints().forEach { bp -> s.addBreakpoint(Breakpoint.Dex(bp.descriptor, bp.dexPc)) }
                s.setExceptionBreak(false, debugBar.exceptionBreakEnabled())
                debugBar.setState(s.state)
                showDebugViews()
            }
            return true
        }

        override fun detach() = onEdt { debugSession?.detach() ?: Unit }
        override fun resume() = onEdt { debugSession?.resume() ?: Unit }
        override fun pause() = onEdt { debugSession?.pause() ?: Unit }
        override fun stepInto() = onEdt { debugSession?.stepInto() ?: Unit }
        override fun stepOver() = onEdt { debugSession?.stepOver() ?: Unit }
        override fun stepOut() = onEdt { debugSession?.stepOut() ?: Unit }

        override fun setBreakpoint(descriptor: String, dexPc: Int): Unit = onEdt {
            onBreakpointToggled(descriptor, dexPc, true)
            dexBytecodeView?.markBreakpoints(breakpointStore().breakpoints().map { it.descriptor to it.dexPc })
            Unit
        }

        override fun clearBreakpoint(descriptor: String, dexPc: Int): Unit = onEdt {
            onBreakpointToggled(descriptor, dexPc, false)
            dexBytecodeView?.markBreakpoints(breakpointStore().breakpoints().map { it.descriptor to it.dexPc })
            Unit
        }

        override fun state(): String = when (debugSession?.state) {
            null, DebugState.Detached -> "detached"
            DebugState.Running -> "running"
            is DebugState.Stopped -> "stopped"
        }

        override fun frames(): List<Map<String, Any?>> = debugSession?.frames().orEmpty().map { f ->
            val loc = f.location as? DebugLocation.Dex
            mapOf("index" to f.index, "description" to f.description, "descriptor" to loc?.methodDescriptor, "dex_pc" to loc?.dexPc)
        }

        override fun variables(frameIndex: Int): List<Map<String, Any?>> =
            debugSession?.variables(frameIndex).orEmpty().map { mapOf("name" to it.name, "type" to it.type, "value" to it.value) }

        override fun readMemory(address: Long, length: Int): ByteArray? = debugSession?.readMemory(address, length)
        override fun writeMemory(address: Long, bytes: ByteArray): Boolean = debugSession?.writeMemory(address, bytes) ?: false
        override fun runtimeAddr(nativeId: String, vaddr: Long): Long? = debugSession?.runtimeAddr(nativeId, vaddr)

        override fun patchNative(nativeId: String, vaddr: Long, asm: String): Boolean {
            val s = debugSession ?: return false
            val rt = s.runtimeAddr(nativeId, vaddr) ?: return false
            val arch = nativeArch[nativeId] ?: return false
            val bytes = KeystoneAssembler.assemble(asm, rt, arch).getOrElse { log.warning("Patch assemble: ${it.message}"); return false }
            return s.writeMemory(rt, bytes)
        }
    }

    init {
        defaultCloseOperation = DO_NOTHING_ON_CLOSE
        size = Dimension(1000, 700)
        setLocationRelativeTo(null)

        addWindowListener(object : WindowAdapter() {
            override fun windowClosing(e: WindowEvent) {
                if (!confirmDiscardChanges()) return
                runCatching { debugSession?.detach() }
                runCatching { clearEditors() }
                runCatching { AppState.persist() }
                runCatching { scope.cancel() }
                runCatching { scripting.close() }
                runCatching { session?.close() }
                runCatching { project?.close() }
                kotlin.system.exitProcess(0)
            }
        })

        rootPane.putClientProperty("JRootPane.titleBarShowTitle", false)
        Docking.initialize(this)
        debugBar = DebugToolBar(
            onAttach = { dev, proc -> attachDebugger(dev, proc) },
            onResume = { debugSession?.resume() },
            onPause = { debugSession?.pause() },
            onStepInto = { debugSession?.stepInto() },
            onStepOver = { debugSession?.stepOver() },
            onStepOut = { debugSession?.stepOut() },
            onDetach = { debugSession?.detach() },
            onExceptionBreak = { enabled -> debugSession?.setExceptionBreak(false, enabled) },
            packageHint = { session?.appPackage },
            log = { log.warning(it) },
        )
        add(RootDockingPanel(this))
        add(statusBar, java.awt.BorderLayout.SOUTH)
        debugViews = DebugViews(
            onFrameSelected = { _, location, vars -> revealDebugLocation(location); updateInlineValues(location, vars) },
            onSetValue = { key, text -> debugSession?.setValue(key, text) ?: false },
            onOpenModule = ::openDeviceModule,
            isPointer = { debugSession?.looksLikePointer(it) ?: false },
        )
        debugViews.memory.readMem = { a, n -> debugSession?.readMemory(a, n) }
        debugViews.memory.addrResolver = ::resolveMemoryAddress

        val editors = EditorAnchor()
        explorer = FilesPanel(::openView, onFindUsages = ::findInBytecode, onOpenDex = ::openDexEditor)
        hierarchy = HierarchyPanel(
            onClass = { rawName -> navigateBytecode { it.revealClass(rawName) } },
            onMethod = { rawName, shortId -> navigateBytecode { it.revealMethod(rawName, shortId) } },
            onField = { rawName, name -> navigateBytecode { it.revealField(rawName, name) } },
            onDecompile = { rawName -> showJava(rawName) },
            loadMembers = { rawName -> session?.members(rawName) ?: HMembers(emptyList(), emptyList(), emptyMap(), emptyList()) },
            renames = renames,
            onRenamed = { renamesChanged() },
        )
        val logger = LoggerPanel()
        scripting = ScriptPanel(ScriptApi(
            session = { session },
            renameStore = { project ?: NoRenames },
            onChanged = { SwingUtilities.invokeLater { renamesChanged() } },
            dexStore = { project ?: NoDexStore },
            onReanalyze = { SwingUtilities.invokeLater { analyze() } },
            fileImporter = { name, bytes -> SwingUtilities.invokeLater { importFile(name, bytes) } },
            debug = debugControl,
            ui = object : ScriptUi {
                override fun message(text: String, error: Boolean) = SwingUtilities.invokeLater {
                    JOptionPane.showMessageDialog(
                        this@MainWindow, text, "Script",
                        if (error) JOptionPane.ERROR_MESSAGE else JOptionPane.INFORMATION_MESSAGE,
                    )
                }

                override fun input(prompt: String, default: String): String? =
                    onEdt { JOptionPane.showInputDialog(this@MainWindow, prompt, default) }

                override fun confirm(text: String): Boolean = onEdt {
                    JOptionPane.showConfirmDialog(this@MainWindow, text, "Script", JOptionPane.YES_NO_OPTION) ==
                        JOptionPane.YES_OPTION
                }

                override fun gotoOffset(offset: Long) =
                    SwingUtilities.invokeLater { navigateBytecode { it.revealOffset(offset) } }

                override fun open(desc: String) = SwingUtilities.invokeLater { openDescriptor(desc) }
            },
        ))

        jMenuBar = createMenuBar(editors, explorer, hierarchy, logger, scripting)
        updateRecentMenu()

        AppState.setAutoPersist(false)
        AppState.setPersistFile(File(System.getProperty("java.io.tmpdir"), "jdex-layout.xml"))

        AppState.setDefaultApplicationLayout(
            WindowLayoutBuilder("project_explorer")
                .dock("editors", "project_explorer", DockingRegion.EAST, 0.8)
                .dock("hierarchy", "project_explorer", DockingRegion.SOUTH, 0.5)
                .dockToRoot("logger", DockingRegion.SOUTH, 0.25)
                .dock("scripting", "logger", DockingRegion.CENTER)
                .buildApplicationLayout()
        )

        runCatching { AppState.restore() }
            .onFailure { log.warning("Discarded incompatible saved layout") }

        if (Docking.isDocked(logger)) Docking.bringToFront(logger)
    }

    private fun codeItem(action: VirtualCodeView.CodeAction): JMenuItem {
        val item = JMenuItem(action.label)
        item.addActionListener { activeCodeView?.takeIf { it.isShowing }?.perform(action) }
        codeActionItems.add(item to action)
        return item
    }

    private fun refreshCodeActions() {
        val v = activeCodeView?.takeIf { it.isShowing }
        codeActionItems.forEach { (item, action) ->
            item.isVisible = v == null || v.applies(action)
            item.isEnabled = v != null && v.canDo(action)
        }
    }

    private fun JMenu.onOpen(block: () -> Unit) = addMenuListener(object : javax.swing.event.MenuListener {
        override fun menuSelected(e: javax.swing.event.MenuEvent) = block()
        override fun menuDeselected(e: javax.swing.event.MenuEvent) {}
        override fun menuCanceled(e: javax.swing.event.MenuEvent) {}
    })

    private fun createMenuBar(editors: EditorAnchor, explorer: FilesPanel, hierarchy: HierarchyPanel, logger: LoggerPanel, scripting: ScriptPanel) = JMenuBar().apply {
        add(JMenu("File").apply {
            add(JMenuItem("Open…").apply {
                icon = Icons.FOLDER_OPEN
                accelerator = shortcut(KeyEvent.VK_O)
                addActionListener { openWithChooser() }
            })
            add(JMenuItem("Import file…").apply { icon = Icons.FILE_BINARY; addActionListener { importFileChooser() } })
            add(JMenuItem("Run Script…").apply { icon = Icons.RUN; addActionListener { runScript() } })
            add(recentMenu)
            addSeparator()
            add(saveItem.apply {
                icon = Icons.SAVE
                accelerator = shortcut(KeyEvent.VK_S)
                isEnabled = false
                addActionListener { saveProject() }
            })
            add(saveAsItem.apply {
                accelerator = KeyStroke.getKeyStroke(KeyEvent.VK_S, Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx or KeyEvent.SHIFT_DOWN_MASK)
                isEnabled = false
                addActionListener { saveProjectAs() }
            })
            addSeparator()
            add(JMenuItem("Close").apply {
                accelerator = shortcut(KeyEvent.VK_W)
                addActionListener {
                    this@MainWindow.dispatchEvent(WindowEvent(this@MainWindow, WindowEvent.WINDOW_CLOSING))
                }
            })
        })
        add(JMenu("Search").apply {
            add(codeItem(VirtualCodeView.CodeAction.FIND))
            add(codeItem(VirtualCodeView.CodeAction.FIND_ACTION))
            onOpen { refreshCodeActions() }
        })
        add(JMenu("Navigate").apply {
            add(codeItem(VirtualCodeView.CodeAction.GOTO_ADDRESS))
            add(codeItem(VirtualCodeView.CodeAction.GOTO_SYMBOL))
            add(codeItem(VirtualCodeView.CodeAction.GOTO_MAIN))
            addSeparator()
            add(codeItem(VirtualCodeView.CodeAction.BOOKMARKS))
            onOpen { refreshCodeActions() }
        })
        add(JMenu("View").apply {
            add(viewItem("Project Explorer", explorer) {
                Docking.dock(explorer, this@MainWindow, DockingRegion.WEST, 0.2)
            })
            add(viewItem("Hierarchy", hierarchy) {
                if (Docking.isDocked(explorer)) Docking.dock(hierarchy, explorer, DockingRegion.SOUTH, 0.5)
                else Docking.dock(hierarchy, this@MainWindow, DockingRegion.WEST, 0.2)
            })
            add(viewItem("Bytecode", editors) {
                if (Docking.isDocked(explorer)) Docking.dock(editors, explorer, DockingRegion.EAST, 0.8)
                else Docking.dock(editors, this@MainWindow, DockingRegion.EAST, 0.8)
            })
            add(viewItem("Logger", logger) {
                Docking.dock(logger, this@MainWindow, DockingRegion.SOUTH, 0.25)
            })
            add(viewItem("Scripting", scripting) {
                if (Docking.isDocked(logger)) Docking.dock(scripting, logger, DockingRegion.CENTER)
                else Docking.dock(scripting, this@MainWindow, DockingRegion.SOUTH, 0.25)
            })
            val subviews = JMenu("Subviews").apply {
                add(codeItem(VirtualCodeView.CodeAction.SEGMENTS))
                add(codeItem(VirtualCodeView.CodeAction.STRINGS))
                addSeparator()
                add(codeItem(VirtualCodeView.CodeAction.EXPORTS))
                add(codeItem(VirtualCodeView.CodeAction.IMPORTS))
                add(codeItem(VirtualCodeView.CodeAction.CONSTRUCTORS))
            }
            addSeparator()
            add(subviews)
            onOpen {
                refreshCodeActions()
                val v = activeCodeView?.takeIf { it.isShowing }
                subviews.isVisible = v == null || v.applies(VirtualCodeView.CodeAction.SEGMENTS)
            }
        })
        add(JMenu("Debug").apply {
            add(viewItem("Threads", debugViews.threads) { dockDebugView(debugViews.threads) })
            add(viewItem("Call Stack", debugViews.frames) { dockDebugView(debugViews.frames) })
            add(viewItem("Variables", debugViews.variables) { dockDebugView(debugViews.variables) })
            add(viewItem("Libraries", debugViews.libraries) { dockDebugView(debugViews.libraries) })
            add(viewItem("Memory", debugViews.memory) { dockDebugView(debugViews.memory) })
            val bpSep = javax.swing.JPopupMenu.Separator()
            add(bpSep)
            add(codeItem(VirtualCodeView.CodeAction.BREAKPOINTS))
            addSeparator()
            add(JMenuItem("Debugger Settings…").apply { addActionListener { DebugConfigDialog.show(this@MainWindow, "", true) } })
            onOpen {
                refreshCodeActions()
                val v = activeCodeView?.takeIf { it.isShowing }
                bpSep.isVisible = v == null || v.applies(VirtualCodeView.CodeAction.BREAKPOINTS)
            }
        })
        add(JMenu("Appearance").apply {
            add(JMenu("Theme").apply {
                val group = ButtonGroup()
                fun fill(menu: JMenu, defs: List<Themes.Def>) {
                    defs.sortedBy { it.label.lowercase() }.forEach { def ->
                        menu.add(JRadioButtonMenuItem(def.label, def.id == Themes.currentId).also {
                            group.add(it)
                            it.addActionListener { Themes.select(def.id) }
                        })
                    }
                }
                add(JMenu("Light").apply { fill(this, Themes.all.filter { !it.dark }) })
                add(JMenu("Dark").apply { fill(this, Themes.all.filter { it.dark }) })
            })
            addSeparator()
            add(JMenuItem("Theme Editor…").apply { icon = Icons.SETTINGS; addActionListener { ThemeEditor.open(this@MainWindow) } })
        })
        add(JMenu("Help").apply {
            add(JMenuItem("About jdex…").apply { addActionListener { showAbout() } })
        })
        add(javax.swing.Box.createHorizontalStrut(24))
        add(debugBar)
    }

    private fun showAbout() {
        val text = buildString {
            appendLine("Apk disassembler and decompiler")
            appendLine("https://github.com/jdexorg/jdex")
            appendLine("Licensed under the GNU General Public License v2")
            appendLine()
            appendLine("Third-party software used by jdex:")
            appendLine()
            appendLine("Libraries")
            appendLine("- jadx, jadx jdwp (Apache License 2.0)")
            appendLine("- FlatLaf (Apache License 2.0)")
            appendLine("- RSyntaxTextArea (modified BSD, BSD-3-Clause)")
            appendLine("- Modern Docking (MIT License)")
            appendLine("- MigLayout (BSD License)")
            appendLine("- BinEd, binary_data (Apache License 2.0)")
            appendLine("- GraalPy / GraalVM (Universal Permissive License 1.0)")
            appendLine("- JNA (Apache License 2.0 or LGPL 2.1)")
            appendLine("- Android apksig, ddmlib (Apache License 2.0)")
            appendLine("- SQLite JDBC (Apache License 2.0)")
            appendLine("- kotlinx.coroutines, Kotlin stdlib (Apache License 2.0)")
            appendLine()
            appendLine("Native")
            appendLine("- Capstone (BSD-3-Clause)")
            appendLine("- Keystone (GPL v2)")
            appendLine()
            appendLine("Fonts & icons")
            appendLine("- Inter, JetBrains Mono (SIL Open Font License 1.1)")
            appendLine("- VS Code Codicons (CC BY 4.0, (c) Microsoft Corporation)")
            appendLine()
            append("Java ${System.getProperty("java.version")}")
        }
        val area = javax.swing.JTextArea(text).apply {
            isEditable = false
            caretPosition = 0
            border = null
            background = javax.swing.UIManager.getColor("Panel.background")
        }
        val scroll = javax.swing.JScrollPane(area).apply { preferredSize = java.awt.Dimension(460, 320) }
        JOptionPane.showMessageDialog(this, scroll, "About jdex", JOptionPane.INFORMATION_MESSAGE)
    }

    private fun viewItem(text: String, dockable: Dockable, dock: () -> Unit) =
        JMenuItem(text).apply {
            addActionListener {
                if (Docking.isDocked(dockable)) Docking.bringToFront(dockable) else dock()
            }
        }

    private fun shortcut(keyCode: Int): KeyStroke =
        KeyStroke.getKeyStroke(keyCode, Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx)

    private fun openWithChooser() {
        val chooser = JFileChooser(recentFiles.all().firstOrNull()?.parentFile)
        chooser.fileFilter = FileNameExtensionFilter(
            "Supported files (*.apk, *.dex, *.jdexproj)", "apk", "dex", Project.EXTENSION
        )
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            open(chooser.selectedFile)
        }
    }

    private fun open(file: File) {
        if (!confirmDiscardChanges()) return
        val isProject = file.extension == Project.EXTENSION
        val sibling = if (!isProject) file.resolveSibling("${file.nameWithoutExtension}.${Project.EXTENSION}") else null
        var startFresh = false
        if (sibling != null && sibling.isFile) {
            val choice = JOptionPane.showOptionDialog(
                this,
                "A saved project was found for ${file.name}.\nLoad your previous work?",
                "Project Found",
                JOptionPane.YES_NO_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                arrayOf("Load Project", "Start Fresh", "Cancel"),
                "Load Project",
            )
            when (choice) {
                JOptionPane.YES_OPTION -> {}
                JOptionPane.NO_OPTION -> startFresh = true
                else -> return
            }
        }
        session?.close()
        session = null
        clearEditors()
        project?.close()
        renames.store = NoRenames
        val project = when {
            isProject -> Project.open(file)
            sibling != null && sibling.isFile && !startFresh -> Project.open(sibling)
            else -> Project.forInput(file)
        }
        this.project = project
        project.onDirty = { SwingUtilities.invokeLater { updateDirtyUi() } }
        renames.store = project
        renames.reload()
        recentFiles.add(file)
        updateRecentMenu()
        projectName = (project.input() ?: file).name
        updateDirtyUi()
        log.info(project.file?.let { "Opened project ${it.absolutePath}" } ?: "Opened ${projectName} (unsaved project)")
        analyze()
    }

    private fun updateDirtyUi() {
        val p = project
        val dirty = p?.isDirty() == true
        saveItem.isEnabled = dirty
        saveAsItem.isEnabled = p != null
        title = projectName?.let { "jdex — $it${if (dirty) " *" else ""}" } ?: "jdex"
    }

    private fun saveProject() {
        val p = project ?: return
        if (p.isInMemory()) { saveProjectAs(); return }
        runCatching { p.save() }.onFailure { log.log(Level.WARNING, "Save failed", it) }
        updateDirtyUi()
    }

    private fun saveProjectAs() {
        val p = project ?: return
        val input = p.input()
        val dir = p.file?.parentFile ?: input?.parentFile ?: recentFiles.all().firstOrNull()?.parentFile
        val chooser = JFileChooser(dir)
        chooser.fileFilter = FileNameExtensionFilter("jdex project (*.${Project.EXTENSION})", Project.EXTENSION)
        chooser.selectedFile = p.file ?: File(dir, "${input?.nameWithoutExtension ?: "project"}.${Project.EXTENSION}")
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return
        var target = chooser.selectedFile
        if (!target.name.endsWith(".${Project.EXTENSION}")) target = File(target.path + ".${Project.EXTENSION}")
        runCatching { p.saveAs(target) }.onFailure {
            log.log(Level.WARNING, "Save As failed", it)
            JOptionPane.showMessageDialog(this, "Could not save project:\n${it.message}", "Save As", JOptionPane.ERROR_MESSAGE)
            return
        }
        projectName = (p.input() ?: target).name
        recentFiles.add(target)
        updateRecentMenu()
        updateDirtyUi()
        log.info("Saved project as ${target.absolutePath}")
    }

    private fun confirmDiscardChanges(): Boolean {
        val p = project ?: return true
        if (!p.isDirty() && !p.isInMemory()) return true
        val name = projectName ?: p.file?.name ?: "project"
        val message = if (p.isInMemory()) "“$name” hasn't been saved to disk. Save it before closing?"
            else "Save changes to $name?"
        val choice = JOptionPane.showOptionDialog(
            this,
            message,
            "Unsaved Project",
            JOptionPane.YES_NO_CANCEL_OPTION,
            JOptionPane.WARNING_MESSAGE,
            null,
            arrayOf("Save", "Don't Save", "Cancel"),
            "Save",
        )
        return when (choice) {
            JOptionPane.YES_OPTION -> { saveProject(); !p.isDirty() && !p.isInMemory() }
            JOptionPane.NO_OPTION -> true
            else -> false
        }
    }

    private fun analyze() {
        val project = project ?: return
        val input = project.input() ?: return
        session?.close()
        session = null
        clearEditors()
        explorer.clear()
        hierarchy.clear()
        log.info("Analyzing ${input.name}…")
        scope.launch {
            runCatching { withContext(Dispatchers.Default) { ApkSession.load(input, project.file?.name ?: input.name, project, project) } }
                .onSuccess { loaded ->
                    session = loaded
                    explorer.show(loaded.root)
                    hierarchyClasses = loaded.topClasses()
                    hierarchyNativeView = null
                    hierarchy.show(hierarchyClasses)
                    val malformed = if (loaded.malformedDexes.isNotEmpty()) ", ${loaded.malformedDexes.size} malformed dex" else ""
                    log.info("Loaded ${input.name}: package=${loaded.appPackage ?: "n/a"}, certs=${loaded.certificateCount}$malformed")
                    explorer.bytecode()?.let { (id, title, load) -> openView(id, title, load) }
                }
                .onFailure { log.log(Level.SEVERE, "Failed to analyze ${input.name}: ${it.message}") }
        }
    }

    private fun openDexEditor(dex: MalformedDex) {
        DexEditorWindow(dex) { d, edited -> saveDex(d, edited) }.isVisible = true
    }

    private fun saveDex(dex: MalformedDex, edited: ByteArray) {
        val project = project ?: return
        project.savePatch(dex.sha, DexPatch.between(dex.source, edited))
        log.info("Saved DEX ${dex.name} — ${if (Dex.parseBroken(edited)) "still malformed" else "valid, merging"}")
        analyze()
    }

    private fun importFileChooser() {
        if (project == null) { log.warning("Open an APK or project before importing a file"); return }
        val chooser = JFileChooser(recentFiles.all().firstOrNull()?.parentFile)
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return
        val file = chooser.selectedFile
        val bytes = runCatching { file.readBytes() }.getOrElse { log.log(Level.SEVERE, "Cannot read ${file.name}: ${it.message}"); return }
        importFile(file.name, bytes)
    }

    private fun importFile(name: String, bytes: ByteArray) {
        val project = project ?: return run { log.warning("Open an APK or project before importing a file") }
        val elf = io.github.nitanmarcel.jdex.disasm.ElfFile.parse(bytes)
        if (elf == null && (Dex.looksLikeDex(bytes) || name.endsWith(".dex", ignoreCase = true))) {
            project.saveImported(DexPatch.sha256(bytes), name, bytes)
            log.info("Imported dex $name (${bytes.size} bytes)")
            analyze()
            return
        }
        val abi = elf?.let { ApkSession.abiFolder(it.arch) }
        val path = if (abi != null) "lib/$abi/$name" else "unknown/$name"
        if (nameExistsInProject(name)) {
            val ok = JOptionPane.showConfirmDialog(
                this, "$name already exists in this project. Override it?", "Import File",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE,
            ) == JOptionPane.OK_OPTION
            if (!ok) return
        }
        project.saveFile(path, bytes)
        log.info("Imported $path (${bytes.size} bytes)")
        analyze()
    }

    private fun nameExistsInProject(name: String): Boolean {
        val p = project ?: return false
        val fromApk = session?.entryNames()?.any { it.substringAfterLast('/') == name } == true
        val fromImported = p.importedFiles().any { it.path.substringAfterLast('/') == name }
        return fromApk || fromImported
    }

    private fun runScript() {
        val chooser = JFileChooser(recentFiles.all().firstOrNull()?.parentFile)
        chooser.fileFilter = FileNameExtensionFilter("Python scripts (*.py)", "py")
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return
        if (Docking.isDocked(scripting)) Docking.bringToFront(scripting)
        scripting.runFile(chooser.selectedFile)
    }

    private fun openView(id: String, title: String, load: () -> Content) {
        val tabId = "editor:$id"
        openTabs[tabId]?.let { tab ->
            if (Docking.isDocked(tab)) Docking.bringToFront(tab) else dockEditorTab(tab)
            return
        }
        scope.launch {
            val content = withContext(Dispatchers.Default) {
                runCatching { load() }.getOrElse { TextContent("Failed to load: ${it.message}") }
            }
            when (content) {
                is CodeContent -> openCode(tabId, title, content)
                is NativeContent -> openNative(tabId, title, content)
                else -> {
                    val tab = EditorTab(tabId, title, Editors.component(content), icon = Icons.of("file"))
                    openTabs[tabId] = tab
                    dockEditorTab(tab)
                }
            }
        }
    }

    private fun openText(title: String, text: String, syntax: Syntax, north: javax.swing.JComponent?): CodeTextArea {
        pseudoTab?.let {
            if (Docking.isDocked(it)) Docking.undock(it)
            Docking.deregisterDockable(it)
        }
        val area = CodeTextArea(text, syntax)
        val pane = SearchableTextPane(area)
        val content = if (north != null) javax.swing.JPanel(java.awt.BorderLayout()).apply {
            add(north, java.awt.BorderLayout.NORTH)
            add(pane, java.awt.BorderLayout.CENTER)
        } else pane
        val tab = EditorTab("pseudo", title, content, icon = Icons.of("file-code"))
        pseudoTab = tab
        val target = bytecodeTab
        if (target != null && Docking.isDocked(target)) Docking.dock(tab, target, DockingRegion.EAST, 0.5)
        else Docking.dock(tab, this@MainWindow, DockingRegion.EAST, 0.5)
        return area
    }

    private fun openDeviceModule(module: io.github.nitanmarcel.jdex.debug.LoadedModule) {
        val serial = debugSession?.device?.serial ?: run { log.warning("Not attached to a device"); return }
        log.info("Pulling ${module.path} from device…")
        Thread {
            val tmp = java.io.File.createTempFile("jdex-dev-", "-${module.name}")
            val bytes = runCatching {
                DeviceBridge.pullFile(serial, module.path, tmp.absolutePath); tmp.readBytes()
            }.getOrElse { e ->
                SwingUtilities.invokeLater { log.warning("Could not pull ${module.path}: ${e.message}") }
                tmp.delete(); return@Thread
            }
            tmp.delete()
            SwingUtilities.invokeLater { openNative("dev:${module.name}", module.name, NativeContent(module.name, bytes)) }
        }.apply { isDaemon = true }.start()
    }

    private fun openNative(tabId: String, title: String, content: NativeContent) {
        val elf = io.github.nitanmarcel.jdex.disasm.ElfFile.parse(content.bytes)
        if (elf == null) {
            val tab = EditorTab(tabId, title, Editors.component(BinaryContent(content.bytes)), icon = Icons.of("file-binary"))
            openTabs[tabId] = tab
            dockEditorTab(tab)
            return
        }
        val choice = DisassemblerDialog.show(this, content.name, elf) ?: return
        val x86Is32 = when (choice.arch) {
            io.github.nitanmarcel.jdex.disasm.ElfArch.X86 -> true
            io.github.nitanmarcel.jdex.disasm.ElfArch.X86_64 -> false
            else -> null
        }
        val hash = java.security.MessageDigest.getInstance("SHA-256").digest(content.bytes)
            .take(4).joinToString("") { "%02x".format(it) }
        val variant = "${choice.disassembler.id}.${choice.arch.name.lowercase()}.${if (choice.littleEndian) "le" else "be"}"
        val nativeId = "$hash:${content.name.substringAfterLast('/')}:$variant"
        val segments = (elf.textSections + elf.dataSections)
            .sortedBy { it.addr }
            .map { (it.name.ifEmpty { "seg_${it.addr.toString(16)}" }) to it.addr }
        val info = buildNativeInfo(elf, content.bytes, choice.arch, choice.littleEndian)
        val nbase = nativeId.split(':').getOrNull(1) ?: nativeId
        nativeExports[nbase] = elf.functions.filter { it.name.startsWith("Java_") }.associate { it.name to it.address }
        nativeSymbols[nbase] = elf.functions
        nativeArch[nbase] = choice.arch
        val code = CodeContent(Syntax.ASM, x86Is32, nativeId, segments, info) { progress, cancel ->
            io.github.nitanmarcel.jdex.disasm.NativeListing.build(elf, choice.disassembler, choice.arch, choice.littleEndian, progress, cancel, info.summary) { nativeAnalyses[nbase] = it }
        }
        openCode(tabId, title, code)
    }

    private fun buildNativeInfo(
        elf: io.github.nitanmarcel.jdex.disasm.ElfFile, bytes: ByteArray,
        arch: io.github.nitanmarcel.jdex.disasm.ElfArch, little: Boolean,
    ): io.github.nitanmarcel.jdex.project.NativeInfo {
        val exports = elf.functions.filter { it.name.isNotEmpty() }
            .associate { it.name to it.address }.toList().sortedBy { it.first.lowercase() }
        val imports = elf.relocs.entries.groupBy { it.value }
            .map { (name, e) -> name to e.minOf { it.key } }.sortedBy { it.first.lowercase() }
        val byAddr = elf.functions.filter { it.name.isNotEmpty() }.associate { it.address to it.name }
        val ptr = if (elf.is64) 8 else 4
        val constructors = ArrayList<Pair<String, Long>>()
        for (sec in elf.sections.filter { it.name == ".init_array" || it.name == ".fini_array" }) {
            var v = sec.addr
            while (v + ptr <= sec.addr + sec.size) {
                elf.relocatedPointerAt(v)?.takeIf { it != 0L }?.let {
                    constructors.add((byAddr[it] ?: "sub_${it.toString(16)}") to it)
                }
                v += ptr
            }
        }
        val eType = java.nio.ByteBuffer.wrap(bytes).order(if (little) java.nio.ByteOrder.LITTLE_ENDIAN else java.nio.ByteOrder.BIG_ENDIAN).getShort(16).toInt() and 0xFFFF
        val kind = when (eType) { 2 -> "Executable"; 3 -> "Shared object (PIE)"; 1 -> "Relocatable"; else -> "type $eType" }
        val stripped = elf.sections.none { it.name == ".symtab" }
        val canary = elf.relocs.values.any { it.startsWith("__stack_chk") } || elf.functions.any { it.name.startsWith("__stack_chk") }
        val dyn = elf.dynamic()
        val summary = ArrayList<String>()
        summary.add("File format : ELF${if (elf.is64) "64" else "32"} for ${arch.name} ($kind)")
        dyn.soname?.let { summary.add("Shared name : '$it'") }
        dyn.needed.forEach { summary.add("Needed lib  : '$it'") }
        summary.add("Processor   : ${arch.name}   Byte sex: ${if (little) "little-endian" else "big-endian"}")
        summary.add("Entry point : 0x${elf.entry.toString(16)}")
        summary.add("Symbols     : ${if (stripped) "stripped (.dynsym only)" else "present (.symtab)"}   Stack canary: ${if (canary) "yes" else "no"}")
        summary.add("Counts      : ${exports.size} functions, ${imports.size} imports, ${constructors.size} constructors")
        val archLabel = "ELF${if (elf.is64) "64" else "32"} · ${arch.name} · ${if (little) "LE" else "BE"}"
        return io.github.nitanmarcel.jdex.project.NativeInfo(exports, imports, constructors, summary, archLabel)
    }

    private fun openCode(tabId: String, title: String, content: CodeContent) {
        val cancelled = AtomicBoolean(false)
        val label = if (content.syntax == Syntax.ASM) "Disassembling" else "Generating bytecode"
        val unit = if (content.syntax == Syntax.ASM) "bytes" else "classes"
        statusBar.startProgress(label) { cancelled.set(true) }
        Thread({
            val result = runCatching {
                content.generate({ current, total -> SwingUtilities.invokeLater { statusBar.setProgress(current, total, unit) } }, cancelled::get)
            }
            result.exceptionOrNull()?.let { if (it !is io.github.nitanmarcel.jdex.project.GenerationCancelled) log.log(Level.WARNING, "Generation failed", it) }
            val source = result.getOrNull()
            SwingUtilities.invokeLater {
                statusBar.stopProgress()
                if (source != null && !cancelled.get()) {
                    val view = VirtualCodeView(
                        source,
                        content.syntax,
                        x86Is32 = content.x86Is32,
                        nativeId = content.nativeId,
                        nativeSegments = content.nativeSegments ?: emptyList(),
                        nativeInfo = content.nativeInfo,
                        onDecompile = { className -> showJava(className) },
                        onResource = { type, name -> explorer.openResource(type, name) },
                        comments = project ?: NoComments,
                        bookmarks = project ?: NoBookmarks,
                        mainActivity = session?.mainActivity(),
                        onUsages = { symbol -> session?.usages(symbol) },
                        renames = renames,
                        onRenamed = { renamesChanged() },
                        onCaret = { target -> javaModes?.followTo(target) },
                        onPosition = { statusBar.setPosition(it) },
                        cfgProvider = { raw, shortId -> session?.methodCfg(raw, shortId) },
                        onText = { title, text, syntax, north -> openText(title, text, syntax, north) },
                        onNativeJump = { cls, method, sig -> jumpToNativeExport(cls, method, sig) },
                        onBytecodeJump = { symbol, jniName, jniSig -> jumpToBytecodeMethod(symbol, jniName, jniSig) },
                        onNativeExportRename = { symbol, jniName, jniSig, name -> propagateExportRename(symbol, jniName, jniSig, name) },
                        onActivated = { v -> onViewActivated(v) },
                    )
                    val tab = EditorTab(tabId, title, view, source, Icons.of(if (content.syntax == Syntax.ASM) "file-binary" else "file-code"))
                    openTabs[tabId] = tab
                    if (content.syntax == Syntax.ASM) {
                        nativeViews.add(Triple(tab, view, source))
                        content.nativeId?.let { renames.setNativeJniBindings(it, buildJniBindings(source)) }
                        val base = content.nativeId?.split(':')?.getOrNull(1)
                        if (base != null) {
                            nativeViewByBase[base] = tab to view
                            view.onToggleNativeBreakpoint = { vaddr, added ->
                                val bp = Breakpoint.Native(base, vaddr)
                                when {
                                    debugSession is ArtSession && added -> enableNativeDebugging()
                                    else -> if (added) debugSession?.addBreakpoint(bp) else debugSession?.removeBreakpoint(bp)
                                }
                            }
                            view.onRunToCursorNative = { off -> debugSession?.runToCursorNative(base, off) }
                            view.onViewMemoryNative = ::viewMemoryFromOperand
                            view.onPatchNative = { vaddr -> patchNativeAtVaddr(base, vaddr) }
                            view.nativePatchEnabled = { debugSession != null && KeystoneAssembler.available() }
                            view.onEnableNative = { enableNativeDebugging() }
                            view.nativeEnableVisible = { debugSession is ArtSession }
                        }
                    } else {
                        bytecodeTab = tab
                        bytecodeView = view
                        dexBytecodeTab = tab
                        dexBytecodeView = view
                        view.onToggleBreakpoint = { desc, dexPc, added -> onBreakpointToggled(desc, dexPc, added) }
                        view.onRunToCursor = { desc, dexPc -> debugSession?.runToCursor(desc, dexPc) }
                        view.markBreakpoints(breakpointStore().breakpoints().map { it.descriptor to it.dexPc })
                    }
                    view.syncApprox = syncState == FlatTriStateCheckBox.State.INDETERMINATE
                    dockEditorTab(tab)
                    log.info("Opened ${if (content.syntax == Syntax.ASM) "disassembly" else "bytecode"} (${source.lineCount} lines)")
                } else {
                    source?.close()
                    log.info("Bytecode generation cancelled")
                }
            }
        }, "bytecode-gen").apply { isDaemon = true }.start()
    }

    private fun clearEditors() {
        openTabs.values.forEach {
            if (Docking.isDocked(it)) Docking.undock(it)
            Docking.deregisterDockable(it)
            it.dispose()
        }
        openTabs.clear()
        nativeViews.clear()
        nativeViewByBase.clear()
        nativeAnalyses.clear()
        nativeExports.clear()
        nativeSymbols.clear()
        nativeArch.clear()
        bytecodeTab = null
        bytecodeView = null
        dexBytecodeTab = null
        dexBytecodeView = null
        hierarchyNativeView = null
        javaTab?.let {
            if (Docking.isDocked(it)) Docking.undock(it)
            Docking.deregisterDockable(it)
        }
        javaTab = null
        javaModes = null
        javaClass = null
        pseudoTab?.let {
            if (Docking.isDocked(it)) Docking.undock(it)
            Docking.deregisterDockable(it)
        }
        pseudoTab = null
    }

    private fun jumpToNativeExport(className: String, method: String, signature: String): Boolean {
        if (nativeViews.isEmpty()) return false
        val cls = JniName.mangle(className.replace('.', '/'))
        val m = JniName.mangle(method)
        val args = signature.substringAfter('(').substringBefore(')')
        val candidates = listOf("Java_${cls}_$m", "Java_${cls}_${m}__${JniName.mangle(args)}", method)
        val ordered = nativeViews.sortedByDescending { it.second === hierarchyNativeView }
        for ((tab, view, _) in ordered) {
            if (!Docking.isDocked(tab)) continue
            for (c in candidates) if (view.revealSection(c)) { Docking.bringToFront(tab); return true }
        }
        return false
    }

    private fun dexMethodKey(symbol: String?, jniName: String?, jniSig: String?): String? {
        val s = session ?: return null
        if (jniName != null && jniSig != null) return s.jniMethodKey(jniName, jniSig)
        if (symbol != null) {
            val (cls, method) = JniName.demangle(symbol) ?: return null
            val shortId = s.nativeMethodShortId(cls, method, JniName.demangleArgs(symbol)) ?: return null
            return "L${cls.replace('.', '/')};->$shortId"
        }
        return null
    }

    private fun jumpToBytecodeMethod(symbol: String, jniName: String?, jniSig: String?): Boolean {
        val key = dexMethodKey(symbol, jniName, jniSig) ?: return false
        val tab = dexBytecodeTab ?: return false
        val view = dexBytecodeView ?: return false
        val cls = key.substringBefore("->").removePrefix("L").removeSuffix(";").replace('/', '.')
        if (Docking.isDocked(tab)) Docking.bringToFront(tab)
        view.revealMethod(cls, key.substringAfter("->"))
        return true
    }

    private fun propagateExportRename(symbol: String, jniName: String?, jniSig: String?, newName: String?) {
        val key = dexMethodKey(symbol, jniName, jniSig) ?: return
        renames.store.setRename(key, newName)
    }

    private fun buildJniBindings(source: io.github.nitanmarcel.jdex.project.LineSource): Map<String, String> {
        val s = session ?: return emptyMap()
        val map = HashMap<String, String>()
        for ((label, line) in source.sections()) {
            when {
                label.startsWith("Java_") -> {
                    val (cls, method) = JniName.demangle(label) ?: continue
                    s.nativeMethodShortId(cls, method, JniName.demangleArgs(label))?.let { map[label] = "L${cls.replace('.', '/')};->$it" }
                }
                label.startsWith("sub_") || label.startsWith("loc_") || label.startsWith("off_") || label.startsWith("unk_") -> {}
                else -> {
                    val c = jniCommentAt(source, line) ?: continue
                    s.jniMethodKey(c.first, c.second)?.let { map[label] = it }
                }
            }
        }
        return map
    }

    private fun jniCommentAt(source: io.github.nitanmarcel.jdex.project.LineSource, start: Int): Pair<String, String>? {
        for (off in 0..4) {
            val t = source.lines(start + off, 1).firstOrNull()?.trimStart() ?: break
            if (t.startsWith("; Java native: ")) {
                val rest = t.removePrefix("; Java native: ").trim()
                return rest.substringBefore(' ') to rest.substringAfter(' ', "")
            }
            if (off > 0 && t.length >= 9 && t[8] == ':' && t.take(8).all { it.isDigit() || it in 'a'..'f' }) break
        }
        return null
    }

    private fun onViewActivated(view: VirtualCodeView) {
        activeCodeView = view
        if (debugSession == null) view.binaryArch?.let { statusBar.setArch(it) }
        if (view.isNativeView) {
            if (hierarchyNativeView === view) return
            hierarchyNativeView = view
            hierarchy.showNativeSymbols(view.nativeFunctions().map { (name, line) -> name to { view.goToLine(line) } })
        } else if (hierarchyNativeView != null) {
            hierarchyNativeView = null
            hierarchy.show(hierarchyClasses)
        }
    }

    private fun renamesChanged() {
        renames.reload()
        bytecodeView?.rerender()
        if (dexBytecodeView !== bytecodeView) dexBytecodeView?.rerender()
        nativeViews.forEach { (_, view, _) -> if (view !== bytecodeView) view.rerender() }
        hierarchy.refresh()
        refreshJava()
    }

    private fun refreshJava() {
        val cls = javaClass ?: return
        val tab = javaTab ?: return
        if (Docking.isDocked(tab)) showJava(cls)
    }

    private fun findInBytecode(query: String) {
        val tab = bytecodeTab ?: return
        if (Docking.isDocked(tab)) Docking.bringToFront(tab)
        bytecodeView?.search(query)
    }

    private fun <T> onEdt(block: () -> T): T {
        if (SwingUtilities.isEventDispatchThread()) return block()
        val ref = java.util.concurrent.atomic.AtomicReference<T>()
        SwingUtilities.invokeAndWait { ref.set(block()) }
        return ref.get()
    }

    private fun openDescriptor(desc: String) {
        val raw = desc.substringBefore("->").removePrefix("L").removeSuffix(";").replace('/', '.')
        val member = desc.substringAfter("->", "")
        when {
            member.isEmpty() -> navigateBytecode { it.revealClass(raw) }
            '(' in member -> navigateBytecode { it.revealMethod(raw, member) }
            else -> navigateBytecode { it.revealField(raw, member.substringBefore(":")) }
        }
    }

    private fun dockEditorTab(tab: EditorTab) {
        val leader = (sequenceOf(dexBytecodeTab) + nativeViews.asSequence().map { it.first } + openTabs.values.asSequence())
            .filterNotNull()
            .firstOrNull { it !== tab && it !== javaTab && it !== pseudoTab && Docking.isDocked(it) }
        if (leader != null) Docking.dock(tab, leader, DockingRegion.CENTER)
        else Docking.dock(tab, "editors", DockingRegion.CENTER)
    }

    private fun navigateBytecode(action: (VirtualCodeView) -> Unit) {
        val tab = bytecodeTab ?: return
        val view = bytecodeView ?: return
        if (Docking.isDocked(tab)) Docking.bringToFront(tab)
        action(view)
    }

    private fun attachDebugger(dev: DebugDevice, proc: DebugProcess) {
        if (debugSession != null || attaching) { log.warning("Already attaching/attached; detach first"); return }
        attaching = true
        log.info("Attaching to ${proc.name} (pid ${proc.pid}) on ${dev.serial}…")
        val dexBps = breakpointStore().breakpoints().map { Breakpoint.Dex(it.descriptor, it.dexPc) }
        Thread {
            DeviceBridge.useJrunas(null)
            val s = runCatching { ArtSession.attach(dev, DeviceBridge.androidRelease(dev.serial), proc.pid, ::registerMetaFor) }.getOrElse { e ->
                SwingUtilities.invokeLater { attaching = false; log.warning("Attach failed: ${e.message}") }
                return@Thread
            }
            val abi = runCatching { DeviceBridge.deviceAbi(dev.serial) }.getOrNull()
            SwingUtilities.invokeLater {
                attaching = false
                attachedDevice = dev; attachedProc = proc
                statusBar.setTarget("${proc.name}  ·  pid ${proc.pid}  ·  ${dev.serial}")
                statusBar.setArch(abi ?: "")
                debugSession = s
                s.onStateChange { st -> SwingUtilities.invokeLater { onDebugState(st) } }
                dexBps.forEach { s.addBreakpoint(it) }
                s.setExceptionBreak(false, debugBar.exceptionBreakEnabled())
                debugBar.setState(s.state)
                showDebugViews()
                onDebugState(s.state)
                log.info("Attached to ${proc.name} (pid ${proc.pid}) — native debugging off; open a .so and enable it to attach the native debugger")
            }
        }.start()
    }

    private fun enableNativeDebugging(then: (() -> Unit)? = null) {
        val art = debugSession as? ArtSession ?: run {
            if (debugSession is MixedSession) then?.invoke() else log.warning("Attach a debugger first")
            return
        }
        if (art.state is DebugState.Stopped) { log.warning("Resume before enabling native debugging"); return }
        if (nativeViewByBase.isEmpty()) { log.warning("Open a native library (.so) first"); return }
        val dev = attachedDevice ?: return
        val proc = attachedProc ?: return
        if (enablingNative) return
        enablingNative = true
        Thread {
            DeviceBridge.useJrunas(null)
            val devAbi = DeviceBridge.deviceAbi(dev.serial)
            val picked = arrayOfNulls<NativeDebug>(1)
            picked[0] = if (DebugConfigDialog.remembered()) DebugConfigDialog.build(devAbi) else null
            if (picked[0] == null) runCatching { SwingUtilities.invokeAndWait { picked[0] = DebugConfigDialog.show(this@MainWindow, devAbi) } }
            val nativeDebug = picked[0] ?: run { SwingUtilities.invokeLater { enablingNative = false; log.info("Native debugging cancelled") }; return@Thread }
            if (nativeDebug is NativeDebug.Managed && !runCatching { DeviceBridge.isDebuggable(dev.serial, proc.name) }.getOrDefault(true) && !setUpRootDebug(dev, proc.name)) {
                SwingUtilities.invokeLater { enablingNative = false }; return@Thread
            }
            abiToArch(devAbi)?.let { devArch ->
                nativeArch.filterValues { it != devArch }.forEach { (base, a) ->
                    SwingUtilities.invokeLater { log.warning("'$base' was disassembled as ${a.name} but the device ABI is $devAbi — its breakpoints/symbols will be mis-bound; re-open the matching .so") }
                }
            }
            val bindingMap = io.github.nitanmarcel.jdex.debug.BindingMap()
            val dexNatives = dexNativeMethods()
            nativeAnalyses.forEach { (base, an) -> bindingMap.add(base, an, nativeExports[base] ?: emptyMap(), dexNatives) }
            val nativeBps = nativeViewByBase.flatMap { (base, tv) -> tv.second.nativeBreakpointSet().map { Breakpoint.Native(base, it) } }
            val s = runCatching {
                MixedSession.upgrade(art, dev, proc.name, proc.pid, nativeDebug, nativeBps, bindingMap, ::symbolizeNative) { m -> SwingUtilities.invokeLater { log.info(m) } }
            }.getOrElse { e ->
                SwingUtilities.invokeLater { enablingNative = false; log.warning("Enable native debugging failed: ${e.message}") }
                return@Thread
            }
            SwingUtilities.invokeLater {
                enablingNative = false
                debugSession = s
                s.onStateChange { st -> SwingUtilities.invokeLater { onDebugState(st) } }
                s.setExceptionBreak(false, debugBar.exceptionBreakEnabled())
                debugBar.setState(s.state)
                onDebugState(s.state)
                log.info("Native debugging enabled (${bindingMap.allEntries().size} binding entr(ies))")
                then?.invoke()
            }
        }.start()
    }

    private fun setUpRootDebug(dev: DebugDevice, pkg: String): Boolean {
        if (!debugPrefs.getBoolean("skipNonDebuggableDialog", false)) {
            val choice = arrayOfNulls<RootDebugDialog.Choice>(1)
            runCatching { SwingUtilities.invokeAndWait { choice[0] = RootDebugDialog.show(this, pkg) } }
            val c = choice[0]
            if (c == null || !c.proceed) { SwingUtilities.invokeLater { log.info("$pkg is not debuggable — native debugging skipped") }; return false }
            if (c.dontShowAgain) debugPrefs.putBoolean("skipNonDebuggableDialog", true)
        }
        if (!DeviceBridge.hasRoot(dev.serial)) {
            runCatching {
                SwingUtilities.invokeAndWait {
                    JOptionPane.showMessageDialog(this,
                        "$pkg is not debuggable and this device is not rooted.\n\n" +
                            "Debugging a non-debuggable app needs a rooted device or an emulator, " +
                            "or install a debuggable build of the APK.",
                        "Cannot debug", JOptionPane.ERROR_MESSAGE)
                }
            }
            SwingUtilities.invokeLater { log.warning("$pkg is not debuggable and the device is not rooted") }
            return false
        }
        val abi = DeviceBridge.deviceAbi(dev.serial)
        val jr = io.github.nitanmarcel.jdex.debug.Jrunas.extract(abi)
            ?: run { SwingUtilities.invokeLater { log.warning("jrunas not bundled for $abi") }; return false }
        DeviceBridge.useJrunas(DeviceBridge.pushJrunas(dev.serial, jr.absolutePath))
        SwingUtilities.invokeLater { log.info("Using jrunas for $pkg (non-debuggable)") }
        return true
    }

    private fun showDebugViews() {
        if (debugViews.dockables.none { Docking.isDocked(it) }) {
            Docking.dock(debugViews.threads, this, DockingRegion.EAST, 0.28)
            Docking.dock(debugViews.frames, debugViews.threads, DockingRegion.CENTER)
            Docking.dock(debugViews.variables, debugViews.threads, DockingRegion.CENTER)
            Docking.dock(debugViews.libraries, debugViews.threads, DockingRegion.CENTER)
            Docking.dock(debugViews.memory, debugViews.threads, DockingRegion.CENTER)
        }
        Docking.bringToFront(debugViews.threads)
    }

    private fun dockDebugView(d: Dockable) {
        val anchor = debugViews.dockables.firstOrNull { it !== d && Docking.isDocked(it) }
        if (anchor != null) Docking.dock(d, anchor, DockingRegion.CENTER)
        else Docking.dock(d, this, DockingRegion.EAST, 0.28)
    }

    private fun describeTarget(t: SyncTarget): String = when (t) {
        is SyncTarget.Line -> "${methodLabel(t.methodId)}  ·  line ${t.sourceLine}"
        is SyncTarget.MethodDecl -> methodLabel(t.methodId)
        is SyncTarget.ClassDecl -> t.rawName.substringAfterLast('.').substringAfterLast('/')
        is SyncTarget.FieldDecl -> "${t.rawName.substringAfterLast('.').substringAfterLast('/')}  ·  ${t.fieldName}"
    }

    private fun methodLabel(id: String): String =
        if ("->" in id) id.substringAfter("->") else id.substringAfterLast('.').substringAfterLast('/')

    private fun onDebugState(state: DebugState) {
        debugBar.setState(state)
        when (state) {
            is DebugState.Stopped -> {
                val s = debugSession ?: return
                debugViews.showStopped(
                    { s.threads() },
                    { threadId -> s.frames(threadId) },
                    { threadId, idx -> s.variables(threadId, idx) },
                    { ref -> s.children(ref) },
                    { s.modules() },
                )
                revealDebugLocation(state.location)
            }
            DebugState.Running -> {
                debugViews.clear()
                dexBytecodeView?.clearDebugLine()
                nativeViewByBase.values.forEach { it.second.clearDebugLine() }
            }
            DebugState.Detached -> {
                statusBar.setTarget(""); statusBar.setArch("")
                debugSession = null
                debugViews.clear()
                dexBytecodeView?.clearDebugLine()
                nativeViewByBase.values.forEach { it.second.clearDebugLine() }
                log.info("Debugger detached")
            }
        }
    }

    private fun updateInlineValues(location: DebugLocation, vars: List<DebugVar>) {
        val view = when (location) {
            is DebugLocation.Dex -> dexBytecodeView
            is DebugLocation.Native -> nativeViewByBase[location.nativeId]?.second
        } ?: return
        val map = HashMap<String, String>()
        debugSession?.let { s -> runCatching { map.putAll(s.inlineValues()) } }
        val paramToken = Regex("p\\d+")
        val popup = StringBuilder()
        for (v in vars) {
            if (v.ref < 0) continue
            val inline = escapeForLine(when {
                v.id != 0L -> "id=${v.id}"
                v.type == "java.lang.String" -> v.value
                else -> v.editValue ?: v.value
            })
            map[v.name.substringBefore(" ")] = inline
            paramToken.find(v.name)?.let { map[it.value] = inline }
            popup.append(popupLine(v)).append('\n')
        }
        view.setDebugInlineValues(map)
        view.setDebugPopup(popup.toString().trimEnd('\n').ifEmpty { null })
    }

    private fun popupLine(v: DebugVar): String {
        val t = v.type.substringAfterLast('.')
        val id = if (v.id != 0L) " (id=${v.id})" else ""
        return when {
            v.type.isEmpty() -> "${v.name} = ${v.value}"
            v.id != 0L && v.value == t -> "${v.name}: $t$id"
            else -> "${v.name}: $t = ${v.value}$id"
        }
    }

    private fun revealDebugLocation(location: DebugLocation) {
        when (location) {
            is DebugLocation.Dex -> {
                val tab = dexBytecodeTab ?: return
                val view = dexBytecodeView ?: return
                val cls = location.methodDescriptor.substringBefore("->").removePrefix("L").removeSuffix(";").replace('/', '.')
                if (Docking.isDocked(tab)) Docking.bringToFront(tab)
                view.revealDexLocation(cls, location.methodDescriptor.substringAfter("->"), location.dexPc)
            }
            is DebugLocation.Native -> {
                val id = location.nativeId ?: return
                val (tab, view) = nativeViewByBase[id] ?: return
                if (Docking.isDocked(tab)) Docking.bringToFront(tab)
                nativeViewByBase.values.forEach { it.second.clearDebugLine() }
                view.revealNativeLocation(location.fileOffset)
            }
        }
    }

    private fun dexNativeMethods(): List<io.github.nitanmarcel.jdex.debug.DexNativeMethod> {
        val jadx = session?.decompiler() ?: return emptyList()
        val out = ArrayList<io.github.nitanmarcel.jdex.debug.DexNativeMethod>()
        for (cls in jadx.root.classes) {
            for (mth in cls.methods) {
                if (!mth.accessFlags.isNative) continue
                val mi = mth.methodInfo
                val raw = mi.declClass.rawName.replace('.', '/')
                val shortId = mi.shortId
                out.add(io.github.nitanmarcel.jdex.debug.DexNativeMethod("L$raw;->$shortId", raw, mi.name, shortId.removePrefix(mi.name), mth.accessFlags.isStatic))
            }
        }
        return out
    }

    private fun abiToArch(abi: String) = io.github.nitanmarcel.jdex.disasm.ElfArch.fromAndroidAbi(abi)

    private fun patchNativeAtVaddr(base: String, vaddr: Long) {
        if (debugSession is ArtSession) { enableNativeDebugging { patchNativeAtVaddr(base, vaddr) }; return }
        val session = debugSession ?: return
        val rt = session.runtimeAddr(base, vaddr) ?: run { log.warning("Patch: '$base' not mapped in the target (library loaded?)"); return }
        val arch = nativeArch[base] ?: run { log.warning("Patch: unknown arch for $base"); return }
        val cur = session.readMemory(rt, 16)?.let { CapstoneDisassembler.disassemble(it, rt, arch, false).firstOrNull() }
        val curAsm = cur?.let { "${it.mnemonic} ${it.operands}".trim() } ?: ""
        val bytes = NativePatchDialog.show(this, rt, arch, curAsm) ?: return
        if (session.writeMemory(rt, bytes)) log.info("Patched ${bytes.size} bytes at 0x${rt.toString(16)} ($base+0x${vaddr.toString(16)}) — listing still shows on-disk code")
        else log.warning("Patch write failed at 0x${rt.toString(16)}")
    }

    private fun viewMemoryFromOperand(operand: String) {
        val regs = debugSession?.inlineValues() ?: return
        fun reg(n: String): Long? = regs[n.trim().removePrefix("$")]?.removePrefix("0x")?.toULongOrNull(16)?.toLong()
        fun regVal(n: String): Long? {
            val name = n.trim().removePrefix("$")
            if (name == "rip" || name == "eip" || name == "pc") return debugSession?.architecturalPc()
            return reg(name)
        }
        var body = operand.trim()
        var segBase = 0L
        Regex("^(fs|gs|ds|es|cs|ss):", RegexOption.IGNORE_CASE).find(body)?.let { seg ->
            body = body.substring(seg.value.length)
            segBase = reg("${seg.groupValues[1].lowercase()}_base") ?: 0L
        }
        fun term(t0: String): Long? {
            val t = t0.trim().removePrefix("#").trim()
            if ('*' in t) { val (r, s) = t.split('*', limit = 2); return regVal(r)?.times(s.trim().toLongOrNull() ?: 1L) }
            if ('/' in t) { val (r, s) = t.split('/', limit = 2); val d = s.trim().toLongOrNull() ?: 1L; return regVal(r)?.let { if (d == 0L) it else it / d } }
            return regVal(t) ?: t.removePrefix("0x").toLongOrNull(16) ?: t.toLongOrNull()
        }
        val shifted = Regex("([a-z0-9$]+)\\s*,\\s*(lsl|asl|lsr|asr|sxt[wxbh]|uxt[wxbh])\\s*(?:#(\\d+))?", RegexOption.IGNORE_CASE)
            .replace(body) { m ->
                val r = m.groupValues[1]; val op = m.groupValues[2].lowercase(); val scale = 1L shl (m.groupValues[3].toIntOrNull() ?: 0)
                if (op == "lsr" || op == "asr") "$r/$scale" else "$r*$scale"
            }
        val cleaned = shifted.replace(",", " + ")
        var addr = 0L
        var any = false
        Regex("[+\\-]?\\s*[^+\\-]+").findAll(cleaned).forEach { m ->
            val raw = m.value.trim()
            val neg = raw.startsWith("-")
            val v = term(raw.removePrefix("-").removePrefix("+")) ?: return@forEach
            addr += if (neg) -v else v
            any = true
        }
        if (!any) return
        debugViews.memory.go(addr + segBase)
        Docking.bringToFront(debugViews.memory)
    }

    private fun resolveMemoryAddress(input: String): Long? {
        val t = input.trim()
        fun num(x: String): Long? {
            val s = x.trim()
            return s.removePrefix("0x").removePrefix("0X").toULongOrNull(16)?.toLong() ?: s.toLongOrNull()
        }
        val plus = t.indexOf('+')
        if (plus > 0) {
            val name = t.substring(0, plus).trim()
            val off = num(t.substring(plus + 1)) ?: return null
            return debugSession?.modules()?.firstOrNull { it.name == name || it.name.startsWith(name) }?.let { it.base + off }
        }
        return num(t) ?: debugSession?.modules()?.firstOrNull { it.name == t || it.name.startsWith(t) }?.base
    }

    private fun symbolizeNative(basename: String, off: Long): String? {
        val fns = nativeSymbols[basename] ?: return null
        val i = fns.indexOfLast { it.address <= off }
        if (i < 0) return null
        val f = fns[i]
        val within = if (f.size > 0) off < f.address + f.size
        else fns.getOrNull(i + 1)?.let { off < it.address } ?: (off - f.address < 0x1000)
        if (!within) return null
        val delta = off - f.address
        return if (delta == 0L) f.name else "${f.name}+0x${delta.toString(16)}"
    }

    private fun registerMetaFor(descriptor: String): RegisterMeta? {
        val s = session ?: return null
        val raw = descriptor.substringBefore("->").removePrefix("L").removeSuffix(";").replace('/', '.')
        return s.registerMeta(raw, descriptor.substringAfter("->"))
    }

    private fun breakpointStore(): BreakpointStore = project ?: NoBreakpoints

    private fun onBreakpointToggled(descriptor: String, dexPc: Int, added: Boolean) {
        val bp = Breakpoint.Dex(descriptor, dexPc)
        if (added) {
            debugSession?.addBreakpoint(bp)
            breakpointStore().addBreakpoint(descriptor, dexPc)
        } else {
            debugSession?.removeBreakpoint(bp)
            breakpointStore().removeBreakpoint(descriptor, dexPc)
        }
        log.info(("${if (added) "Set" else "Cleared"} breakpoint at $descriptor @%04x").format(dexPc))
    }

    private fun showJava(className: String) {
        if (session == null) return
        javaClass = className
        javaTab?.let {
            if (Docking.isDocked(it)) Docking.undock(it)
            Docking.deregisterDockable(it)
        }
        val view = JavaModesView(
            decompile = { mode, onResult ->
                scope.launch {
                    val result = withContext(Dispatchers.Default) {
                        session?.let { it.syncRenames(renames.snapshot()); it.decompile(className, mode) }
                    }
                    onResult(result)
                }
            },
            onCaret = { target -> bytecodeView?.followFromJava(target); statusBar.setPosition(describeTarget(target)) },
            syncState = syncState,
            onSyncToggle = { state ->
                syncState = state
                bytecodeView?.syncApprox = state == FlatTriStateCheckBox.State.INDETERMINATE
                if (state == FlatTriStateCheckBox.State.UNSELECTED) bytecodeView?.clearSyncHighlight()
            },
        )
        val tab = EditorTab("decompiled", className.substringAfterLast('.'), view, icon = Icons.of("file-code"))
        javaTab = tab
        javaModes = view
        val target = bytecodeTab
        if (target != null && Docking.isDocked(target)) Docking.dock(tab, target, DockingRegion.EAST, 0.5)
        else Docking.dock(tab, this@MainWindow, DockingRegion.EAST, 0.5)
        log.info("Decompiled $className")
    }

    private fun updateRecentMenu() {
        recentMenu.removeAll()
        val files = recentFiles.all()
        files.forEach { file ->
            recentMenu.add(JMenuItem(file.absolutePath).apply {
                addActionListener { open(file) }
            })
        }
        if (files.isNotEmpty()) {
            recentMenu.addSeparator()
            recentMenu.add(JMenuItem("Clear Recently Opened").apply {
                addActionListener {
                    recentFiles.clear()
                    updateRecentMenu()
                }
            })
        }
        recentMenu.isEnabled = files.isNotEmpty()
    }
}
