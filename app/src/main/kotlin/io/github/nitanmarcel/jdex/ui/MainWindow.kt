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
import io.github.nitanmarcel.jdex.project.ApkSession
import io.github.nitanmarcel.jdex.project.CodeContent
import io.github.nitanmarcel.jdex.project.Content
import io.github.nitanmarcel.jdex.project.Dex
import io.github.nitanmarcel.jdex.project.DexPatch
import io.github.nitanmarcel.jdex.project.HMembers
import io.github.nitanmarcel.jdex.project.MalformedDex
import io.github.nitanmarcel.jdex.project.NoBookmarks
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
    private val scope = CoroutineScope(Dispatchers.Swing)
    private val openTabs = LinkedHashMap<String, EditorTab>()
    private lateinit var explorer: FilesPanel
    private lateinit var hierarchy: HierarchyPanel
    private var project: Project? = null
    private var session: ApkSession? = null
    private val renames = Renames()
    private var javaTab: EditorTab? = null
    private var javaView: JavaView? = null
    private var javaClass: String? = null
    private var syncState = FlatTriStateCheckBox.State.UNSELECTED
    private var bytecodeTab: EditorTab? = null
    private var bytecodeView: VirtualCodeView? = null
    private lateinit var scripting: ScriptPanel

    init {
        defaultCloseOperation = EXIT_ON_CLOSE
        size = Dimension(1000, 700)
        setLocationRelativeTo(null)

        addWindowListener(object : WindowAdapter() {
            override fun windowClosing(e: WindowEvent) {
                runCatching { clearEditors() }
                runCatching { AppState.persist() }
                runCatching { scope.cancel() }
                runCatching { scripting.close() }
                runCatching { session?.close() }
                runCatching { project?.close() }
            }
        })

        Docking.initialize(this)
        add(RootDockingPanel(this))

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
            importer = { name, bytes ->
                SwingUtilities.invokeLater {
                    project?.let { it.saveImported(DexPatch.sha256(bytes), name, bytes); analyze() }
                        ?: log.warning("Open an APK or project before importing a DEX")
                }
            },
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

    private fun createMenuBar(editors: EditorAnchor, explorer: FilesPanel, hierarchy: HierarchyPanel, logger: LoggerPanel, scripting: ScriptPanel) = JMenuBar().apply {
        add(JMenu("File").apply {
            add(JMenuItem("Open…").apply {
                icon = Icons.FOLDER_OPEN
                accelerator = shortcut(KeyEvent.VK_O)
                addActionListener { openWithChooser() }
            })
            add(JMenuItem("Import DEX…").apply { icon = Icons.FILE_BINARY; addActionListener { importDex() } })
            add(JMenuItem("Run Script…").apply { icon = Icons.RUN; addActionListener { runScript() } })
            add(recentMenu)
            addSeparator()
            add(saveItem.apply {
                icon = Icons.SAVE
                accelerator = shortcut(KeyEvent.VK_S)
                isEnabled = false
                addActionListener { project?.save() }
            })
            addSeparator()
            add(JMenuItem("Close").apply {
                accelerator = shortcut(KeyEvent.VK_W)
                addActionListener {
                    this@MainWindow.dispatchEvent(WindowEvent(this@MainWindow, WindowEvent.WINDOW_CLOSING))
                }
            })
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
        })
        add(JMenu("Appearance").apply {
            add(JMenu("Theme").apply {
                val group = ButtonGroup()
                Themes.all.forEach { def ->
                    add(JRadioButtonMenuItem(def.label, def.id == Themes.currentId).also {
                        group.add(it)
                        it.addActionListener { Themes.select(def.id) }
                    })
                }
            })
            addSeparator()
            add(JMenuItem("Theme Editor…").apply { icon = Icons.SETTINGS; addActionListener { ThemeEditor.open(this@MainWindow) } })
        })
        add(JMenu("Help").apply {
            add(JMenuItem("About jdex…").apply { addActionListener { showAbout() } })
        })
    }

    private fun showAbout() {
        val msg = """
            <html><body style='width:360px'>
            <h2 style='margin:0'>jdex</h2>
            <p>Android APK/DEX reverse-engineering tool.</p>
            <p>Built with jadx, FlatLaf, GraalPy, RSyntaxTextArea and Modern Docking.</p>
            <p>Icons: <b>VS Code Codicons</b> &copy; Microsoft Corporation, licensed under
            CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).</p>
            <p style='color:gray'>Java ${System.getProperty("java.version")}</p>
            </body></html>
        """.trimIndent()
        JOptionPane.showMessageDialog(this, msg, "About jdex", JOptionPane.INFORMATION_MESSAGE)
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
        session?.close()
        session = null
        clearEditors()
        project?.close()
        renames.store = NoRenames
        val project = if (file.extension == Project.EXTENSION) Project.open(file) else Project.forInput(file)
        this.project = project
        renames.store = project
        renames.reload()
        recentFiles.add(file)
        updateRecentMenu()
        saveItem.isEnabled = true
        title = "jdex — ${(project.input() ?: file).name}"
        log.info("Opened project ${project.file.absolutePath}")
        analyze()
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
            runCatching { withContext(Dispatchers.Default) { ApkSession.load(input, project.file.name, project) } }
                .onSuccess { loaded ->
                    session = loaded
                    explorer.show(loaded.root)
                    hierarchy.show(loaded.topClasses())
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

    private fun importDex() {
        val project = project ?: return run { log.warning("Open an APK or project before importing a DEX") }
        val chooser = JFileChooser(recentFiles.all().firstOrNull()?.parentFile)
        chooser.fileFilter = FileNameExtensionFilter("DEX files (*.dex)", "dex")
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return
        val file = chooser.selectedFile
        val bytes = runCatching { file.readBytes() }.getOrElse { log.log(Level.SEVERE, "Cannot read ${file.name}: ${it.message}"); return }
        project.saveImported(DexPatch.sha256(bytes), file.name, bytes)
        log.info("Imported ${file.name} (${bytes.size} bytes)")
        analyze()
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
            if (Docking.isDocked(tab)) Docking.bringToFront(tab) else Docking.dock(tab, "editors", DockingRegion.CENTER)
            return
        }
        scope.launch {
            val content = withContext(Dispatchers.Default) {
                runCatching { load() }.getOrElse { TextContent("Failed to load: ${it.message}") }
            }
            if (content is CodeContent) {
                openCode(tabId, title, content)
            } else {
                val tab = EditorTab(tabId, title, Editors.component(content))
                openTabs[tabId] = tab
                Docking.dock(tab, "editors", DockingRegion.CENTER)
            }
        }
    }

    private fun openCode(tabId: String, title: String, content: CodeContent) {
        val cancelled = AtomicBoolean(false)
        val dialog = LoadingDialog(this, "Generating bytecode", onCancel = { cancelled.set(true) })
        Thread({
            val source = runCatching {
                content.generate({ current, total -> SwingUtilities.invokeLater { dialog.progress(current, total) } }, cancelled::get)
            }.getOrNull()
            SwingUtilities.invokeLater {
                dialog.dispose()
                if (source != null && !cancelled.get()) {
                    val view = VirtualCodeView(
                        source,
                        content.syntax,
                        onDecompile = { className -> showJava(className) },
                        onResource = { type, name -> explorer.openResource(type, name) },
                        comments = project ?: NoComments,
                        bookmarks = project ?: NoBookmarks,
                        mainActivity = session?.mainActivity(),
                        onUsages = { symbol -> session?.usages(symbol) },
                        renames = renames,
                        onRenamed = { renamesChanged() },
                        onCaret = { target -> javaView?.followTo(target) },
                    )
                    val tab = EditorTab(tabId, title, view, source)
                    openTabs[tabId] = tab
                    bytecodeTab = tab
                    bytecodeView = view
                    view.syncApprox = syncState == FlatTriStateCheckBox.State.INDETERMINATE
                    Docking.dock(tab, "editors", DockingRegion.CENTER)
                    log.info("Opened bytecode (${source.lineCount} lines)")
                } else {
                    source?.close()
                    log.info("Bytecode generation cancelled")
                }
            }
        }, "bytecode-gen").apply { isDaemon = true }.start()
        dialog.isVisible = true
    }

    private fun clearEditors() {
        openTabs.values.forEach {
            if (Docking.isDocked(it)) Docking.undock(it)
            Docking.deregisterDockable(it)
            it.dispose()
        }
        openTabs.clear()
        bytecodeTab = null
        bytecodeView = null
        javaTab?.let {
            if (Docking.isDocked(it)) Docking.undock(it)
            Docking.deregisterDockable(it)
        }
        javaTab = null
        javaView = null
        javaClass = null
    }

    private fun renamesChanged() {
        renames.reload()
        bytecodeView?.rerender()
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

    private fun navigateBytecode(action: (VirtualCodeView) -> Unit) {
        val tab = bytecodeTab ?: return
        val view = bytecodeView ?: return
        if (Docking.isDocked(tab)) Docking.bringToFront(tab)
        action(view)
    }

    private fun showJava(className: String) {
        val session = session ?: return
        javaClass = className
        scope.launch {
            val result = withContext(Dispatchers.Default) {
                session.syncRenames(renames.snapshot())
                session.decompile(className)
            } ?: return@launch
            javaTab?.let {
                if (Docking.isDocked(it)) Docking.undock(it)
                Docking.deregisterDockable(it)
            }
            val view = JavaView(
                result.code,
                result.sync,
                onCaret = { target -> bytecodeView?.followFromJava(target) },
                syncInitial = syncState,
                onSyncToggle = { state ->
                    syncState = state
                    bytecodeView?.syncApprox = state == FlatTriStateCheckBox.State.INDETERMINATE
                    if (state == FlatTriStateCheckBox.State.UNSELECTED) bytecodeView?.clearSyncHighlight()
                },
            )
            val tab = EditorTab("decompiled", result.title, view)
            javaTab = tab
            javaView = view
            val target = bytecodeTab
            if (target != null && Docking.isDocked(target)) Docking.dock(tab, target, DockingRegion.EAST, 0.5)
            else Docking.dock(tab, this@MainWindow, DockingRegion.EAST, 0.5)
            log.info("Decompiled $className")
        }
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
