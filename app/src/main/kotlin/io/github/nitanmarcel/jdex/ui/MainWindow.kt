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
import io.github.nitanmarcel.jdex.project.HMembers
import io.github.nitanmarcel.jdex.project.NoBookmarks
import io.github.nitanmarcel.jdex.project.NoComments
import io.github.nitanmarcel.jdex.project.NoRenames
import io.github.nitanmarcel.jdex.project.Project
import io.github.nitanmarcel.jdex.project.Renames
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
import javax.swing.JFileChooser
import javax.swing.SwingUtilities
import javax.swing.JFrame
import javax.swing.JMenu
import javax.swing.JMenuBar
import javax.swing.JMenuItem
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

    init {
        defaultCloseOperation = EXIT_ON_CLOSE
        size = Dimension(1000, 700)
        setLocationRelativeTo(null)

        addWindowListener(object : WindowAdapter() {
            override fun windowClosing(e: WindowEvent) {
                runCatching { clearEditors() }
                runCatching { AppState.persist() }
                runCatching { scope.cancel() }
                runCatching { session?.close() }
                runCatching { project?.close() }
            }
        })

        Docking.initialize(this)
        add(RootDockingPanel(this))

        val editors = EditorAnchor()
        explorer = FilesPanel(::openView, onFindUsages = ::findInBytecode)
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

        jMenuBar = createMenuBar(editors, explorer, hierarchy, logger)
        updateRecentMenu()

        AppState.setAutoPersist(false)
        AppState.setPersistFile(File(System.getProperty("java.io.tmpdir"), "jdex-layout.xml"))

        AppState.setDefaultApplicationLayout(
            WindowLayoutBuilder("project_explorer")
                .dock("editors", "project_explorer", DockingRegion.EAST, 0.8)
                .dock("hierarchy", "project_explorer", DockingRegion.SOUTH, 0.5)
                .dockToRoot("logger", DockingRegion.SOUTH, 0.25)
                .buildApplicationLayout()
        )

        runCatching { AppState.restore() }
            .onFailure { log.warning("Discarded incompatible saved layout") }
    }

    private fun createMenuBar(editors: EditorAnchor, explorer: FilesPanel, hierarchy: HierarchyPanel, logger: LoggerPanel) = JMenuBar().apply {
        add(JMenu("File").apply {
            add(JMenuItem("Open…").apply {
                accelerator = shortcut(KeyEvent.VK_O)
                addActionListener { openWithChooser() }
            })
            add(recentMenu)
            addSeparator()
            add(saveItem.apply {
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
        })
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

        val input = project.input() ?: return
        explorer.clear()
        hierarchy.clear()
        log.info("Analyzing ${input.name}…")
        scope.launch {
            runCatching { withContext(Dispatchers.Default) { ApkSession.load(input, project.file.name) } }
                .onSuccess { loaded ->
                    session = loaded
                    explorer.show(loaded.root)
                    hierarchy.show(loaded.topClasses())
                    log.info("Loaded ${input.name}: package=${loaded.appPackage ?: "n/a"}, certs=${loaded.certificateCount}")
                    explorer.bytecode()?.let { (id, title, load) -> openView(id, title, load) }
                }
                .onFailure { log.log(Level.SEVERE, "Failed to analyze ${input.name}: ${it.message}") }
        }
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
