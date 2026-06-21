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
import io.github.nitanmarcel.jdex.disasm.JniName
import io.github.nitanmarcel.jdex.project.ApkSession
import io.github.nitanmarcel.jdex.project.BinaryContent
import io.github.nitanmarcel.jdex.project.CodeContent
import io.github.nitanmarcel.jdex.project.Content
import io.github.nitanmarcel.jdex.project.NativeContent
import io.github.nitanmarcel.jdex.project.Syntax
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
    private var dexBytecodeTab: EditorTab? = null
    private var dexBytecodeView: VirtualCodeView? = null
    private var hierarchyClasses: List<io.github.nitanmarcel.jdex.project.HClass> = emptyList()
    private var hierarchyNativeView: VirtualCodeView? = null
    private lateinit var scripting: ScriptPanel

    init {
        defaultCloseOperation = DO_NOTHING_ON_CLOSE
        size = Dimension(1000, 700)
        setLocationRelativeTo(null)

        addWindowListener(object : WindowAdapter() {
            override fun windowClosing(e: WindowEvent) {
                if (!confirmDiscardChanges()) return
                runCatching { clearEditors() }
                runCatching { AppState.persist() }
                runCatching { scope.cancel() }
                runCatching { scripting.close() }
                runCatching { session?.close() }
                runCatching { project?.close() }
                kotlin.system.exitProcess(0)
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
            runCatching { withContext(Dispatchers.Default) { ApkSession.load(input, project.file?.name ?: input.name, project) } }
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
            when (content) {
                is CodeContent -> openCode(tabId, title, content)
                is NativeContent -> openNative(tabId, title, content)
                else -> {
                    val tab = EditorTab(tabId, title, Editors.component(content))
                    openTabs[tabId] = tab
                    Docking.dock(tab, "editors", DockingRegion.CENTER)
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
        val tab = EditorTab("pseudo", title, content)
        pseudoTab = tab
        val target = bytecodeTab
        if (target != null && Docking.isDocked(target)) Docking.dock(tab, target, DockingRegion.EAST, 0.5)
        else Docking.dock(tab, this@MainWindow, DockingRegion.EAST, 0.5)
        return area
    }

    private fun openNative(tabId: String, title: String, content: NativeContent) {
        val elf = io.github.nitanmarcel.jdex.disasm.ElfFile.parse(content.bytes)
        if (elf == null) {
            val tab = EditorTab(tabId, title, Editors.component(BinaryContent(content.bytes)))
            openTabs[tabId] = tab
            Docking.dock(tab, "editors", DockingRegion.CENTER)
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
        val code = CodeContent(Syntax.ASM, x86Is32, nativeId, segments, info) { progress, cancel ->
            io.github.nitanmarcel.jdex.disasm.NativeListing.build(elf, choice.disassembler, choice.arch, choice.littleEndian, progress, cancel, info.summary)
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
        return io.github.nitanmarcel.jdex.project.NativeInfo(exports, imports, constructors, summary)
    }

    private fun openCode(tabId: String, title: String, content: CodeContent) {
        val cancelled = AtomicBoolean(false)
        val label = if (content.syntax == Syntax.ASM) "Disassembling" else "Generating bytecode"
        val unit = if (content.syntax == Syntax.ASM) "bytes" else "classes"
        val dialog = LoadingDialog(this, label, unit, onCancel = { cancelled.set(true) })
        Thread({
            val result = runCatching {
                content.generate({ current, total -> SwingUtilities.invokeLater { dialog.progress(current, total) } }, cancelled::get)
            }
            result.exceptionOrNull()?.let { if (it !is io.github.nitanmarcel.jdex.project.GenerationCancelled) log.log(Level.WARNING, "Generation failed", it) }
            val source = result.getOrNull()
            SwingUtilities.invokeLater {
                dialog.dispose()
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
                        cfgProvider = { raw, shortId -> session?.methodCfg(raw, shortId) },
                        onText = { title, text, syntax, north -> openText(title, text, syntax, north) },
                        onNativeJump = { cls, method, sig -> jumpToNativeExport(cls, method, sig) },
                        onBytecodeJump = { symbol, jniName, jniSig -> jumpToBytecodeMethod(symbol, jniName, jniSig) },
                        onNativeExportRename = { symbol, jniName, jniSig, name -> propagateExportRename(symbol, jniName, jniSig, name) },
                        onActivated = { v -> onViewActivated(v) },
                    )
                    val tab = EditorTab(tabId, title, view, source)
                    openTabs[tabId] = tab
                    if (content.syntax == Syntax.ASM) {
                        nativeViews.add(Triple(tab, view, source))
                        content.nativeId?.let { renames.setNativeJniBindings(it, buildJniBindings(source)) }
                    } else {
                        bytecodeTab = tab
                        bytecodeView = view
                        dexBytecodeTab = tab
                        dexBytecodeView = view
                    }
                    view.syncApprox = syncState == FlatTriStateCheckBox.State.INDETERMINATE
                    Docking.dock(tab, "editors", DockingRegion.CENTER)
                    log.info("Opened ${if (content.syntax == Syntax.ASM) "disassembly" else "bytecode"} (${source.lineCount} lines)")
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
        nativeViews.clear()
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

    private fun navigateBytecode(action: (VirtualCodeView) -> Unit) {
        val tab = bytecodeTab ?: return
        val view = bytecodeView ?: return
        if (Docking.isDocked(tab)) Docking.bringToFront(tab)
        action(view)
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
            onCaret = { target -> bytecodeView?.followFromJava(target) },
            syncState = syncState,
            onSyncToggle = { state ->
                syncState = state
                bytecodeView?.syncApprox = state == FlatTriStateCheckBox.State.INDETERMINATE
                if (state == FlatTriStateCheckBox.State.UNSELECTED) bytecodeView?.clearSyncHighlight()
            },
        )
        val tab = EditorTab("decompiled", className.substringAfterLast('.'), view)
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
