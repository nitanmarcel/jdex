package org.example.ui

import io.github.andrewauclair.moderndocking.DockingRegion
import io.github.andrewauclair.moderndocking.app.AppState
import io.github.andrewauclair.moderndocking.Dockable
import io.github.andrewauclair.moderndocking.app.Docking
import io.github.andrewauclair.moderndocking.app.RootDockingPanel
import io.github.andrewauclair.moderndocking.app.WindowLayoutBuilder
import org.example.RecentFiles
import org.example.project.Project
import java.awt.Dimension
import java.awt.Toolkit
import java.awt.event.KeyEvent
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import java.io.File
import java.util.logging.Logger
import javax.swing.JFileChooser
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
    private var project: Project? = null

    init {
        defaultCloseOperation = EXIT_ON_CLOSE
        size = Dimension(1000, 700)
        setLocationRelativeTo(null)

        addWindowListener(object : WindowAdapter() {
            override fun windowClosing(e: WindowEvent) {
                project?.close()
            }
        })

        Docking.initialize(this)
        add(RootDockingPanel(this))

        val editors = EditorAnchor()
        val explorer = FilesPanel()
        val logger = LoggerPanel()

        jMenuBar = createMenuBar(editors, explorer, logger)
        updateRecentMenu()

        AppState.setAutoPersist(true)
        AppState.setPersistFile(File(System.getProperty("java.io.tmpdir"), "jdex-layout.xml"))

        AppState.setDefaultApplicationLayout(
            WindowLayoutBuilder("project_explorer")
                .dock("editors", "project_explorer", DockingRegion.EAST, 0.8)
                .dockToRoot("logger", DockingRegion.SOUTH, 0.25)
                .buildApplicationLayout()
        )

        AppState.restore()
    }

    private fun createMenuBar(editors: EditorAnchor, explorer: FilesPanel, logger: LoggerPanel) = JMenuBar().apply {
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
        project?.close()
        project = if (file.extension == Project.EXTENSION) Project.open(file) else Project.forInput(file)
        recentFiles.add(file)
        updateRecentMenu()
        saveItem.isEnabled = true
        title = "jdex — ${(project?.input() ?: file).name}"
        log.info("Opened project ${project?.file?.absolutePath}")
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
