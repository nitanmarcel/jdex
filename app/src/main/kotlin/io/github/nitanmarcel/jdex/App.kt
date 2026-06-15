package io.github.nitanmarcel.jdex

import com.formdev.flatlaf.FlatLaf
import io.github.andrewauclair.moderndocking.ext.ui.DockingUI
import io.github.nitanmarcel.jdex.ui.CodeTextArea
import io.github.nitanmarcel.jdex.ui.MainWindow
import io.github.nitanmarcel.jdex.ui.Themes
import java.util.logging.Logger
import javax.swing.SwingUtilities

private val log = Logger.getLogger("jdex")

fun main() {
    FlatLaf.registerCustomDefaultsSource("docking")
    Themes.install()
    CodeTextArea.registerSyntaxStyles()
    SwingUtilities.invokeLater {
        DockingUI.initialize()
        MainWindow().isVisible = true
        log.info("jdex started")
        log.info("Java: ${System.getProperty("java.version")} (${System.getProperty("java.vendor")})")
        log.info("OS: ${System.getProperty("os.name")} ${System.getProperty("os.arch")}")
        log.info("Memory: ${Runtime.getRuntime().maxMemory() / (1024 * 1024)}M max")
    }
}
