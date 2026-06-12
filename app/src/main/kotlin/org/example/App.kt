package org.example

import com.formdev.flatlaf.FlatLightLaf
import org.example.ui.MainWindow
import java.util.logging.Logger
import javax.swing.SwingUtilities

private val log = Logger.getLogger("jdex")

fun main() {
    FlatLightLaf.setup()
    SwingUtilities.invokeLater {
        MainWindow().isVisible = true
        log.info("jdex started")
        log.info("Java: ${System.getProperty("java.version")} (${System.getProperty("java.vendor")})")
        log.info("OS: ${System.getProperty("os.name")} ${System.getProperty("os.arch")}")
        log.info("Memory: ${Runtime.getRuntime().maxMemory() / (1024 * 1024)}M max")
    }
}
