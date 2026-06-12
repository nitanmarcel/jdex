package org.example.ui

import com.formdev.flatlaf.FlatLightLaf
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assumptions.assumeFalse
import org.junit.jupiter.api.Test
import java.awt.GraphicsEnvironment
import javax.swing.SwingUtilities

class MainWindowTest {

    @Test
    fun hasExpectedTitle() {
        assumeFalse(GraphicsEnvironment.isHeadless(), "Requires a display")
        var title = ""
        SwingUtilities.invokeAndWait {
            FlatLightLaf.setup()
            title = MainWindow().title
        }
        assertEquals("jdex", title)
    }
}
