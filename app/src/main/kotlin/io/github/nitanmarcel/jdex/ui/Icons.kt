package io.github.nitanmarcel.jdex.ui

import com.formdev.flatlaf.extras.FlatSVGIcon
import org.fife.ui.rsyntaxtextarea.TokenTypes
import java.awt.Color
import java.awt.Component
import java.awt.Graphics
import javax.swing.Icon
import javax.swing.UIManager

object Icons {

    private val cache = HashMap<String, FlatSVGIcon>()

    fun of(name: String): FlatSVGIcon = cache.getOrPut(name) {
        FlatSVGIcon("icons/$name.svg").apply {
            colorFilter = FlatSVGIcon.ColorFilter { UIManager.getColor("Tree.foreground") ?: UIManager.getColor("Label.foreground") ?: it }
        }
    }

    val PACKAGE: Icon = KindIcon("symbol-namespace", TokenTypes.RESERVED_WORD, Color(0x45A29E))
    val CLASS: Icon = KindIcon("symbol-class", TokenTypes.DATA_TYPE, Color(0x59A869))
    val INTERFACE: Icon = KindIcon("symbol-interface", TokenTypes.DATA_TYPE, Color(0x3592C4))
    val ENUM: Icon = KindIcon("symbol-enum", TokenTypes.DATA_TYPE, Color(0xC57E3C))
    val METHOD: Icon = KindIcon("symbol-method", TokenTypes.FUNCTION, Color(0xB07CC6))
    val FIELD: Icon = KindIcon("symbol-field", TokenTypes.VARIABLE, Color(0x4F86C6))

    val FILE get() = of("file")
    val FILE_CODE get() = of("file-code")
    val FILE_BINARY get() = of("file-binary")
    val FOLDER get() = of("folder")
    val FOLDER_OPEN get() = of("folder-opened")
    val JSON get() = of("json")

    val RUN get() = of("play")
    val RESET get() = of("debug-restart")
    val CLEAR get() = of("clear-all")
    val SAVE get() = of("save")
    val SETTINGS get() = of("settings-gear")

    private class KindIcon(private val name: String, private val type: Int, private val fallback: Color) : Icon {
        private val tinted = HashMap<Int, FlatSVGIcon>()
        private val base = FlatSVGIcon("icons/$name.svg")

        private fun glyph(color: Color): FlatSVGIcon =
            tinted.getOrPut(color.rgb) { FlatSVGIcon("icons/$name.svg").apply { colorFilter = FlatSVGIcon.ColorFilter { color } } }

        override fun getIconWidth() = base.iconWidth
        override fun getIconHeight() = base.iconHeight

        override fun paintIcon(c: Component?, g: Graphics, x: Int, y: Int) {
            glyph(SyntaxThemes.iconColor(type, fallback)).paintIcon(c, g, x, y)
        }
    }
}
