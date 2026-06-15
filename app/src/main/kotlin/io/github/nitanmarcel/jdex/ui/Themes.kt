package io.github.nitanmarcel.jdex.ui

import com.formdev.flatlaf.FlatDarculaLaf
import com.formdev.flatlaf.FlatDarkLaf
import com.formdev.flatlaf.FlatIntelliJLaf
import com.formdev.flatlaf.FlatLaf
import com.formdev.flatlaf.FlatLightLaf
import com.formdev.flatlaf.intellijthemes.FlatArcDarkIJTheme
import com.formdev.flatlaf.intellijthemes.FlatArcIJTheme
import com.formdev.flatlaf.intellijthemes.FlatCobalt2IJTheme
import com.formdev.flatlaf.intellijthemes.FlatDraculaIJTheme
import com.formdev.flatlaf.intellijthemes.FlatGruvboxDarkHardIJTheme
import com.formdev.flatlaf.intellijthemes.FlatMonocaiIJTheme
import com.formdev.flatlaf.intellijthemes.FlatNordIJTheme
import com.formdev.flatlaf.intellijthemes.FlatOneDarkIJTheme
import com.formdev.flatlaf.intellijthemes.FlatSolarizedDarkIJTheme
import com.formdev.flatlaf.intellijthemes.FlatSolarizedLightIJTheme
import com.formdev.flatlaf.intellijthemes.FlatXcodeDarkIJTheme
import java.awt.Color
import java.awt.Font
import java.util.prefs.Preferences
import javax.swing.UIManager
import javax.swing.plaf.FontUIResource

object Themes {

    class Def(val id: String, val label: String, val dark: Boolean, val syntax: String, val create: () -> FlatLaf)

    val all: List<Def> = listOf(
        Def("light", "Light", false, "light") { FlatLightLaf() },
        Def("dark", "Dark", true, "dark") { FlatDarkLaf() },
        Def("intellij", "IntelliJ", false, "intellij") { FlatIntelliJLaf() },
        Def("darcula", "Darcula", true, "darcula") { FlatDarculaLaf() },
        Def("arc", "Arc", false, "arc") { FlatArcIJTheme() },
        Def("arc-dark", "Arc Dark", true, "arc-dark") { FlatArcDarkIJTheme() },
        Def("dracula", "Dracula", true, "dracula") { FlatDraculaIJTheme() },
        Def("nord", "Nord", true, "nord") { FlatNordIJTheme() },
        Def("one-dark", "One Dark", true, "one-dark") { FlatOneDarkIJTheme() },
        Def("gruvbox", "Gruvbox Dark", true, "gruvbox") { FlatGruvboxDarkHardIJTheme() },
        Def("monokai", "Monokai", true, "monokai") { FlatMonocaiIJTheme() },
        Def("cobalt2", "Cobalt 2", true, "cobalt2") { FlatCobalt2IJTheme() },
        Def("xcode-dark", "Xcode Dark", true, "xcode-dark") { FlatXcodeDarkIJTheme() },
        Def("solarized-light", "Solarized Light", false, "solarized-light") { FlatSolarizedLightIJTheme() },
        Def("solarized-dark", "Solarized Dark", true, "solarized-dark") { FlatSolarizedDarkIJTheme() },
    )

    fun select(id: String) {
        SyntaxThemes.baseId = def(id).syntax
        apply(id)
    }

    val chromeKeys: List<Pair<String, String>> = listOf(
        "@accentColor" to "Accent",
        "@background" to "Background",
        "@foreground" to "Foreground",
        "@selectionBackground" to "Selection",
        "Component.borderColor" to "Border",
        "Component.focusColor" to "Focus",
    )

    private val prefs = Preferences.userRoot().node("jdex/ui")
    private val chromePrefs = Preferences.userRoot().node("jdex/ui/chrome")

    var currentId: String
        get() = prefs.get("theme", "light").takeIf { id -> all.any { it.id == id } } ?: "light"
        private set(value) = prefs.put("theme", value)

    fun def(id: String): Def = all.firstOrNull { it.id == id } ?: all.first()
    val current: Def get() = def(currentId)

    fun chromeColor(key: String): Color? =
        chromePrefs.get(key, "").ifEmpty { null }?.let { runCatching { Color.decode(it) }.getOrNull() }

    fun setChromeColor(key: String, c: Color?) =
        if (c == null) chromePrefs.remove(key) else chromePrefs.put(key, hex(c))

    var accent: String?
        get() = chromePrefs.get("@accentColor", "").ifEmpty { null }
        set(value) = if (value.isNullOrBlank()) chromePrefs.remove("@accentColor") else chromePrefs.put("@accentColor", value)

    var uiFontFamily: String?
        get() = prefs.get("font.ui.family", "").ifEmpty { null }
        set(value) = if (value == null) prefs.remove("font.ui.family") else prefs.put("font.ui.family", value)
    var uiFontSize: Int
        get() = prefs.getInt("font.ui.size", 0)
        set(value) = prefs.putInt("font.ui.size", value)

    fun resetChrome() {
        chromePrefs.keys().forEach(chromePrefs::remove)
        uiFontFamily = null
        uiFontSize = 0
    }

    fun apply(id: String = currentId) {
        val extra = HashMap<String, String>()
        for ((key, _) in chromeKeys) chromeColor(key)?.let { extra[key] = hex(it) }
        FlatLaf.setGlobalExtraDefaults(extra)
        FlatLaf.setup(def(id).create())
        applyUiFont()
        currentId = id
        FlatLaf.updateUI()
        SyntaxThemes.applyAll()
    }

    private fun applyUiFont() {
        val fam = uiFontFamily
        val size = uiFontSize
        if (fam == null && size <= 0) return
        val base = UIManager.getFont("defaultFont") ?: return
        UIManager.put("defaultFont", FontUIResource(fam ?: base.family, Font.PLAIN, if (size > 0) size else base.size))
    }

    fun install() = apply()

    private fun hex(c: Color) = "#%06X".format(c.rgb and 0xFFFFFF)
}
