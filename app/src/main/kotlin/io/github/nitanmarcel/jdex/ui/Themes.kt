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

    private val curated: List<Def> = listOf(
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

    private val curatedClasses = setOf(
        "com.formdev.flatlaf.intellijthemes.FlatArcIJTheme",
        "com.formdev.flatlaf.intellijthemes.FlatArcDarkIJTheme",
        "com.formdev.flatlaf.intellijthemes.FlatDraculaIJTheme",
        "com.formdev.flatlaf.intellijthemes.FlatNordIJTheme",
        "com.formdev.flatlaf.intellijthemes.FlatOneDarkIJTheme",
        "com.formdev.flatlaf.intellijthemes.FlatGruvboxDarkHardIJTheme",
        "com.formdev.flatlaf.intellijthemes.FlatMonocaiIJTheme",
        "com.formdev.flatlaf.intellijthemes.FlatCobalt2IJTheme",
        "com.formdev.flatlaf.intellijthemes.FlatXcodeDarkIJTheme",
        "com.formdev.flatlaf.intellijthemes.FlatSolarizedLightIJTheme",
        "com.formdev.flatlaf.intellijthemes.FlatSolarizedDarkIJTheme",
    )

    val all: List<Def> = curated + com.formdev.flatlaf.intellijthemes.FlatAllIJThemes.INFOS
        .filter { it.className !in curatedClasses }
        .map { info ->
            Def(slug(info.name), info.name, info.isDark, if (info.isDark) "dark" else "light") {
                Class.forName(info.className).getDeclaredConstructor().newInstance() as FlatLaf
            }
        }

    private fun slug(s: String) = s.lowercase().replace(Regex("[^a-z0-9]+"), "-").trim('-')

    fun select(id: String) {
        SyntaxThemes.baseId = def(id).syntax
        apply(id)
    }

    class ChromeKey(val id: String, val label: String, val targets: List<String> = listOf(id))

    val chromeKeys: List<ChromeKey> = listOf(
        ChromeKey("@accentColor", "Accent"),
        ChromeKey("@background", "Window background", listOf(
            "@background", "Panel.background", "MenuBar.background", "ToolBar.background",
            "TabbedPane.background", "Viewport.background", "ScrollPane.background",
            "SplitPane.background", "RootPane.background", "OptionPane.background",
            "TableHeader.background", "ModernDocking.headerBackground",
            "PopupMenu.background", "Menu.background", "MenuItem.background",
            "CheckBoxMenuItem.background", "RadioButtonMenuItem.background",
            "TabbedPane.selectedBackground", "TabbedPane.focusColor",
        )),
        ChromeKey("componentBackground", "Component background", listOf(
            "TextField.background", "FormattedTextField.background", "PasswordField.background",
            "TextArea.background", "TextPane.background", "EditorPane.background",
            "Spinner.background", "ComboBox.background", "ComboBox.nonEditableBackground",
            "ComboBox.buttonBackground", "ComboBox.buttonEditableBackground", "ComboBox.buttonFocusedEditableBackground",
            "List.background", "Tree.background", "Table.background",
            "CheckBox.icon.background", "CheckBox.icon.selectedBackground",
            "RadioButton.icon.background", "RadioButton.icon.selectedBackground",
            "Button.background", "Button.startBackground", "Button.endBackground", "ToggleButton.background",
        )),
        ChromeKey("@foreground", "Foreground"),
        ChromeKey("@selectionBackground", "Selection", listOf(
            "@selectionBackground", "List.selectionBackground", "Tree.selectionBackground",
            "Table.selectionBackground", "Table.lightSelectionBackground",
            "Menu.selectionBackground", "MenuItem.selectionBackground",
        )),
        ChromeKey("Component.borderColor", "Border"),
        ChromeKey("Component.focusColor", "Focus", listOf(
            "Component.focusColor", "Component.focusedBorderColor", "Button.focusedBorderColor",
        )),
        ChromeKey("Actions.Red", "Error / breakpoint"),
        ChromeKey("Actions.Yellow", "Warning / debug pointer"),
        ChromeKey("Actions.Green", "Success / debug line"),
        ChromeKey("Actions.Blue", "Info / bookmark"),
        ChromeKey("Label.disabledForeground", "Disabled text"),
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

    fun resetChromeColors() = chromePrefs.keys().forEach(chromePrefs::remove)

    fun apply(id: String = currentId) {
        val extra = HashMap<String, String>()
        for (ck in chromeKeys) chromeColor(ck.id)?.let { c -> ck.targets.forEach { extra[it] = hex(c) } }
        FlatLaf.setGlobalExtraDefaults(extra)
        FlatLaf.setup(def(id).create())
        applyUiFont()
        currentId = id
        FlatLaf.updateUI()
        SyntaxThemes.applyAll()
    }

    private fun applyUiFont() {
        UIManager.put("defaultFont", null)
        val fam = uiFontFamily
        val size = uiFontSize
        if (fam == null && size <= 0) return
        val base = UIManager.getFont("defaultFont") ?: return
        UIManager.put("defaultFont", FontUIResource(fam ?: base.family, Font.PLAIN, if (size > 0) size else base.size))
    }

    fun install() = apply()

    private fun hex(c: Color) = "#%06X".format(c.rgb and 0xFFFFFF)
}
