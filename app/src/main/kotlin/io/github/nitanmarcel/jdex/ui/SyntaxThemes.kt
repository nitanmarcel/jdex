package io.github.nitanmarcel.jdex.ui

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea
import org.fife.ui.rsyntaxtextarea.Theme
import org.fife.ui.rsyntaxtextarea.TokenTypes
import java.awt.Color
import java.util.Collections
import java.util.WeakHashMap
import java.util.prefs.Preferences

object SyntaxThemes {

    interface Rethemeable {
        fun retheme()
    }

    class TokenEntry(val key: String, val label: String, val type: Int)

    val tokens: List<TokenEntry> = listOf(
        TokenEntry("comment", "Comment", TokenTypes.COMMENT_EOL),
        TokenEntry("keyword", "Keyword", TokenTypes.RESERVED_WORD),
        TokenEntry("keyword2", "Keyword 2", TokenTypes.RESERVED_WORD_2),
        TokenEntry("type", "Data type", TokenTypes.DATA_TYPE),
        TokenEntry("function", "Function", TokenTypes.FUNCTION),
        TokenEntry("string", "String", TokenTypes.LITERAL_STRING_DOUBLE_QUOTE),
        TokenEntry("char", "Char", TokenTypes.LITERAL_CHAR),
        TokenEntry("number", "Number", TokenTypes.LITERAL_NUMBER_DECIMAL_INT),
        TokenEntry("operator", "Operator", TokenTypes.OPERATOR),
        TokenEntry("identifier", "Identifier", TokenTypes.IDENTIFIER),
        TokenEntry("variable", "Variable", TokenTypes.VARIABLE),
        TokenEntry("annotation", "Annotation", TokenTypes.ANNOTATION),
        TokenEntry("preprocessor", "Directive", TokenTypes.PREPROCESSOR),
    )

    val bases: List<Pair<String, String>> = listOf(
        "light" to "Light",
        "dark" to "Dark",
        "intellij" to "IntelliJ",
        "darcula" to "Darcula",
        "arc" to "Arc",
        "arc-dark" to "Arc Dark",
        "dracula" to "Dracula",
        "nord" to "Nord",
        "one-dark" to "One Dark",
        "gruvbox" to "Gruvbox Dark",
        "monokai" to "Monokai",
        "cobalt2" to "Cobalt 2",
        "xcode-dark" to "Xcode Dark",
        "solarized-light" to "Solarized Light",
        "solarized-dark" to "Solarized Dark",
    )

    private val prefs = Preferences.userRoot().node("jdex/ui/syntax")
    private val targets = Collections.newSetFromMap(WeakHashMap<Rethemeable, Boolean>())

    var baseId: String
        get() = prefs.get("base", "light").takeIf { id -> bases.any { it.first == id } } ?: "light"
        set(value) { prefs.put("base", value) }

    private fun loadBase(): Theme =
        Theme.load(SyntaxThemes::class.java.getResourceAsStream("/syntax/$baseId.xml"))

    private fun colorPref(key: String): Color? =
        prefs.get(key, "").ifEmpty { null }?.let { runCatching { Color.decode(it) }.getOrNull() }

    private fun putColor(key: String, c: Color?) =
        if (c == null) prefs.remove(key) else prefs.put(key, "#%06X".format(c.rgb and 0xFFFFFF))

    fun editorColor(key: String): Color? = colorPref("editor.$key")
    fun setEditorColor(key: String, c: Color?) = putColor("editor.$key", c)

    fun tokenColor(key: String): Color? = colorPref("token.$key.fg")
    fun setTokenColor(key: String, c: Color?) = putColor("token.$key.fg", c)
    fun tokenBold(key: String): Boolean? = prefs.get("token.$key.bold", "").ifEmpty { null }?.toBoolean()
    fun setTokenBold(key: String, v: Boolean?) = if (v == null) prefs.remove("token.$key.bold") else prefs.putBoolean("token.$key.bold", v)
    fun tokenItalic(key: String): Boolean? = prefs.get("token.$key.italic", "").ifEmpty { null }?.toBoolean()
    fun setTokenItalic(key: String, v: Boolean?) = if (v == null) prefs.remove("token.$key.italic") else prefs.putBoolean("token.$key.italic", v)

    var editorFontFamily: String?
        get() = prefs.get("font.family", "").ifEmpty { null }
        set(value) = if (value == null) prefs.remove("font.family") else prefs.put("font.family", value)
    var editorFontSize: Int
        get() = prefs.getInt("font.size", 13)
        set(value) = prefs.putInt("font.size", value)

    fun editorFont(): java.awt.Font =
        java.awt.Font(editorFontFamily ?: java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, editorFontSize.coerceAtLeast(8))

    fun resetOverrides() {
        prefs.keys().filter { it.startsWith("editor.") || it.startsWith("token.") || it.startsWith("font.") }.forEach(prefs::remove)
    }

    private var cachedTheme: Theme? = null

    fun theme(): Theme = cachedTheme ?: buildTheme().also { cachedTheme = it }

    fun iconColor(type: Int, fallback: java.awt.Color): java.awt.Color =
        theme().scheme.getStyle(type)?.foreground ?: fallback

    private fun buildTheme(): Theme {
        val t = loadBase()
        editorColor("background")?.let { t.bgColor = it }
        editorColor("selection")?.let { t.selectionBG = it }
        editorColor("caret")?.let { t.caretColor = it }
        editorColor("currentLine")?.let { t.currentLineHighlight = it }
        for (entry in tokens) {
            val style = t.scheme.getStyle(entry.type) ?: continue
            tokenColor(entry.key)?.let { style.foreground = it }
            val bold = tokenBold(entry.key)
            val italic = tokenItalic(entry.key)
            if (bold != null || italic != null) {
                val base = style.font ?: t.baseFont
                if (base != null) {
                    var s = base.style
                    bold?.let { s = if (it) s or java.awt.Font.BOLD else s and java.awt.Font.BOLD.inv() }
                    italic?.let { s = if (it) s or java.awt.Font.ITALIC else s and java.awt.Font.ITALIC.inv() }
                    style.font = base.deriveFont(s)
                }
            }
        }
        return t
    }

    fun applyTo(area: RSyntaxTextArea) {
        runCatching { theme().apply(area) }
        area.font = editorFont()
    }

    fun register(target: Rethemeable) {
        targets.add(target)
        runCatching { target.retheme() }
    }

    fun attach(area: RSyntaxTextArea) {
        val r = object : Rethemeable {
            override fun retheme() = applyTo(area)
        }
        area.putClientProperty("jdex.retheme", r)
        register(r)
    }

    fun applyAll() {
        cachedTheme = null
        targets.toList().forEach { runCatching { it.retheme() } }
    }

    fun foregroundOf(t: Theme): Color = t.scheme.getStyle(TokenTypes.IDENTIFIER)?.foreground ?: Color.BLACK
}
