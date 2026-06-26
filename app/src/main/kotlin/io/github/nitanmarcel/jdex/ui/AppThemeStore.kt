package io.github.nitanmarcel.jdex.ui

import java.awt.Color
import java.io.File
import java.util.Properties

object AppThemeStore {

    const val EXT = "jdextheme"
    private val dir = File(System.getProperty("user.home"), ".jdex/themes")
    private val editorColorKeys = listOf("background", "selection", "caret", "currentLine")

    fun snapshot(): Map<String, String> {
        val m = LinkedHashMap<String, String>()
        m["chrome.base"] = Themes.currentId
        for (ck in Themes.chromeKeys) Themes.chromeColor(ck.id)?.let { m["chrome.${ck.id}"] = hex(it) }
        Themes.uiFontFamily?.let { m["font.ui.family"] = it }
        if (Themes.uiFontSize > 0) m["font.ui.size"] = Themes.uiFontSize.toString()

        m["syntax.base"] = SyntaxThemes.baseId
        for (t in SyntaxThemes.tokens) {
            SyntaxThemes.tokenColor(t.key)?.let { m["syntax.token.${t.key}.fg"] = hex(it) }
            SyntaxThemes.tokenBold(t.key)?.let { m["syntax.token.${t.key}.bold"] = it.toString() }
            SyntaxThemes.tokenItalic(t.key)?.let { m["syntax.token.${t.key}.italic"] = it.toString() }
        }
        for (k in editorColorKeys) SyntaxThemes.editorColor(k)?.let { m["syntax.editor.$k"] = hex(it) }
        SyntaxThemes.editorFontFamily?.let { m["font.editor.family"] = it }
        if (SyntaxThemes.editorFontSize != 13) m["font.editor.size"] = SyntaxThemes.editorFontSize.toString()
        return m
    }

    fun applySnapshot(m: Map<String, String>) {
        Themes.resetChrome()
        SyntaxThemes.resetOverrides()
        for (ck in Themes.chromeKeys) color(m["chrome.${ck.id}"])?.let { Themes.setChromeColor(ck.id, it) }
        Themes.uiFontFamily = m["font.ui.family"]
        Themes.uiFontSize = m["font.ui.size"]?.toIntOrNull() ?: 0

        SyntaxThemes.baseId = m["syntax.base"] ?: SyntaxThemes.baseId
        for (t in SyntaxThemes.tokens) {
            color(m["syntax.token.${t.key}.fg"])?.let { SyntaxThemes.setTokenColor(t.key, it) }
            m["syntax.token.${t.key}.bold"]?.toBoolean()?.let { SyntaxThemes.setTokenBold(t.key, it) }
            m["syntax.token.${t.key}.italic"]?.toBoolean()?.let { SyntaxThemes.setTokenItalic(t.key, it) }
        }
        for (k in editorColorKeys) color(m["syntax.editor.$k"])?.let { SyntaxThemes.setEditorColor(k, it) }
        SyntaxThemes.editorFontFamily = m["font.editor.family"]
        SyntaxThemes.editorFontSize = m["font.editor.size"]?.toIntOrNull() ?: 13

        Themes.apply(m["chrome.base"] ?: Themes.currentId)
    }

    fun list(): List<String> =
        (dir.listFiles { f -> f.extension == EXT } ?: emptyArray()).map { it.nameWithoutExtension }.sorted()

    fun save(name: String) = writeTo(File(dir.apply { mkdirs() }, "$name.$EXT"))
    fun load(name: String) = readFrom(File(dir, "$name.$EXT"))
    fun delete(name: String) = File(dir, "$name.$EXT").delete()

    fun exportTo(file: File) = writeTo(file)
    fun importFrom(file: File) = readFrom(file)

    private fun writeTo(file: File) {
        val p = Properties()
        snapshot().forEach { (k, v) -> p.setProperty(k, v) }
        file.parentFile?.mkdirs()
        file.outputStream().use { p.store(it, "jdex theme") }
    }

    private fun readFrom(file: File) {
        if (!file.exists()) return
        val p = Properties()
        file.inputStream().use { p.load(it) }
        applySnapshot(p.entries.associate { it.key.toString() to it.value.toString() })
    }

    private fun hex(c: Color) = "#%06X".format(c.rgb and 0xFFFFFF)
    private fun color(s: String?): Color? = s?.let { runCatching { Color.decode(it) }.getOrNull() }
}
