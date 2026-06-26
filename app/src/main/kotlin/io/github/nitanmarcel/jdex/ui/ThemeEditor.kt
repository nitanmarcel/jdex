package io.github.nitanmarcel.jdex.ui

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea
import org.fife.ui.rsyntaxtextarea.SyntaxConstants
import org.fife.ui.rtextarea.RTextScrollPane
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Cursor
import java.awt.Dimension
import java.awt.Font
import java.awt.GraphicsEnvironment
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.Window
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.io.File
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JColorChooser
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JFileChooser
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSpinner
import javax.swing.JTabbedPane
import javax.swing.SpinnerNumberModel
import javax.swing.SwingConstants
import javax.swing.UIManager
import javax.swing.filechooser.FileNameExtensionFilter

class ThemeEditor private constructor(owner: Window?) : JDialog(owner, "Theme Editor", ModalityType.MODELESS) {

    private val refreshers = ArrayList<() -> Unit>()
    private val fonts = GraphicsEnvironment.getLocalGraphicsEnvironment().availableFontFamilyNames

    private val preview = RSyntaxTextArea(8, 44).apply {
        isEditable = false
        syntaxEditingStyle = SyntaxConstants.SYNTAX_STYLE_JAVA
        antiAliasingEnabled = true
        text = SAMPLE
        caretPosition = 0
    }

    init {
        SyntaxThemes.attach(preview)

        val tabs = JTabbedPane().apply {
            addTab("Chrome", chromeTab())
            addTab("Syntax", syntaxTab())
            addTab("Fonts", fontsTab())
        }

        val previewPanel = JPanel(BorderLayout()).apply {
            border = BorderFactory.createTitledBorder("Preview")
            add(sampleComponents(), BorderLayout.NORTH)
            add(RTextScrollPane(preview), BorderLayout.CENTER)
            preferredSize = Dimension(460, 0)
        }

        contentPane.layout = BorderLayout()
        contentPane.add(themeBar(), BorderLayout.NORTH)
        contentPane.add(tabs, BorderLayout.WEST)
        contentPane.add(previewPanel, BorderLayout.CENTER)
        pack()
        setLocationRelativeTo(owner)
    }

    private fun themeBar(): JComponent {
        val combo = JComboBox<String>()
        fun reload(select: String? = null) {
            combo.removeAllItems()
            combo.addItem("(current)")
            AppThemeStore.list().forEach { combo.addItem(it) }
            if (select != null) combo.selectedItem = select
        }
        reload()
        combo.addActionListener {
            val name = combo.selectedItem as? String ?: return@addActionListener
            if (name != "(current)") { runCatching { AppThemeStore.load(name) }; refreshAll() }
        }
        return JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            border = BorderFactory.createEmptyBorder(6, 8, 6, 8)
            add(JLabel("Theme: "))
            add(combo)
            add(Box.createHorizontalStrut(8))
            add(JButton("Save As…").apply {
                addActionListener {
                    val name = JOptionPane.showInputDialog(this@ThemeEditor, "Theme name:") ?: return@addActionListener
                    if (name.isNotBlank()) { AppThemeStore.save(name.trim()); reload(name.trim()) }
                }
            })
            add(JButton("Delete").apply {
                addActionListener {
                    val name = combo.selectedItem as? String ?: return@addActionListener
                    if (name != "(current)") { AppThemeStore.delete(name); reload() }
                }
            })
            add(JButton("Import…").apply {
                addActionListener { chooseFile(false)?.let { AppThemeStore.importFrom(it); refreshAll(); reload() } }
            })
            add(JButton("Export…").apply {
                addActionListener { chooseFile(true)?.let { AppThemeStore.exportTo(it) } }
            })
            add(Box.createHorizontalGlue())
            add(JButton("Reset all").apply {
                addActionListener { Themes.resetChrome(); SyntaxThemes.resetOverrides(); Themes.apply(); refreshAll() }
            })
        }
    }

    private fun chooseFile(save: Boolean): File? {
        val c = JFileChooser()
        c.fileFilter = FileNameExtensionFilter("jdex theme (*.${AppThemeStore.EXT})", AppThemeStore.EXT)
        val r = if (save) c.showSaveDialog(this) else c.showOpenDialog(this)
        if (r != JFileChooser.APPROVE_OPTION) return null
        val f = c.selectedFile
        return if (save && f.extension != AppThemeStore.EXT) File(f.parentFile, "${f.name}.${AppThemeStore.EXT}") else f
    }

    private fun chromeTab(): JComponent {
        val panel = JPanel(GridBagLayout())
        val g = grid()
        panel.add(JLabel("Base theme:"), g.at(0, 0))
        panel.add(baseCombo(Themes.all.map { it.label }, Themes.all.indexOfFirst { it.id == Themes.currentId }) {
            Themes.resetChromeColors(); SyntaxThemes.resetColorOverrides(); Themes.select(Themes.all[it].id); refreshAll()
        }, g.at(1, 0, 2))
        var row = 1
        for (ck in Themes.chromeKeys) {
            panel.add(JLabel(ck.label), g.at(0, row))
            panel.add(swatch({ Themes.chromeColor(ck.id) ?: resolveChrome(ck.id) }) { Themes.setChromeColor(ck.id, it); Themes.apply(); refreshAll() }, g.at(1, row))
            row++
        }
        return wrap(panel)
    }

    private fun syntaxTab(): JComponent {
        val panel = JPanel(GridBagLayout())
        val g = grid()
        panel.add(JLabel("Base:"), g.at(0, 0))
        panel.add(baseCombo(SyntaxThemes.bases.map { it.second }, SyntaxThemes.bases.indexOfFirst { it.first == SyntaxThemes.baseId }) {
            SyntaxThemes.baseId = SyntaxThemes.bases[it].first; SyntaxThemes.applyAll(); refreshAll()
        }, g.at(1, 0, 3))
        var row = 1
        for ((key, label) in listOf("background" to "Background", "selection" to "Selection", "caret" to "Caret", "currentLine" to "Current line")) {
            panel.add(JLabel(label), g.at(0, row))
            panel.add(swatch({ editorColorOf(key) }) { SyntaxThemes.setEditorColor(key, it); SyntaxThemes.applyAll(); refreshAll() }, g.at(1, row))
            row++
        }
        for (t in SyntaxThemes.tokens) {
            panel.add(JLabel(t.label), g.at(0, row))
            panel.add(swatch({ SyntaxThemes.theme().scheme.getStyle(t.type)?.foreground }) { SyntaxThemes.setTokenColor(t.key, it); SyntaxThemes.applyAll(); refreshAll() }, g.at(1, row))
            panel.add(JCheckBox("B", SyntaxThemes.tokenBold(t.key) == true).apply { addActionListener { SyntaxThemes.setTokenBold(t.key, isSelected); SyntaxThemes.applyAll() } }, g.at(2, row))
            panel.add(JCheckBox("I", SyntaxThemes.tokenItalic(t.key) == true).apply { addActionListener { SyntaxThemes.setTokenItalic(t.key, isSelected); SyntaxThemes.applyAll() } }, g.at(3, row))
            row++
        }
        return wrap(panel)
    }

    private fun fontsTab(): JComponent {
        val panel = JPanel(GridBagLayout())
        val g = grid()
        panel.add(JLabel("UI font:"), g.at(0, 0))
        panel.add(fontCombo({ Themes.uiFontFamily }) { Themes.uiFontFamily = it; Themes.apply() }, g.at(1, 0))
        panel.add(sizeSpinner({ if (Themes.uiFontSize > 0) Themes.uiFontSize else UIManager.getFont("defaultFont")?.size ?: 12 }) { Themes.uiFontSize = it; Themes.apply() }, g.at(2, 0))
        panel.add(JLabel("Editor font:"), g.at(0, 1))
        panel.add(fontCombo({ SyntaxThemes.editorFontFamily }) { SyntaxThemes.editorFontFamily = it; SyntaxThemes.applyAll() }, g.at(1, 1))
        panel.add(sizeSpinner({ SyntaxThemes.editorFontSize }) { SyntaxThemes.editorFontSize = it; SyntaxThemes.applyAll() }, g.at(2, 1))
        return wrap(panel)
    }

    private fun baseCombo(labels: List<String>, selected: Int, onPick: (Int) -> Unit): JComboBox<String> =
        JComboBox(labels.toTypedArray()).apply {
            selectedIndex = selected.coerceAtLeast(0)
            addActionListener { onPick(selectedIndex) }
        }

    private fun fontCombo(current: () -> String?, onPick: (String?) -> Unit): JComboBox<String> {
        val combo = JComboBox((listOf("Default") + fonts.toList()).toTypedArray())
        var sync = false
        combo.selectedItem = current() ?: "Default"
        combo.addActionListener { if (!sync) onPick((combo.selectedItem as String).takeIf { it != "Default" }) }
        refreshers.add { sync = true; combo.selectedItem = current() ?: "Default"; sync = false }
        return combo
    }

    private fun sizeSpinner(value: () -> Int, onChange: (Int) -> Unit): JSpinner {
        val spinner = JSpinner(SpinnerNumberModel(value().coerceIn(8, 40), 8, 40, 1))
        var sync = false
        spinner.addChangeListener { if (!sync) onChange(spinner.value as Int) }
        refreshers.add { sync = true; spinner.value = value().coerceIn(8, 40); sync = false }
        return spinner
    }

    private fun swatch(current: () -> Color?, onPick: (Color) -> Unit): JComponent {
        val sw = object : JComponent() {
            var color: Color? = current()
            override fun paintComponent(gr: java.awt.Graphics) {
                gr.color = color ?: UIManager.getColor("Panel.background") ?: Color.GRAY
                gr.fillRect(0, 0, width, height)
            }
        }.apply {
            preferredSize = Dimension(46, 18)
            border = BorderFactory.createLineBorder(UIManager.getColor("Component.borderColor") ?: Color.GRAY)
            cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
            toolTipText = "Click to choose color"
        }
        sw.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                JColorChooser.showDialog(this@ThemeEditor, "Choose color", sw.color ?: Color.GRAY)?.let { onPick(it) }
            }
        })
        refreshers.add { sw.color = current(); sw.repaint() }
        return sw
    }

    private fun sampleComponents(): JComponent = JPanel().apply {
        border = BorderFactory.createEmptyBorder(4, 4, 8, 4)
        add(JButton("Button"))
        add(JCheckBox("Check", true))
        add(JComboBox(arrayOf("Combo")))
    }

    private fun refreshAll() = refreshers.forEach { runCatching { it() } }

    private fun resolveChrome(key: String): Color? = when (key) {
        "@accentColor" -> UIManager.getColor("Component.accentColor") ?: UIManager.getColor("Component.focusColor")
        "@background" -> UIManager.getColor("Panel.background")
        "componentBackground" -> UIManager.getColor("TextField.background") ?: UIManager.getColor("List.background")
        "@foreground" -> UIManager.getColor("Label.foreground")
        "@selectionBackground" -> UIManager.getColor("List.selectionBackground")
        "Actions.Red" -> UiColors.error()
        "Actions.Yellow" -> UiColors.warning()
        "Actions.Green" -> UiColors.success()
        "Actions.Blue" -> UiColors.info()
        "Label.disabledForeground" -> UiColors.disabled()
        else -> UIManager.getColor(key)
    }

    private fun editorColorOf(key: String): Color? = SyntaxThemes.theme().let {
        when (key) {
            "background" -> it.bgColor
            "selection" -> it.selectionBG
            "caret" -> it.caretColor
            "currentLine" -> it.currentLineHighlight
            else -> null
        }
    }

    private fun grid() = object {
        val c = GridBagConstraints().apply { insets = Insets(3, 6, 3, 6); anchor = GridBagConstraints.WEST }
        fun at(x: Int, y: Int, w: Int = 1): GridBagConstraints =
            c.apply { gridx = x; gridy = y; gridwidth = w; weightx = if (x == 0) 0.0 else 1.0; fill = GridBagConstraints.NONE }
    }

    private fun wrap(p: JComponent): JComponent = JScrollPane(JPanel(BorderLayout()).apply { add(p, BorderLayout.NORTH) }).apply {
        preferredSize = Dimension(330, 460)
        horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
    }

    companion object {
        private var instance: ThemeEditor? = null

        fun open(owner: Window?) {
            val e = instance?.takeIf { it.isDisplayable } ?: ThemeEditor(owner).also { instance = it }
            e.isVisible = true
            e.toFront()
        }

        private val SAMPLE = """
            // preview of your syntax theme
            package com.example;

            @Override
            public final class Demo extends Base {
                private static final int COUNT = 42;
                private String name = "hello world";

                public int compute(int x) {
                    if (x > COUNT) return x * 0x10; // inline
                    return name.length();
                }
            }
        """.trimIndent()

        private val MONO = Font(Font.MONOSPACED, Font.PLAIN, 13)
    }
}
