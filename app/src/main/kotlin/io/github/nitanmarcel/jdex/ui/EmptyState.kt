package io.github.nitanmarcel.jdex.ui

import com.formdev.flatlaf.extras.FlatSVGIcon
import java.awt.GridBagLayout
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JLabel
import javax.swing.JPanel

class EmptyState(iconName: String, title: String, subtitle: String? = null) : JPanel(GridBagLayout()) {
    init {
        val icon = FlatSVGIcon("icons/$iconName.svg").derive(48, 48).apply {
            colorFilter = FlatSVGIcon.ColorFilter { UiColors.disabled() }
        }
        val box = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
            add(JLabel(icon).apply { alignmentX = CENTER_ALIGNMENT })
            add(Box.createVerticalStrut(12))
            add(JLabel(title).apply {
                alignmentX = CENTER_ALIGNMENT
                foreground = UiColors.disabled()
                putClientProperty(com.formdev.flatlaf.FlatClientProperties.STYLE_CLASS, "h3")
            })
            subtitle?.let {
                add(Box.createVerticalStrut(4))
                add(JLabel(it).apply {
                    alignmentX = CENTER_ALIGNMENT
                    foreground = UiColors.disabled()
                    font = font.deriveFont(font.size2D - 1f)
                })
            }
        }
        add(box)
    }
}
