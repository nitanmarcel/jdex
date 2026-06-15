package io.github.nitanmarcel.jdex.ui

import java.awt.Color
import javax.swing.UIManager

object UiColors {

    fun accent(): Color = UIManager.getColor("Component.accentColor")
        ?: UIManager.getColor("Component.focusColor") ?: Color(0x2675BF)

    fun border(): Color = UIManager.getColor("Component.borderColor") ?: Color.GRAY

    fun error(): Color = UIManager.getColor("Actions.Red") ?: Color(0xC0392B)

    fun success(): Color = UIManager.getColor("Actions.Green") ?: Color(0x2E863C)

    fun info(): Color = UIManager.getColor("Actions.Blue") ?: Color(0x3592C4)

    fun alpha(c: Color, a: Int): Color = Color(c.red, c.green, c.blue, a)
}
