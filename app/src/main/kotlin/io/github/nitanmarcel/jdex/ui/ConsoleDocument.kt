package io.github.nitanmarcel.jdex.ui

import javax.swing.JTextArea
import javax.swing.text.AbstractDocument
import javax.swing.text.AttributeSet
import javax.swing.text.DocumentFilter

class ConsoleDocument(private val area: JTextArea) {

    var inputStart = 0
        private set

    @Volatile var running = false

    private var guard = false

    private var outCol = 0

    init {
        (area.document as AbstractDocument).documentFilter = Filter()
    }

    fun write(text: String) = guarded {
        area.document.insertString(area.document.length, text, null)
    }

    fun prompt(text: String) {
        write(text)
        outCol = 0
        inputStart = area.document.length
        area.caretPosition = inputStart
    }

    fun appendOutput(text: String) {
        val out = reflow(text)
        guarded { area.document.insertString(inputStart, out, null) }
        inputStart += out.length
    }

    private fun reflow(text: String): String {
        val out = StringBuilder(text.length + text.length / MAX_LINE + 1)
        for (ch in text) {
            if (ch == '\n') {
                out.append(ch)
                outCol = 0
                continue
            }
            if (outCol == MAX_LINE) {
                out.append('\n')
                outCol = 0
            }
            out.append(ch)
            outCol++
        }
        return out.toString()
    }

    fun input(): String = area.document.getText(inputStart, area.document.length - inputStart)

    fun endInput() { inputStart = area.document.length }

    fun setInput(text: String) = replace(inputStart, area.document.length - inputStart, text)

    fun replace(offset: Int, len: Int, str: String) {
        guarded {
            if (len > 0) area.document.remove(offset, len)
            area.document.insertString(offset, str, null)
        }
        area.caretPosition = offset + str.length
    }

    fun clear() {
        guarded { area.text = "" }
        inputStart = 0
        outCol = 0
    }

    private inline fun guarded(block: () -> Unit) {
        guard = true
        try { block() } finally { guard = false }
    }

    private fun editable(offset: Int) = guard || (!running && offset >= inputStart)

    private inner class Filter : DocumentFilter() {
        override fun insertString(fb: FilterBypass, offset: Int, string: String?, attr: AttributeSet?) {
            if (editable(offset)) fb.insertString(offset, string, attr)
        }

        override fun replace(fb: FilterBypass, offset: Int, length: Int, text: String?, attrs: AttributeSet?) {
            if (editable(offset)) fb.replace(offset, length, text, attrs)
        }

        override fun remove(fb: FilterBypass, offset: Int, length: Int) {
            if (editable(offset)) fb.remove(offset, length)
        }
    }

    companion object {
        private const val MAX_LINE = 1000
    }
}
