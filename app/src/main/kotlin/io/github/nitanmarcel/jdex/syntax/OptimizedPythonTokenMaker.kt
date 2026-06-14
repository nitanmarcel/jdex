package io.github.nitanmarcel.jdex.syntax

import org.fife.ui.rsyntaxtextarea.Token
import org.fife.ui.rsyntaxtextarea.modes.PythonTokenMaker
import javax.swing.text.Segment

class OptimizedPythonTokenMaker : PythonTokenMaker() {

    override fun getTokenList(text: Segment, initialTokenType: Int, startOffset: Int): Token {
        if (text.count <= MAX && isInput(text)) {
            return super.getTokenList(text, initialTokenType, startOffset)
        }
        resetTokenList()
        if (text.count == 0) {
            addNullToken()
        } else {
            addToken(text.array, text.offset, text.offset + text.count - 1, Token.IDENTIFIER, startOffset)
            addNullToken()
        }
        return firstToken
    }

    private fun isInput(t: Segment): Boolean {
        if (t.count < 4) return false
        val a = t.array
        val o = t.offset
        if (a[o + 3] != ' ') return false
        val c = a[o]
        return (c == '>' && a[o + 1] == '>' && a[o + 2] == '>') ||
            (c == '.' && a[o + 1] == '.' && a[o + 2] == '.')
    }

    companion object {
        const val MAX = 1000
        const val MIME = "text/x-jdex-py"
    }
}
