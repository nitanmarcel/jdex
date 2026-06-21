package io.github.nitanmarcel.jdex.syntax

import org.fife.ui.rsyntaxtextarea.AbstractTokenMaker
import org.fife.ui.rsyntaxtextarea.Token
import org.fife.ui.rsyntaxtextarea.TokenMap
import org.fife.ui.rsyntaxtextarea.TokenTypes
import javax.swing.text.Segment

class AsmTokenMaker : AbstractTokenMaker() {

    override fun getWordsToHighlight(): TokenMap = TokenMap()

    override fun getTokenList(text: Segment, initialTokenType: Int, startOffset: Int): Token {
        resetTokenList()
        val a = text.array
        val off = text.offset
        val end = off + text.count
        if (text.count == 0) { addNullToken(); return firstToken }

        fun emit(s: Int, e: Int, type: Int) { if (e > s) addToken(a, s, e - 1, type, startOffset + (s - off)) }

        var i = off
        run { val s = i; while (i < end && (a[i] == ' ' || a[i] == '\t')) i++; emit(s, i, TokenTypes.WHITESPACE) }
        if (i >= end) { addNullToken(); return firstToken }

        var mnemonicPending = false
        val h = hexRun(a, i, end)
        if (h >= 4 && i + h < end && a[i + h] == ':' && (i + h + 1 >= end || a[i + h + 1] == ' ')) {
            emit(i, i + h, BytecodeStyle.ADDRESS); i += h
            emit(i, i + 1, TokenTypes.SEPARATOR); i++
            run { val s = i; while (i < end && a[i] == ' ') i++; emit(s, i, TokenTypes.WHITESPACE) }
            val b = hexRun(a, i, end)
            if (b > 0 && i + b + 1 < end && a[i + b] == ' ' && a[i + b + 1] == ' ') { emit(i, i + b, BytecodeStyle.BYTES); i += b }
            mnemonicPending = true
        } else if (a[i] != ';') {
            var j = i
            while (j < end && isLabel(a[j])) j++
            if (j > i && j < end && a[j] == ':') {
                emit(i, j, TokenTypes.FUNCTION)
                emit(j, j + 1, TokenTypes.SEPARATOR)
                i = j + 1
            }
        }

        while (i < end) {
            val c = a[i]
            when {
                c == ' ' || c == '\t' -> { val s = i; while (i < end && (a[i] == ' ' || a[i] == '\t')) i++; emit(s, i, TokenTypes.WHITESPACE) }
                c == ';' -> { emit(i, end, TokenTypes.COMMENT_EOL); i = end }
                mnemonicPending -> { val s = i; while (i < end && a[i] != ' ' && a[i] != '\t') i++; emit(s, i, TokenTypes.FUNCTION); mnemonicPending = false }
                else -> i = body(a, i, end, ::emit)
            }
        }
        addNullToken()
        return firstToken
    }

    private fun body(a: CharArray, start: Int, end: Int, emit: (Int, Int, Int) -> Unit): Int {
        var i = start
        val c = a[i]
        if (c == '0' && i + 1 < end && (a[i + 1] == 'x' || a[i + 1] == 'X')) {
            var j = i + 2; while (j < end && isHex(a[j])) j++; emit(i, j, TokenTypes.LITERAL_NUMBER_HEXADECIMAL); return j
        }
        if (c == '#' && i + 1 < end && a[i + 1] == '-' && i + 3 < end && a[i + 2] == '0' && a[i + 3] == 'x') {
            var j = i + 4; while (j < end && isHex(a[j])) j++; emit(i, j, TokenTypes.LITERAL_NUMBER_HEXADECIMAL); return j
        }
        if (c.isDigit()) { var j = i; while (j < end && a[j].isDigit()) j++; emit(i, j, TokenTypes.LITERAL_NUMBER_DECIMAL_INT); return j }
        if (c.isLetter() || c == '_' || c == '.' || c == '$' || c == '@') {
            var j = i; while (j < end && isLabel(a[j])) j++
            val word = String(a, i, j - i)
            val type = if (word.startsWith("sub_") || word.startsWith("loc_") || word.startsWith("j_") || word.startsWith("locret_")) TokenTypes.FUNCTION else TokenTypes.IDENTIFIER
            emit(i, j, type); return j
        }
        emit(i, i + 1, TokenTypes.SEPARATOR); return i + 1
    }

    private fun hexRun(a: CharArray, from: Int, end: Int): Int { var j = from; while (j < end && isHex(a[j])) j++; return j - from }
    private fun isHex(c: Char) = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'
    private fun isLabel(c: Char) = c.isLetterOrDigit() || c == '_' || c == '.' || c == '$' || c == '@'
}
