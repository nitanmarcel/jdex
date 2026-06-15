package io.github.nitanmarcel.jdex.syntax

import org.fife.ui.rsyntaxtextarea.AbstractTokenMaker
import org.fife.ui.rsyntaxtextarea.SyntaxScheme
import org.fife.ui.rsyntaxtextarea.Token
import org.fife.ui.rsyntaxtextarea.TokenMap
import org.fife.ui.rsyntaxtextarea.TokenTypes
import java.awt.Color
import javax.swing.text.Segment

object BytecodeStyle {
    const val ADDRESS = 0x1001
    const val BYTES = 0x1002
    const val OFFSET = 0x1003

    fun color(type: Int, scheme: SyntaxScheme, fg: Color, bg: Color): Color = when (type) {
        ADDRESS, BYTES -> blend(bg, fg, 0.40)
        OFFSET -> blend(bg, fg, 0.66)
        else -> (if (type in 0 until TokenTypes.DEFAULT_NUM_TOKEN_TYPES) scheme.getStyle(type)?.foreground else null) ?: fg
    }

    private fun blend(a: Color, b: Color, t: Double) = Color(
        (a.red + (b.red - a.red) * t).toInt().coerceIn(0, 255),
        (a.green + (b.green - a.green) * t).toInt().coerceIn(0, 255),
        (a.blue + (b.blue - a.blue) * t).toInt().coerceIn(0, 255),
    )
}

class BytecodeTokenMaker : AbstractTokenMaker() {

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

        var instruction = false
        if (hexRun(a, i, end) == 8 && i + 8 < end && a[i + 8] == ':') {
            emit(i, i + 8, BytecodeStyle.ADDRESS); i += 8
            emit(i, i + 1, TokenTypes.SEPARATOR); i++
            while (i < end) {
                val s = i; while (i < end && a[i] == ' ') i++; emit(s, i, TokenTypes.WHITESPACE)
                if (i >= end) break
                val h = hexRun(a, i, end)
                if (h == 0) break
                if (i + h < end && a[i + h] == ':') {
                    emit(i, i + h, BytecodeStyle.OFFSET); i += h
                    emit(i, i + 1, TokenTypes.SEPARATOR); i++
                    instruction = true; break
                }
                emit(i, i + h, BytecodeStyle.BYTES); i += h
            }
        } else {
            val h = hexRun(a, i, end)
            if (h in 1..4 && i + h < end && a[i + h] == ':') {
                emit(i, i + h, BytecodeStyle.OFFSET); i += h
                emit(i, i + 1, TokenTypes.SEPARATOR); i++
                instruction = true
            }
        }

        var mnemonicPending = instruction
        while (i < end) {
            val c = a[i]
            when {
                c == ' ' || c == '\t' -> { val s = i; while (i < end && (a[i] == ' ' || a[i] == '\t')) i++; emit(s, i, TokenTypes.WHITESPACE) }
                c == '#' -> { emit(i, end, TokenTypes.COMMENT_EOL); i = end }
                c == '"' -> { val s = i; i++; while (i < end) { val ch = a[i]; if (ch == '\\' && i + 1 < end) i += 2 else if (ch == '"') { i++; break } else i++ }; emit(s, i, TokenTypes.LITERAL_STRING_DOUBLE_QUOTE) }
                mnemonicPending -> {
                    val s = i; while (i < end && a[i] != ' ' && a[i] != '\t') i++
                    emit(s, i, if (String(a, s, i - s) in OPCODES) TokenTypes.FUNCTION else TokenTypes.IDENTIFIER)
                    mnemonicPending = false
                }
                else -> i = body(a, i, end, instruction, ::emit)
            }
        }
        addNullToken()
        return firstToken
    }

    private fun body(a: CharArray, start: Int, end: Int, instruction: Boolean, emit: (Int, Int, Int) -> Unit): Int {
        var i = start
        val c = a[i]
        if (c == '-' && i + 1 < end && a[i + 1] == '>') {
            emit(i, i + 2, TokenTypes.SEPARATOR); i += 2
            val s = i
            while (i < end && a[i] != '(' && a[i] != ':' && a[i] != ' ' && a[i] != ',' && a[i] != ';') i++
            emit(s, i, TokenTypes.FUNCTION)
            return i
        }
        if (c == 'L') {
            var j = i + 1
            while (j < end && (a[j].isLetterOrDigit() || a[j] == '/' || a[j] == '$' || a[j] == '_')) j++
            if (j < end && a[j] == ';') { emit(i, j + 1, TokenTypes.DATA_TYPE); return j + 1 }
        }
        if (c == '0' && i + 1 < end && (a[i + 1] == 'x' || a[i + 1] == 'X')) {
            var j = i + 2; while (j < end && isHex(a[j])) j++; emit(i, j, TokenTypes.LITERAL_NUMBER_HEXADECIMAL); return j
        }
        if (c == '-' && i + 2 < end && a[i + 1] == '0' && a[i + 2] == 'x') {
            var j = i + 3; while (j < end && isHex(a[j])) j++; emit(i, j, TokenTypes.LITERAL_NUMBER_HEXADECIMAL); return j
        }
        if ((c == 'v' || c == 'p') && i + 1 < end && a[i + 1].isDigit()) {
            var j = i + 1; while (j < end && a[j].isDigit()) j++
            if (j >= end || !isWord(a[j])) { emit(i, j, TokenTypes.VARIABLE); return j }
        }
        if (c == '.') {
            var j = i + 1; while (j < end && (a[j].isLetterOrDigit() || a[j] == '_')) j++; emit(i, j, TokenTypes.RESERVED_WORD_2); return j
        }
        if (instruction && isHex(c)) {
            val h = hexRun(a, i, end)
            if (h == 4 && (i + h >= end || !isWord(a[i + h]))) { emit(i, i + h, BytecodeStyle.OFFSET); return i + h }
        }
        if (c.isLetterOrDigit() || c == '_' || c == '$') {
            var j = i; while (j < end && (a[j].isLetterOrDigit() || a[j] == '_' || a[j] == '$')) j++
            val word = String(a, i, j - i)
            val type = when {
                word in KEYWORDS -> TokenTypes.RESERVED_WORD
                word in HEADERS && j < end && a[j] == ':' -> TokenTypes.RESERVED_WORD
                word.all { it.isDigit() } -> TokenTypes.LITERAL_NUMBER_DECIMAL_INT
                else -> TokenTypes.IDENTIFIER
            }
            emit(i, j, type); return j
        }
        emit(i, i + 1, TokenTypes.SEPARATOR); return i + 1
    }

    private fun hexRun(a: CharArray, from: Int, end: Int): Int {
        var j = from; while (j < end && isHex(a[j])) j++; return j - from
    }

    private fun isHex(c: Char) = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'
    private fun isWord(c: Char) = c.isLetterOrDigit() || c == '_' || c == '$'

    private companion object {
        val KEYWORDS = setOf(
            "public", "private", "protected", "static", "final", "abstract", "synthetic", "bridge",
            "native", "synchronized", "transient", "volatile", "enum", "interface", "annotation",
            "varargs", "strictfp", "constructor", "declared-synchronized",
        )
        val HEADERS = setOf("Class", "AccessFlags", "SuperType", "Interfaces")

        val OPCODES = setOf(
            "add-double", "add-double/2addr", "add-float", "add-float/2addr", "add-int", "add-int/2addr",
            "add-int/lit16", "add-int/lit8", "add-long", "add-long/2addr", "aget", "aget-boolean",
            "aget-byte", "aget-char", "aget-object", "aget-short", "aget-wide", "and-int",
            "and-int/2addr", "and-int/lit16", "and-int/lit8", "and-long", "and-long/2addr", "aput",
            "aput-boolean", "aput-byte", "aput-char", "aput-object", "aput-short", "aput-wide",
            "array-length", "check-cast", "cmpg-double", "cmpg-float", "cmpl-double", "cmpl-float",
            "cmp-long", "const", "const/16", "const/4", "const-class", "const/high16",
            "const-method-handle", "const-method-type", "const-string", "const-string/jumbo", "const-wide", "const-wide/16",
            "const-wide/32", "const-wide/high16", "div-double", "div-double/2addr", "div-float", "div-float/2addr",
            "div-int", "div-int/2addr", "div-int/lit16", "div-int/lit8", "div-long", "div-long/2addr",
            "double-to-float", "double-to-int", "double-to-long", "fill-array-data", "filled-new-array", "filled-new-array/range",
            "float-to-double", "float-to-int", "float-to-long", "goto", "goto/16", "goto/32",
            "if-eq", "if-eqz", "if-ge", "if-gez", "if-gt", "if-gtz",
            "if-le", "if-lez", "if-lt", "if-ltz", "if-ne", "if-nez",
            "iget", "iget-boolean", "iget-byte", "iget-char", "iget-object", "iget-short",
            "iget-wide", "instance-of", "int-to-byte", "int-to-char", "int-to-double", "int-to-float",
            "int-to-long", "int-to-short", "invoke-custom", "invoke-custom/range", "invoke-direct", "invoke-direct/range",
            "invoke-interface", "invoke-interface/range", "invoke-polymorphic", "invoke-polymorphic/range", "invoke-static", "invoke-static/range",
            "invoke-super", "invoke-super/range", "invoke-virtual", "invoke-virtual/range", "iput", "iput-boolean",
            "iput-byte", "iput-char", "iput-object", "iput-short", "iput-wide", "long-to-double",
            "long-to-float", "long-to-int", "monitor-enter", "monitor-exit", "move", "move/16",
            "move-exception", "move/from16", "move-object", "move-object/16", "move-object/from16", "move-result",
            "move-result-object", "move-result-wide", "move-wide", "move-wide/16", "move-wide/from16", "mul-double",
            "mul-double/2addr", "mul-float", "mul-float/2addr", "mul-int", "mul-int/2addr", "mul-int/lit16",
            "mul-int/lit8", "mul-long", "mul-long/2addr", "neg-double", "neg-float", "neg-int",
            "neg-long", "new-array", "new-instance", "nop", "not-int", "not-long",
            "or-int", "or-int/2addr", "or-int/lit16", "or-int/lit8", "or-long", "or-long/2addr",
            "packed-switch", "rem-double", "rem-double/2addr", "rem-float", "rem-float/2addr", "rem-int",
            "rem-int/2addr", "rem-int/lit16", "rem-int/lit8", "rem-long", "rem-long/2addr", "return",
            "return-object", "return-void", "return-wide", "rsub-int", "rsub-int/lit8", "sget",
            "sget-boolean", "sget-byte", "sget-char", "sget-object", "sget-short", "sget-wide",
            "shl-int", "shl-int/2addr", "shl-int/lit8", "shl-long", "shl-long/2addr", "shr-int",
            "shr-int/2addr", "shr-int/lit8", "shr-long", "shr-long/2addr", "sparse-switch", "sput",
            "sput-boolean", "sput-byte", "sput-char", "sput-object", "sput-short", "sput-wide",
            "sub-double", "sub-double/2addr", "sub-float", "sub-float/2addr", "sub-int", "sub-int/2addr",
            "sub-long", "sub-long/2addr", "throw", "ushr-int", "ushr-int/2addr", "ushr-int/lit8",
            "ushr-long", "ushr-long/2addr", "xor-int", "xor-int/2addr", "xor-int/lit16", "xor-int/lit8",
            "xor-long", "xor-long/2addr",
            "packed-switch-payload", "sparse-switch-payload", "fill-array-data-payload",
        )
    }
}
