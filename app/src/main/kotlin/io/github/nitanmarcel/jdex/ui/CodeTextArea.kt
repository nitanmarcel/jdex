package io.github.nitanmarcel.jdex.ui

import io.github.nitanmarcel.jdex.project.Syntax
import org.fife.ui.rsyntaxtextarea.AbstractTokenMakerFactory
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea
import org.fife.ui.rsyntaxtextarea.TokenMakerFactory

class CodeTextArea(text: String, syntax: Syntax) : RSyntaxTextArea() {

    init {
        isEditable = false
        antiAliasingEnabled = true
        highlightCurrentLine = false
        font = SyntaxThemes.editorFont()
        syntaxEditingStyle = SyntaxStyles.mime(syntax)
        setText(text)
        caretPosition = 0
        SyntaxThemes.attach(this)
    }

    companion object {
        fun registerSyntaxStyles() {
            val factory = TokenMakerFactory.getDefaultInstance() as AbstractTokenMakerFactory
            factory.putMapping("text/smali", "io.github.nitanmarcel.jdex.syntax.BytecodeTokenMaker")
            factory.putMapping("text/jdex-asm", "io.github.nitanmarcel.jdex.syntax.AsmTokenMaker")
            factory.putMapping("text/jdex-debug", "io.github.nitanmarcel.jdex.syntax.DebugTokenMaker")
        }
    }
}
