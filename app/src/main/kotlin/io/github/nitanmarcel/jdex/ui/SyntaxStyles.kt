package io.github.nitanmarcel.jdex.ui

import io.github.nitanmarcel.jdex.project.Syntax
import org.fife.ui.rsyntaxtextarea.SyntaxConstants

object SyntaxStyles {

    fun mime(syntax: Syntax): String = when (syntax) {
        Syntax.SMALI -> "text/smali"
        Syntax.JAVA -> SyntaxConstants.SYNTAX_STYLE_JAVA
        Syntax.XML -> SyntaxConstants.SYNTAX_STYLE_XML
        Syntax.JSON -> SyntaxConstants.SYNTAX_STYLE_JSON
        Syntax.JAVASCRIPT -> SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT
        Syntax.HTML -> SyntaxConstants.SYNTAX_STYLE_HTML
        Syntax.CSS -> SyntaxConstants.SYNTAX_STYLE_CSS
        Syntax.PROPERTIES -> SyntaxConstants.SYNTAX_STYLE_PROPERTIES_FILE
        Syntax.ASM -> "text/jdex-asm"
        Syntax.C -> SyntaxConstants.SYNTAX_STYLE_C
        Syntax.NONE -> SyntaxConstants.SYNTAX_STYLE_NONE
    }
}
