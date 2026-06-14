package io.github.nitanmarcel.jdex.project

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream

class ReplTest {

    private fun engine(out: ByteArrayOutputStream) = ScriptEngine(ScriptApi({ null }), out)

    @Test
    fun lineByLineContinuationAndEcho() {
        val out = ByteArrayOutputStream()
        engine(out).use { e ->
            assertFalse(e.feed("x = 21"), "assignment is complete")
            assertFalse(e.feed("x * 2"), "expression is complete")
            assertTrue(e.feed("def g(n):"), "block head needs more")
            assertTrue(e.feed("    a = n + 1"), "block body needs more")
            assertTrue(e.feed("    return a"), "still in block")
            assertFalse(e.feed(""), "blank line ends the block")
            assertFalse(e.feed("g(3)"), "call is complete")
        }
        val text = out.toString(Charsets.UTF_8)
        assertTrue("\n42\n" in "\n$text\n", "expression echo missing: $text")
        assertTrue("\n4\n" in "\n$text\n", "multiline def result missing: $text")
    }

    @Test
    fun tracebackAndCompletion() {
        val out = ByteArrayOutputStream()
        engine(out).use { e ->
            e.feed("1/0")
            val text = out.toString(Charsets.UTF_8)
            assertTrue("ZeroDivisionError" in text, "no traceback: $text")
            assertFalse("_run" in text, "internal frame leaked: $text")

            val c = e.complete("fl", 0)
            assertEquals("float(", c)
        }
    }

    @Test
    fun hostExceptionReportsCleanlyWithoutCrashingHandler() {
        val out = ByteArrayOutputStream()
        engine(out).use { e ->
            assertFalse(e.feed("jdex.classes()"), "statement is complete")
            assertFalse(e.feed("1 + 1"), "repl wedged after host exception")
        }
        val text = out.toString(Charsets.UTF_8)
        assertFalse("tb_next" in text, "exception handler itself crashed: $text")
        assertTrue("No APK or DEX loaded" in text, "host error message not surfaced: $text")
        assertTrue("\n2\n" in "\n$text\n", "repl did not recover to evaluate 1 + 1: $text")
    }

    @Test
    fun largeOutputIsNotTruncated() {
        val out = ByteArrayOutputStream()
        engine(out).use { e ->
            assertFalse(e.feed("'x' * 5000"), "expression is complete")
        }
        val text = out.toString(Charsets.UTF_8)
        assertTrue("x".repeat(5000) in text, "full repr was truncated")
    }

    @Test
    fun signatureAndDocResolveDocstring() {
        val out = ByteArrayOutputStream()
        engine(out).use { e ->
            val sig = e.signature("jdex.classes")
            assertNotNull(sig, "no signature for jdex.classes")
            assertTrue("All classes" in sig!!, "docstring missing from signature: $sig")

            val doc = e.doc("jdex.find_classes")
            assertNotNull(doc, "no doc for jdex.find_classes")
            assertTrue("find_classes(" in doc!! && "regex" in doc, "doc pane text malformed: $doc")
            assertEquals("", out.toString(Charsets.UTF_8), "introspection must not print")
        }
    }
}
