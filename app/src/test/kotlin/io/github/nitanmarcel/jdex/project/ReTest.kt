package io.github.nitanmarcel.jdex.project

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream

class ReTest {
    @Test fun reModuleWorks() {
        val out = ByteArrayOutputStream()
        ScriptEngine(ScriptApi({ null }), out).use { e ->
            e.feed("import re")
            e.feed("bool(re.search(r'^La/', 'La/b'))")
            e.feed("re.findall(r'[0-9]+', 'a1b22c333')")
        }
        val text = out.toString(Charsets.UTF_8)
        assertTrue("True" in text, "re.search failed: $text")
        assertTrue("'1', '22', '333'" in text || "['1', '22', '333']" in text, "re.findall failed: $text")
    }
}
