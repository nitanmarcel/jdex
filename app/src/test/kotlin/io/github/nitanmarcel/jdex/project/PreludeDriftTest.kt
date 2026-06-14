package io.github.nitanmarcel.jdex.project

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PreludeDriftTest {

    @Test
    fun everyHostCallInPreludeExistsOnScriptApi() {
        val calls = Regex("""_host\.(\w+)\(""").findAll(ScriptEngine.PRELUDE).map { it.groupValues[1] }.toSet()
        assertTrue(calls.isNotEmpty(), "no host calls found in prelude")
        val methods = ScriptApi::class.java.methods.map { it.name }.toSet()
        val missing = calls - methods
        assertTrue(missing.isEmpty(), "prelude calls missing on ScriptApi: $missing")
    }
}
