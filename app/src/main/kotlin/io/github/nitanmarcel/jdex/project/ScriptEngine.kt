package io.github.nitanmarcel.jdex.project

import org.graalvm.polyglot.Context
import org.graalvm.polyglot.Source
import org.graalvm.polyglot.Value
import java.io.File
import java.io.OutputStream
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors

class ScriptEngine(api: ScriptApi, out: OutputStream) : AutoCloseable {

    private val thread = Executors.newSingleThreadExecutor { r -> Thread(r, "jdex-python").apply { isDaemon = true } }
    private val context: Context
    private val feedFn: Value
    private val completeFn: Value
    private val signatureFn: Value
    private val docFn: Value

    init {
        context = on {
            Context.newBuilder("python")
                .allowAllAccess(true)
                .option("engine.WarnInterpreterOnly", "false")
                .out(out)
                .err(out)
                .build()
        }
        on {
            context.getBindings("python").putMember("_jdex_host", api)
            context.eval("python", PRELUDE)
            context.eval("python", REPL)
        }
        feedFn = on { context.eval("python", "_repl.feed") }
        completeFn = on { context.eval("python", "_complete") }
        signatureFn = on { context.eval("python", "_signature_of") }
        docFn = on { context.eval("python", "_doc_of") }
    }

    fun feed(line: String): Boolean = on { feedFn.execute(line).asBoolean() }

    fun complete(text: String, state: Int): String? = on {
        val v = completeFn.execute(text, state)
        if (v.isNull) null else v.asString()
    }

    fun signature(expr: String): String? = on {
        val v = signatureFn.execute(expr)
        if (v.isNull) null else v.asString().ifEmpty { null }
    }

    fun doc(expr: String): String? = on {
        val v = docFn.execute(expr)
        if (v.isNull) null else v.asString().ifEmpty { null }
    }

    fun eval(code: String): Value = on { context.eval(Source.newBuilder("python", code, "<repl>").build()) }

    fun runFile(file: File): Value = on { context.eval(Source.newBuilder("python", file).build()) }

    override fun close() {
        runCatching { on { context.close() } }
        thread.shutdownNow()
    }

    private fun <T> on(block: () -> T): T =
        try {
            thread.submit(Callable { block() }).get()
        } catch (e: ExecutionException) {
            throw e.cause ?: e
        }

    companion object {
        val PRELUDE: String = ScriptEngine::class.java.getResource("/jdex_prelude.py")!!.readText()
        val REPL: String = ScriptEngine::class.java.getResource("/jdex_repl.py")!!.readText()
        val STUB: String = ScriptEngine::class.java.getResource("/jdex.pyi")!!.readText()
    }
}
