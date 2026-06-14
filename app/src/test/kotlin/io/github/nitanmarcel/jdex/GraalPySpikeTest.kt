package io.github.nitanmarcel.jdex

import org.graalvm.polyglot.Context
import org.graalvm.polyglot.HostAccess
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class GraalPySpikeTest {

    class Api {
        @HostAccess.Export
        fun greet(name: String): String = "hello, $name from jdex"

        @HostAccess.Export
        fun add(a: Int, b: Int): Int = a + b
    }

    @Test
    fun pythonCallsCuratedHostFacade() {
        val access = HostAccess.newBuilder()
            .allowAccessAnnotatedBy(HostAccess.Export::class.java)
            .build()
        Context.newBuilder("python").allowHostAccess(access).build().use { ctx ->
            ctx.getBindings("python").putMember("jdex", Api())
            val result = ctx.eval("python", "jdex.greet('world') + ' / ' + str(jdex.add(2, 3))")
            assertEquals("hello, world from jdex / 5", result.asString())
        }
    }
}
