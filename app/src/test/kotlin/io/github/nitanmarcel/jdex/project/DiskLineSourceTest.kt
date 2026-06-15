package io.github.nitanmarcel.jdex.project

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class DiskLineSourceTest {

    private fun source(count: Int): DiskLineSource {
        val text = (0 until count).joinToString("") { "line$it\n" }
        return DiskLineSource.build(sequenceOf(LabeledChunk("s", text)))
    }

    private fun expected(from: Int, n: Int, total: Int) =
        (from until (from + n).coerceAtMost(total)).map { "line$it" }

    @Test
    fun `windowed cache returns correct lines across chunk boundaries and EOF`() {
        val total = 1000
        source(total).use { src ->
            assertEquals(total, src.lineCount)
            val cases = listOf(
                0 to 1, 1 to 1, 255 to 1, 256 to 1, 257 to 1, 999 to 1,
                250 to 20,
                0 to 300,
                768 to 500,
                990 to 50,
            )
            repeat(2) {
                for ((from, n) in cases) {
                    assertEquals(expected(from, n, total), src.lines(from, n), "lines($from, $n)")
                }
            }
            assertEquals(emptyList<String>(), src.lines(-1, 5))
            assertEquals(emptyList<String>(), src.lines(total, 5))
        }
    }

    @Test
    fun `concurrent reads stay correct under contention`() {
        val total = 5000
        source(total).use { src ->
            val pool = Executors.newFixedThreadPool(8)
            val errors = java.util.concurrent.ConcurrentLinkedQueue<String>()
            repeat(8) {
                pool.submit {
                    val rnd = java.util.Random(it.toLong())
                    repeat(3000) {
                        val from = rnd.nextInt(total)
                        val n = 1 + rnd.nextInt(40)
                        if (src.lines(from, n) != expected(from, n, total)) errors.add("lines($from,$n)")
                    }
                }
            }
            pool.shutdown()
            pool.awaitTermination(30, TimeUnit.SECONDS)
            assertEquals(emptyList<String>(), errors.toList())
        }
    }
}
