package io.github.nitanmarcel.jdex.project

import java.io.BufferedOutputStream
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStreamReader

class LabeledChunk(val label: String, val text: String)

class GenerationCancelled : RuntimeException()

interface LineSource : AutoCloseable {
    val lineCount: Int
    fun lines(from: Int, count: Int): List<String>

    fun sectionAt(line: Int): String?

    fun sectionStart(name: String): Int?

    fun sections(): List<Pair<String, Int>>


    fun sectionEnd(line: Int): Int

    fun search(query: String, from: Int, forward: Boolean, ignoreCase: Boolean): Int?

    fun findFrom(query: String, fromLine: Int, limit: Int, ignoreCase: Boolean, transform: (Int, String) -> String = { _, t -> t }): List<Int>
}

class DiskLineSource private constructor(
    private val file: File,
    private val offsets: LongArray,
    override val lineCount: Int,
    private val stride: Int,
    private val sectionLines: IntArray,
    private val sectionNames: Array<String>,
) : LineSource {

    private val lock = Any()
    private val chunkCache = object : LinkedHashMap<Int, List<String>>(MAX_CHUNKS * 2, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, List<String>>): Boolean = size > MAX_CHUNKS
    }

    override fun lines(from: Int, count: Int): List<String> {
        if (count <= 0 || from >= lineCount || from < 0) return emptyList()
        val n = count.coerceAtMost(lineCount - from)
        synchronized(lock) {
            val chunkStart = (from / stride) * stride
            if (from + n <= chunkStart + stride) {
                val chunk = chunkCache.getOrPut(chunkStart) { readDirect(chunkStart, stride) }
                val lo = from - chunkStart
                if (lo + n <= chunk.size) return ArrayList(chunk.subList(lo, lo + n))
            }
            return readDirect(from, n)
        }
    }

    private fun readDirect(from: Int, count: Int): List<String> {
        val n = count.coerceAtMost(lineCount - from).coerceAtLeast(0)
        if (n == 0) return emptyList()
        val idx = (from / stride).coerceIn(0, offsets.size - 1)
        val baseLine = idx * stride
        val result = ArrayList<String>(n)
        FileInputStream(file).use { fis ->
            fis.channel.position(offsets[idx])
            BufferedReader(InputStreamReader(fis, Charsets.UTF_8)).use { reader ->
                repeat(from - baseLine) { reader.readLine() }
                repeat(n) { result.add(reader.readLine() ?: return@use) }
            }
        }
        return result
    }

    override fun sectionAt(line: Int): String? {
        if (sectionLines.isEmpty()) return null
        var lo = 0
        var hi = sectionLines.size - 1
        var found = -1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            if (sectionLines[mid] <= line) {
                found = mid
                lo = mid + 1
            } else {
                hi = mid - 1
            }
        }
        return if (found >= 0) sectionNames[found] else null
    }

    override fun sectionStart(name: String): Int? {
        val index = sectionNames.indexOf(name)
        return if (index >= 0) sectionLines[index] else null
    }

    override fun sections(): List<Pair<String, Int>> = sectionNames.indices.map { sectionNames[it] to sectionLines[it] }

    override fun sectionEnd(line: Int): Int {
        if (sectionLines.isEmpty()) return lineCount - 1
        var lo = 0
        var hi = sectionLines.size - 1
        var found = -1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            if (sectionLines[mid] <= line) { found = mid; lo = mid + 1 } else hi = mid - 1
        }
        if (found < 0) return lineCount - 1
        return if (found + 1 < sectionLines.size) sectionLines[found + 1] - 1 else lineCount - 1
    }

    override fun search(query: String, from: Int, forward: Boolean, ignoreCase: Boolean): Int? {
        if (query.isEmpty()) return null
        if (forward) {
            for (line in from until lineCount) {
                if (lines(line, 1).firstOrNull()?.contains(query, ignoreCase) == true) return line
            }
        } else {
            for (line in from downTo 0) {
                if (lines(line, 1).firstOrNull()?.contains(query, ignoreCase) == true) return line
            }
        }
        return null
    }

    override fun findFrom(query: String, fromLine: Int, limit: Int, ignoreCase: Boolean, transform: (Int, String) -> String): List<Int> {
        if (query.isEmpty() || fromLine >= lineCount || fromLine < 0) return emptyList()
        val result = ArrayList<Int>()
        val idx = (fromLine / stride).coerceIn(0, offsets.size - 1)
        FileInputStream(file).use { fis ->
            fis.channel.position(offsets[idx])
            BufferedReader(InputStreamReader(fis, Charsets.UTF_8)).use { reader ->
                var line = idx * stride
                while (line < fromLine) { reader.readLine() ?: return result; line++ }
                while (result.size < limit) {
                    val text = reader.readLine() ?: break
                    if (transform(line, text).contains(query, ignoreCase)) result.add(line)
                    line++
                }
            }
        }
        return result
    }

    override fun close() {
        file.delete()
    }

    companion object {
        private const val NL = '\n'.code.toByte()
        private const val MAX_CHUNKS = 16

        fun build(chunks: Sequence<LabeledChunk>, stride: Int = 256): DiskLineSource {
            val file = File.createTempFile("jdex-code", ".txt").apply { deleteOnExit() }
            val offsets = ArrayList<Long>().apply { add(0L) }
            val sectionLines = ArrayList<Int>()
            val sectionNames = ArrayList<String>()
            var lineCount = 0
            var bytePos = 0L
            try {
                BufferedOutputStream(FileOutputStream(file)).use { out ->
                    for (chunk in chunks) {
                        sectionLines.add(lineCount)
                        sectionNames.add(chunk.label)
                        val bytes = chunk.text.toByteArray(Charsets.UTF_8)
                        out.write(bytes)
                        for (i in bytes.indices) {
                            if (bytes[i] == NL) {
                                lineCount++
                                if (lineCount % stride == 0) offsets.add(bytePos + i + 1)
                            }
                        }
                        bytePos += bytes.size
                    }
                }
            } catch (e: Throwable) {
                file.delete()
                throw e
            }
            return DiskLineSource(file, offsets.toLongArray(), lineCount, stride, sectionLines.toIntArray(), sectionNames.toTypedArray())
        }
    }
}
