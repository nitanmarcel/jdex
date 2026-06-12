package org.example

import java.io.File
import java.util.prefs.Preferences

class RecentFiles(private val limit: Int = 10) {

    private val prefs = Preferences.userRoot().node("jdex/recent-files")

    fun all(): List<File> =
        generateSequence(0) { it + 1 }
            .map { prefs.get(it.toString(), null) }
            .takeWhile { it != null }
            .filterNotNull()
            .map(::File)
            .toList()

    fun add(file: File) = write(listOf(file) + (all() - file))

    fun clear() = write(emptyList())

    private fun write(files: List<File>) {
        prefs.clear()
        files.take(limit).forEachIndexed { index, file ->
            prefs.put(index.toString(), file.absolutePath)
        }
    }
}
