package org.example.project

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class ProjectTest {

    @Test
    fun persistsInputAcrossReopen(@TempDir dir: File) {
        val apk = File(dir, "sample.apk").apply { writeBytes(byteArrayOf(1, 2, 3)) }

        val projectFile = Project.forInput(apk).use { it.file }
        assertTrue(projectFile.exists())
        assertEquals("sample.jdexproj", projectFile.name)

        Project.open(projectFile).use {
            assertEquals(apk.absolutePath, it.input()?.absolutePath)
        }
    }
}
