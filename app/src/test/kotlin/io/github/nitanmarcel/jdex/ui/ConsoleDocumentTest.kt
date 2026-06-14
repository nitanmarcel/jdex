package io.github.nitanmarcel.jdex.ui

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import javax.swing.JTextArea

class ConsoleDocumentTest {

    private fun fresh(): Pair<JTextArea, ConsoleDocument> {
        val area = JTextArea()
        return area to ConsoleDocument(area)
    }

    @Test fun promptOpensEditableRegionAndProtectsScrollback() {
        val (area, doc) = fresh()
        doc.write("banner\n")
        doc.prompt(">>> ")
        assertEquals("banner\n>>> ", area.text)
        area.document.insertString(doc.inputStart, "x = 1", null)
        assertEquals("x = 1", doc.input())
        area.document.insertString(0, "HACK", null)
        assertFalse("HACK" in area.text)
        area.document.remove(0, 3)
        assertEquals("banner\n>>> x = 1", area.text)
    }

    @Test fun outputSplicesAboveInProgressInput() {
        val (area, doc) = fresh()
        doc.prompt(">>> ")
        area.document.insertString(doc.inputStart, "typing", null)
        doc.appendOutput("async log\n")
        assertEquals(">>> async log\ntyping", area.text)
        assertEquals("typing", doc.input())
    }

    @Test fun submitFlowSealsLineThenOutputThenNextPrompt() {
        val (area, doc) = fresh()
        doc.prompt(">>> ")
        area.document.insertString(doc.inputStart, "1+1", null)
        val line = doc.input()
        doc.write("\n"); doc.endInput()
        doc.appendOutput("2\n")
        doc.prompt(">>> ")
        assertEquals("1+1", line)
        assertEquals(">>> 1+1\n2\n>>> ", area.text)
        assertEquals("", doc.input())
    }

    @Test fun editsRejectedWhileRunning() {
        val (area, doc) = fresh()
        doc.prompt(">>> ")
        doc.running = true
        area.document.insertString(area.document.length, "nope", null)
        assertEquals(">>> ", area.text)
        doc.appendOutput("output while running\n")
        doc.running = false
        assertEquals(">>> output while running\n", area.text)
    }

    @Test fun clearResetsToEmptyScrollback() {
        val (area, doc) = fresh()
        doc.write("old\n"); doc.prompt(">>> ")
        area.document.insertString(doc.inputStart, "junk", null)
        doc.clear()
        assertEquals("", area.text)
        assertEquals(0, doc.inputStart)
    }
}
