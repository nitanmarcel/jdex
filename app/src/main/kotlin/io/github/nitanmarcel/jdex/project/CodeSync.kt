package io.github.nitanmarcel.jdex.project

import java.util.TreeMap

sealed interface SyncTarget {
    data class Line(val methodId: String, val sourceLine: Int) : SyncTarget
    data class ClassDecl(val rawName: String) : SyncTarget
    data class MethodDecl(val methodId: String) : SyncTarget
    data class FieldDecl(val rawName: String, val fieldName: String) : SyncTarget
}

class CodeSync(
    private val targets: TreeMap<Int, SyncTarget>,
    private val sourceToJavaLine: Map<String, TreeMap<Int, Int>>,
    private val classDeclLine: Map<String, Int>,
    private val methodDeclLine: Map<String, Int>,
    private val fieldDeclLine: Map<String, Int>,
) {
    fun locate(javaLine: Int, approx: Boolean): SyncTarget? =
        if (approx) targets.floorEntry(javaLine)?.value else targets[javaLine]

    fun javaLineFor(target: SyncTarget, approx: Boolean): Int? = when (target) {
        is SyncTarget.Line -> {
            val byLine = sourceToJavaLine[target.methodId]
            val exact = byLine?.get(target.sourceLine)
            if (!approx) exact
            else exact ?: byLine?.floorEntry(target.sourceLine)?.value ?: byLine?.ceilingEntry(target.sourceLine)?.value ?: methodDeclLine[target.methodId]
        }
        is SyncTarget.ClassDecl -> classDeclLine[target.rawName]
        is SyncTarget.MethodDecl -> methodDeclLine[target.methodId]
        is SyncTarget.FieldDecl -> fieldDeclLine["${target.rawName}#${target.fieldName}"]
    }

    companion object {
        val EMPTY = CodeSync(TreeMap(), emptyMap(), emptyMap(), emptyMap(), emptyMap())
    }
}
