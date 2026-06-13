package io.github.nitanmarcel.jdex.project

class ProjectNode(
    val label: String,
    val open: (() -> Content)? = null,
    val children: List<ProjectNode> = emptyList(),
    val dex: MalformedDex? = null,
) {
    override fun toString() = label
}

enum class Syntax { NONE, SMALI, JAVA, XML, JSON, JAVASCRIPT, HTML, CSS, PROPERTIES }

sealed interface Content
class TextContent(val text: String, val syntax: Syntax = Syntax.NONE) : Content
class BinaryContent(val bytes: ByteArray) : Content
class CodeContent(
    val syntax: Syntax,
    val generate: (progress: (Int, Int) -> Unit, cancel: () -> Boolean) -> LineSource?,
) : Content
