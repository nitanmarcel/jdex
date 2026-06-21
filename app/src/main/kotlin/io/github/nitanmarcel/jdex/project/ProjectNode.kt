package io.github.nitanmarcel.jdex.project

class ProjectNode(
    val label: String,
    val open: (() -> Content)? = null,
    val children: List<ProjectNode> = emptyList(),
    val dex: MalformedDex? = null,
) {
    override fun toString() = label
}

enum class Syntax { NONE, SMALI, JAVA, XML, JSON, JAVASCRIPT, HTML, CSS, PROPERTIES, ASM, C }

sealed interface Content
class TextContent(val text: String, val syntax: Syntax = Syntax.NONE) : Content
class BinaryContent(val bytes: ByteArray) : Content
class NativeContent(val name: String, val bytes: ByteArray) : Content
class CodeContent(
    val syntax: Syntax,
    val x86Is32: Boolean? = null,
    val nativeId: String? = null,
    val nativeSegments: List<Pair<String, Long>>? = null,
    val nativeInfo: NativeInfo? = null,
    val generate: (progress: (Int, Int) -> Unit, cancel: () -> Boolean) -> LineSource?,
) : Content

class NativeInfo(
    val exports: List<Pair<String, Long>>,
    val imports: List<Pair<String, Long>>,
    val constructors: List<Pair<String, Long>>,
    val summary: List<String>,
)
