package io.github.nitanmarcel.jdex.project

import jadx.api.JavaClass
import jadx.api.plugins.input.data.AccessFlags
import jadx.api.plugins.input.data.AccessFlagsScope
import jadx.api.plugins.input.data.ICodeReader
import jadx.api.plugins.input.data.IFieldData
import jadx.api.plugins.input.data.IMethodData
import jadx.api.plugins.input.data.ISeqConsumer
import jadx.api.plugins.input.insns.InsnData
import jadx.api.plugins.input.insns.InsnIndexType
import jadx.api.plugins.input.insns.custom.IArrayPayload
import jadx.api.plugins.input.insns.custom.ISwitchPayload
import java.lang.reflect.Array as ReflectArray

object BytecodeWriter {

    private const val MNEMONIC_WIDTH = 20

    fun forClass(cls: JavaClass, resources: Map<Int, String>): String {
        val data = cls.classNode?.clsData ?: return "Class: L${cls.rawName.replace('.', '/')};\n"
        val out = StringBuilder()
        out.appendLine("Class: ${data.type}")
        out.appendLine("AccessFlags: ${AccessFlags.format(data.accessFlags, AccessFlagsScope.CLASS).trim()}")
        out.appendLine("SuperType: ${data.superType}")
        if (data.interfacesTypes.isNotEmpty()) {
            out.appendLine("Interfaces: [${data.interfacesTypes.joinToString(", ")}]")
        }

        val fields = mutableListOf<Pair<String, String>>()
        val methods = StringBuilder()
        data.visitFieldsAndMethods(
            ISeqConsumer<IFieldData> { field ->
                fields.add("${modifiers(field.accessFlags, AccessFlagsScope.FIELD)}${field.name}" to field.type)
            },
            ISeqConsumer<IMethodData> { method -> appendMethod(methods, method, resources) },
        )

        if (fields.isNotEmpty()) {
            out.appendLine()
            out.appendLine("# fields")
            val width = fields.maxOf { it.first.length }
            fields.forEach { (declaration, type) -> out.appendLine(".field ${declaration.padEnd(width)} : $type") }
        }
        out.append(methods)
        return out.toString()
    }

    private fun appendMethod(out: StringBuilder, method: IMethodData, resources: Map<Int, String>) {
        val ref = method.methodRef.apply { load() }
        out.appendLine()
        out.appendLine(".method ${modifiers(method.accessFlags, AccessFlagsScope.METHOD)}${ref.name}(${ref.argTypes.joinToString("")})${ref.returnType}")
        val reader = method.codeReader
        if (reader == null) {
            out.appendLine(".end method")
            return
        }

        out.appendLine("    .registers ${reader.registersCount}")
        appendTries(out, reader)

        val isStatic = AccessFlags.hasFlag(method.accessFlags, AccessFlags.STATIC)
        val insSize = (if (isStatic) 0 else 1) + ref.argTypes.sumOf { if (it == "J" || it == "D") 2 else 1 }
        val paramBase = reader.registersCount - insSize

        val debug = reader.debugInfo
        val lines = debug?.sourceLineMapping ?: emptyMap()
        val localStart = (debug?.localVars ?: emptyList()).groupBy { it.startOffset }
        val localEnd = (debug?.localVars ?: emptyList()).groupBy { it.endOffset }

        out.appendLine()
        val codeBase = reader.codeOffset
        var first = true
        reader.visitInstructions { insn ->
            insn.decode()
            val offset = insn.offset
            lines[offset]?.let {
                if (!first) out.appendLine()
                out.appendLine("    .line $it")
            }
            localEnd[offset]?.forEach { out.appendLine("    .end local ${reg(it.regNum, paramBase)}") }
            localStart[offset]?.forEach {
                val kind = if (it.isMarkedAsParameter) ".param" else ".local"
                out.appendLine("    $kind ${reg(it.regNum, paramBase)}, \"${it.name}\":${it.type}")
            }
            out.appendLine("    ${formatInsn(insn, codeBase, resources, paramBase)}")
            first = false
        }
        out.appendLine(".end method")
    }

    private fun appendTries(out: StringBuilder, reader: ICodeReader) {
        for (aTry in reader.tries) {
            val catch = aTry.catch
            val range = "%04x .. %04x".format(aTry.startOffset, aTry.endOffset)
            catch.types.forEachIndexed { i, type ->
                out.appendLine("    .catch $type { $range } -> %04x".format(catch.handlers[i]))
            }
            if (catch.catchAllHandler >= 0) {
                out.appendLine("    .catchall { $range } -> %04x".format(catch.catchAllHandler))
            }
        }
    }

    private fun formatInsn(insn: InsnData, codeBase: Int, resources: Map<Int, String>, paramBase: Int): String {
        val name = insn.opcode?.name ?: ""
        val mnemonic = insn.opcodeMnemonic
        val fileOffset = codeBase + insn.offset * 2

        payload(insn)?.let { return "%08x: %-18s %04x: %s".format(fileOffset, "%04x".format(insn.rawOpcodeUnit), insn.offset, it) }

        val prefix = "%08x: %-18s %04x:".format(fileOffset, hex(insn.byteCode), insn.offset)
        val operands = operandText(insn, name, paramBase)
        val resource = if (isLiteral(name)) resources[insn.literal.toInt()]?.let { " # @$it" } ?: "" else ""
        return "$prefix ${mnemonic.padEnd(MNEMONIC_WIDTH)} $operands${comment(insn)}$resource".trimEnd()
    }

    private fun operandText(insn: InsnData, name: String, paramBase: Int): String {
        val braces = name.startsWith("INVOKE") || name.startsWith("FILLED_NEW_ARRAY")
        val registers = registers(insn, braces, name.endsWith("_RANGE"), paramBase)
        val operand = when {
            name == "CONST_METHOD_HANDLE" -> "${insn.indexAsMethodHandle.type}"
            name == "CONST_METHOD_TYPE" -> insn.getIndexAsProto(insn.index).let { "(${it.argTypes.joinToString("")})${it.returnType}" }
            isTarget(name) -> "%04x".format(insn.target)
            insn.indexType == InsnIndexType.CALL_SITE -> insn.indexAsCallSite.values.joinToString(", ")
            insn.indexType == InsnIndexType.METHOD_REF -> insn.indexAsMethod.apply { load() }.let { "${it.parentClassType}->${it.name}(${it.argTypes.joinToString("")})${it.returnType}" }
            insn.indexType == InsnIndexType.FIELD_REF -> insn.indexAsField.let { "${it.parentClassType}->${it.name}:${it.type}" }
            insn.indexType == InsnIndexType.STRING_REF -> "\"${escape(insn.indexAsString)}\""
            insn.indexType == InsnIndexType.TYPE_REF -> insn.indexAsType
            isLiteral(name) -> literal(insn.literal)
            else -> null
        }
        return listOfNotNull(registers.ifEmpty { null }, operand).joinToString(", ")
    }

    private fun payload(insn: InsnData): String? = when (insn.rawOpcodeUnit) {
        0x0100, 0x0200 -> {
            val name = if (insn.rawOpcodeUnit == 0x0100) "packed-switch-payload" else "sparse-switch-payload"
            val switch = insn.payload as? ISwitchPayload
            val cases = switch?.let { it.keys.zip(it.targets.toList()).joinToString(", ") { (k, t) -> "0x${k.toString(16)} -> %04x".format(t) } }
            if (cases != null) "$name {$cases}" else name
        }
        0x0300 -> {
            val array = insn.payload as? IArrayPayload
            if (array != null) "fill-array-data-payload {${arrayValues(array.data)}}" else "fill-array-data-payload"
        }
        else -> null
    }

    private fun arrayValues(data: Any?): String {
        if (data == null) return ""
        val size = ReflectArray.getLength(data)
        return (0 until size).joinToString(", ") {
            when (val v = ReflectArray.get(data, it)) {
                is Byte -> "0x${(v.toInt() and 0xff).toString(16)}"
                is Short -> "0x${(v.toInt() and 0xffff).toString(16)}"
                is Int -> "0x${v.toLong().and(0xffffffffL).toString(16)}"
                is Long -> "0x${v.toULong().toString(16)}"
                else -> v.toString()
            }
        }
    }

    private fun registers(insn: InsnData, braces: Boolean, range: Boolean, paramBase: Int): String {
        val count = insn.regsCount
        if (count == 0) return ""
        val body = if (range) "${reg(insn.getReg(0), paramBase)} .. ${reg(insn.getReg(count - 1), paramBase)}"
        else (0 until count).joinToString(", ") { reg(insn.getReg(it), paramBase) }
        return if (braces) "{$body}" else body
    }

    private fun reg(r: Int, paramBase: Int): String = if (paramBase in 0..r) "p${r - paramBase}" else "v$r"

    private fun comment(insn: InsnData): String = when (insn.indexType) {
        InsnIndexType.METHOD_REF -> " # method@${insn.index.toString(16)}"
        InsnIndexType.FIELD_REF -> " # field@${insn.index.toString(16)}"
        InsnIndexType.STRING_REF -> " # string@${insn.index.toString(16)}"
        InsnIndexType.TYPE_REF -> " # type@${insn.index.toString(16)}"
        InsnIndexType.CALL_SITE -> " # call_site@${insn.index.toString(16)}"
        else -> ""
    }

    private fun isTarget(name: String) = name.startsWith("GOTO") || name.startsWith("IF_") ||
        name == "PACKED_SWITCH" || name == "SPARSE_SWITCH" || name == "FILL_ARRAY_DATA"

    private fun isLiteral(name: String) = name.startsWith("CONST") || name.endsWith("_LIT") || name == "RSUB_INT"

    private fun literal(value: Long): String = if (value < 0) "-0x${(-value).toString(16)}" else "0x${value.toString(16)}"

    private fun escape(s: String): String = buildString {
        for (c in s) when (c) {
            '\\' -> append("\\\\")
            '"' -> append("\\\"")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (c < ' ') append("\\u%04x".format(c.code)) else append(c)
        }
    }

    private fun hex(bytes: ByteArray): String = buildString {
        var i = 0
        while (i < bytes.size) {
            append("%02x".format(bytes[i].toInt() and 0xff))
            if (i + 1 < bytes.size) append("%02x".format(bytes[i + 1].toInt() and 0xff))
            append(' ')
            i += 2
        }
    }.trim()

    private fun modifiers(flags: Int, scope: AccessFlagsScope): String {
        val text = AccessFlags.format(flags, scope).trim()
        return if (text.isEmpty()) "" else "$text "
    }

    private fun shortIdOf(m: IMethodData): String {
        val ref = m.methodRef.apply { load() }
        return "${ref.name}(${ref.argTypes.joinToString("")})${ref.returnType}"
    }

    private fun <T> withMethod(cls: JavaClass, shortId: String, block: (IMethodData) -> T): T? {
        val data = cls.classNode?.clsData ?: return null
        var result: T? = null
        var found = false
        runCatching {
            data.visitFieldsAndMethods(
                ISeqConsumer<IFieldData> {},
                ISeqConsumer<IMethodData> { m -> if (!found && shortIdOf(m) == shortId) { found = true; result = block(m) } },
            )
        }
        return result
    }

    fun methodShortIds(cls: JavaClass): List<String> {
        val data = cls.classNode?.clsData ?: return emptyList()
        val out = ArrayList<String>()
        runCatching { data.visitFieldsAndMethods(ISeqConsumer<IFieldData> {}, ISeqConsumer<IMethodData> { out.add(shortIdOf(it)) }) }
        return out
    }

    fun fieldNames(cls: JavaClass): List<String> {
        val data = cls.classNode?.clsData ?: return emptyList()
        val out = ArrayList<String>()
        runCatching { data.visitFieldsAndMethods(ISeqConsumer<IFieldData> { out.add(it.name) }, ISeqConsumer<IMethodData> {}) }
        return out
    }

    fun methodSmali(cls: JavaClass, shortId: String, resources: Map<Int, String>): String? =
        withMethod(cls, shortId) { m -> StringBuilder().also { appendMethod(it, m, resources) }.toString().trim() }

    fun instructions(cls: JavaClass, shortId: String, resources: Map<Int, String>): List<Map<String, Any?>>? =
        withMethod(cls, shortId) { m ->
            val reader = m.codeReader ?: return@withMethod emptyList()
            val isStatic = AccessFlags.hasFlag(m.accessFlags, AccessFlags.STATIC)
            val ref = m.methodRef.apply { load() }
            val insSize = (if (isStatic) 0 else 1) + ref.argTypes.sumOf { if (it == "J" || it == "D") 2 else 1 }
            val paramBase = reader.registersCount - insSize
            val codeBase = reader.codeOffset
            val lines = reader.debugInfo?.sourceLineMapping ?: emptyMap()
            val rows = ArrayList<Map<String, Any?>>()
            reader.visitInstructions { insn ->
                insn.decode()
                val name = insn.opcode?.name ?: ""
                val payload = payload(insn)
                val operands = payload ?: operandText(insn, name, paramBase)
                val resource = if (payload == null && isLiteral(name)) resources[insn.literal.toInt()]?.let { "@$it" } else null
                rows.add(
                    linkedMapOf(
                        "offset" to insn.offset,
                        "addr" to (codeBase + insn.offset * 2),
                        "line" to lines[insn.offset],
                        "mnemonic" to insn.opcodeMnemonic,
                        "operands" to operands,
                        "comment" to comment(insn).removePrefix(" # ").trim().ifEmpty { null },
                        "resource" to resource,
                    )
                )
            }
            rows
        }

    fun stringRefs(cls: JavaClass): List<Pair<String, String>> {
        val data = cls.classNode?.clsData ?: return emptyList()
        val out = ArrayList<Pair<String, String>>()
        runCatching {
            data.visitFieldsAndMethods(
                ISeqConsumer<IFieldData> {},
                ISeqConsumer<IMethodData> { m ->
                    val shortId = shortIdOf(m)
                    m.codeReader?.let { reader ->
                        runCatching {
                            reader.visitInstructions { insn ->
                                insn.decode()
                                if (insn.indexType == InsnIndexType.STRING_REF) runCatching { out.add(shortId to insn.indexAsString) }
                            }
                        }
                    }
                },
            )
        }
        return out
    }

    fun scanCode(cls: JavaClass, rx: Regex): List<Triple<String, Int, String>> {
        val data = cls.classNode?.clsData ?: return emptyList()
        val out = ArrayList<Triple<String, Int, String>>()
        runCatching {
            data.visitFieldsAndMethods(
                ISeqConsumer<IFieldData> {},
                ISeqConsumer<IMethodData> { m ->
                    val reader = m.codeReader ?: return@ISeqConsumer
                    val shortId = shortIdOf(m)
                    val isStatic = AccessFlags.hasFlag(m.accessFlags, AccessFlags.STATIC)
                    val insSize = (if (isStatic) 0 else 1) + m.methodRef.argTypes.sumOf { if (it == "J" || it == "D") 2 else 1 }
                    val paramBase = reader.registersCount - insSize
                    runCatching {
                        reader.visitInstructions { insn ->
                            insn.decode()
                            val name = insn.opcode?.name ?: ""
                            val text = "${insn.opcodeMnemonic} ${payload(insn) ?: operandText(insn, name, paramBase)}".trim()
                            if (rx.containsMatchIn(text)) out.add(Triple(shortId, insn.offset, text))
                        }
                    }
                },
            )
        }
        return out
    }

    fun fieldAccessIn(cls: JavaClass, shortId: String, fieldClassDesc: String, fieldName: String): Pair<Boolean, Boolean> =
        withMethod(cls, shortId) { m ->
            var reads = false
            var writes = false
            m.codeReader?.let { reader ->
                runCatching {
                    reader.visitInstructions { insn ->
                        insn.decode()
                        if (insn.indexType == InsnIndexType.FIELD_REF) {
                            val f = insn.indexAsField
                            if (f.name == fieldName && f.parentClassType == fieldClassDesc) {
                                val n = insn.opcode?.name ?: ""
                                if (n.startsWith("IPUT") || n.startsWith("SPUT")) writes = true
                                if (n.startsWith("IGET") || n.startsWith("SGET")) reads = true
                            }
                        }
                    }
                }
            }
            reads to writes
        } ?: (false to false)

    fun strings(cls: JavaClass): List<String> {
        val data = cls.classNode?.clsData ?: return emptyList()
        val seen = LinkedHashSet<String>()
        runCatching {
            data.visitFieldsAndMethods(
                ISeqConsumer<IFieldData> {},
                ISeqConsumer<IMethodData> { m ->
                    m.codeReader?.let { reader ->
                        runCatching {
                            reader.visitInstructions { insn ->
                                insn.decode()
                                if (insn.indexType == InsnIndexType.STRING_REF) runCatching { seen.add(insn.indexAsString) }
                            }
                        }
                    }
                },
            )
        }
        return seen.toList()
    }

    fun classInfo(cls: JavaClass): Map<String, Any?> {
        val data = cls.classNode?.clsData
        val flags = data?.accessFlags ?: 0
        return linkedMapOf(
            "descriptor" to "L${cls.rawName.replace('.', '/')};",
            "name" to cls.rawName.substringAfterLast('.'),
            "package" to cls.rawName.substringBeforeLast('.', ""),
            "super" to data?.superType,
            "interfaces" to (data?.interfacesTypes ?: emptyList<String>()),
            "access_flags" to flags,
            "modifiers" to AccessFlags.format(flags, AccessFlagsScope.CLASS).trim(),
        )
    }

    fun methodInfo(cls: JavaClass, shortId: String): Map<String, Any?>? =
        withMethod(cls, shortId) { m ->
            val ref = m.methodRef.apply { load() }
            linkedMapOf(
                "descriptor" to "L${cls.rawName.replace('.', '/')};->$shortId",
                "name" to ref.name,
                "signature" to shortId,
                "return_type" to ref.returnType,
                "arg_types" to ref.argTypes.toList(),
                "access_flags" to m.accessFlags,
                "modifiers" to AccessFlags.format(m.accessFlags, AccessFlagsScope.METHOD).trim(),
                "registers" to (m.codeReader?.registersCount ?: 0),
            )
        }

    fun fieldInfo(cls: JavaClass, name: String): Map<String, Any?>? {
        val data = cls.classNode?.clsData ?: return null
        var result: Map<String, Any?>? = null
        runCatching {
            data.visitFieldsAndMethods(
                ISeqConsumer<IFieldData> { f ->
                    if (result == null && f.name == name) {
                        result = linkedMapOf(
                            "descriptor" to "L${cls.rawName.replace('.', '/')};->${f.name}",
                            "name" to f.name,
                            "type" to f.type,
                            "access_flags" to f.accessFlags,
                            "modifiers" to AccessFlags.format(f.accessFlags, AccessFlagsScope.FIELD).trim(),
                        )
                    }
                },
                ISeqConsumer<IMethodData> {},
            )
        }
        return result
    }
}
