package io.github.nitanmarcel.jdex.project

interface RenameStore {
    fun renames(): Map<String, String>
    fun setRename(key: String, name: String?)
}

object NoRenames : RenameStore {
    override fun renames(): Map<String, String> = emptyMap()
    override fun setRename(key: String, name: String?) = Unit
}

class Renames(var store: RenameStore = NoRenames) {

    private var forward: Map<String, String> = emptyMap()
    private val displayNames = HashMap<String, String>()
    private val classDisplay = HashMap<String, String>()
    private val classReverse = HashMap<String, String>()
    private val methodReverse = HashMap<String, String>()
    private val fieldReverse = HashMap<String, String>()
    private val localRenames = HashMap<String, MutableMap<String, String>>()
    private val localReverse = HashMap<String, MutableMap<String, String>>()

    init {
        reload()
    }

    fun reload() {
        forward = store.renames()
        displayNames.clear()
        classDisplay.clear(); classReverse.clear(); methodReverse.clear(); fieldReverse.clear()
        localRenames.clear(); localReverse.clear()
        displayNames.putAll(disambiguate(forward))
        for (key in forward.keys) {
            val name = displayNames[key] ?: continue
            if ('#' in key) {
                val methodKey = key.substringBeforeLast('#')
                val register = key.substringAfterLast('#')
                localRenames.getOrPut(methodKey) { HashMap() }[register] = name
                localReverse.getOrPut(methodKey) { HashMap() }[name] = register
                continue
            }
            val member = if ("->" in key) key.substringAfter("->") else null
            when {
                member == null -> {
                    val disp = classDisplayDesc(key, name)
                    classDisplay[key] = disp
                    classReverse[disp] = key
                }
                '(' in member -> {
                    val cls = key.substringBefore("->")
                    val sig = member.substring(member.indexOf('('))
                    methodReverse["$cls->$name$sig"] = key
                }
                else -> {
                    val cls = key.substringBefore("->")
                    fieldReverse["$cls->$name"] = key
                }
            }
        }
    }

    private fun disambiguate(map: Map<String, String>): Map<String, String> {
        val result = HashMap<String, String>()
        val groups = LinkedHashMap<String, MutableList<String>>()
        for ((key, name) in map) {
            val scope = scopeOf(key, name)
            if (scope == null) result[key] = name else groups.getOrPut(scope) { ArrayList() }.add(key)
        }
        for (keys in groups.values) {
            keys.sort()
            keys.forEachIndexed { i, k -> result[k] = if (i == 0) map.getValue(k) else "${map.getValue(k)}${i + 1}" }
        }
        return result
    }

    private fun scopeOf(key: String, name: String): String? = when {
        '#' in key -> "L|${key.substringBeforeLast('#')}|$name"
        "->" !in key -> {
            val inner = key.removePrefix("L").removeSuffix(";")
            "C|${if ('/' in inner) inner.substringBeforeLast('/') else ""}|$name"
        }
        '(' in key.substringAfter("->") -> null
        else -> "F|${key.substringBefore("->")}|$name"
    }

    fun hasLocals() = localRenames.isNotEmpty()

    fun localRegister(methodKey: String, name: String): String? = localReverse[methodKey]?.get(name)

    fun hasAny() = forward.isNotEmpty()

    val active: Boolean get() = store !== NoRenames

    fun nameFor(key: String): String? = displayNames[key]

    fun snapshot(): Map<String, String> = forward

    private fun classDisplayDesc(key: String, name: String): String {
        val inner = key.removePrefix("L").removeSuffix(";")
        val slash = inner.lastIndexOf('/')
        val pkg = if (slash >= 0) inner.substring(0, slash + 1) else ""
        return "L$pkg$name;"
    }

    fun display(raw: String, sectionClass: () -> String?, methodKey: () -> String? = { null }): String {
        if (forward.isEmpty()) return raw
        var line = raw
        for (key in forward.keys) {
            if ('#' in key) continue
            val name = displayNames[key] ?: continue
            val member = if ("->" in key) key.substringAfter("->") else continue
            if ('(' in member) {
                if (key in line) {
                    val cls = key.substringBefore("->")
                    val sig = member.substring(member.indexOf('('))
                    line = line.replace(key, "$cls->$name$sig")
                }
            } else if ("$key:" in line) {
                val cls = key.substringBefore("->")
                line = line.replace("$key:", "$cls->$name:")
            }
        }
        for ((key, disp) in classDisplay) {
            if (key in line) line = line.replace(key, disp)
        }
        val trimmed = line.trimStart()
        if (trimmed.startsWith(".method") || trimmed.startsWith(".field")) {
            val secDesc = sectionClass()?.let { "L${it.replace('.', '/')};" }
            if (secDesc != null) line = renameDeclaration(line, trimmed, secDesc)
        }
        if (localRenames.isNotEmpty()) {
            val locals = methodKey()?.let { localRenames[it] }
            if (!locals.isNullOrEmpty()) line = replaceRegisters(line, locals)
        }
        return line
    }

    private fun replaceRegisters(line: String, regs: Map<String, String>): String {
        val q = line.indexOf('"')
        val head = if (q >= 0) line.substring(0, q) else line
        var h = head
        for ((reg, name) in regs) {
            if (reg in h) h = Regex("\\b${Regex.escape(reg)}\\b").replace(h) { name }
        }
        return if (q >= 0) h + line.substring(q) else h
    }

    private fun renameDeclaration(line: String, trimmed: String, secDesc: String): String {
        if (trimmed.startsWith(".method")) {
            val sig = trimmed.substringAfterLast(' ')
            if ('(' !in sig) return line
            val name = displayNames["$secDesc->$sig"] ?: return line
            val newSig = name + sig.substring(sig.indexOf('('))
            return line.dropLast(sig.length) + newSig
        }
        val at = line.indexOf(" : ")
        if (at < 0) return line
        val head = line.substring(0, at)
        val nameEnd = head.trimEnd().length
        val fieldName = head.trimEnd().substringAfterLast(' ')
        val name = displayNames["$secDesc->$fieldName"] ?: return line
        return line.substring(0, nameEnd - fieldName.length) + name + line.substring(nameEnd)
    }

    fun toRaw(symbol: Symbol): Symbol = when (symbol.kind) {
        SymbolKind.TYPE -> Symbol(SymbolKind.TYPE, classReverse[symbol.text] ?: symbol.text)
        SymbolKind.METHOD -> {
            val cls = symbol.text.substringBefore("->")
            val member = symbol.text.substringAfter("->")
            val rawCls = classReverse[cls] ?: cls
            Symbol(SymbolKind.METHOD, methodReverse["$rawCls->$member"] ?: "$rawCls->$member")
        }
        SymbolKind.FIELD -> {
            val cls = symbol.text.substringBefore("->")
            val member = symbol.text.substringAfter("->")
            val rawCls = classReverse[cls] ?: cls
            val name = member.substringBefore(':')
            val type = member.substringAfter(':', "")
            val rawName = fieldReverse["$rawCls->$name"]?.substringAfter("->") ?: name
            Symbol(SymbolKind.FIELD, if (type.isEmpty()) "$rawCls->$rawName" else "$rawCls->$rawName:$type")
        }
        else -> symbol
    }
}
