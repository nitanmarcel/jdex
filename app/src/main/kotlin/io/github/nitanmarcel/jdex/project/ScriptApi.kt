package io.github.nitanmarcel.jdex.project

import jadx.api.JadxDecompiler

class ScriptApi(
    private val session: () -> ApkSession?,
    private val renameStore: () -> RenameStore = { NoRenames },
    private val onChanged: () -> Unit = {},
    private val dexStore: () -> DexStore = { NoDexStore },
    private val onReanalyze: () -> Unit = {},
    private val importer: (String, ByteArray) -> Unit = { _, _ -> },
    private val ui: ScriptUi = NoScriptUi,
) {

    private fun active(): ApkSession = session() ?: throw IllegalStateException("No APK or DEX loaded")

    private fun malformed(sha: String): MalformedDex? = active().malformedDexes.firstOrNull { it.sha == sha }

    private fun rawOf(desc: String): String = desc.substringBefore("->").removePrefix("L").removeSuffix(";").replace('/', '.')

    private fun descOf(raw: String): String = "L" + raw.replace('.', '/') + ";"

    fun classDescriptors(): List<String> = active().classRawNames().map { descOf(it) }

    fun hasClass(desc: String): Boolean = active().classNode(rawOf(desc)) != null

    fun classMethods(desc: String): List<String> = active().members(rawOf(desc)).methods.map { "$desc->${it.shortId}" }

    fun classFields(desc: String): List<String> = active().members(rawOf(desc)).fields.map { "$desc->${it.name}" }

    fun classJava(desc: String): String = active().javaSource(rawOf(desc)) ?: ""

    fun classSmali(desc: String): String = active().smali(rawOf(desc)) ?: ""

    fun classSuper(desc: String): String? = active().classSuper(rawOf(desc))

    fun classInterfaces(desc: String): List<String> = active().classInterfaces(rawOf(desc))

    fun findMethods(pattern: String): List<String> = active().findMethods(pattern)

    fun findFields(pattern: String): List<String> = active().findFields(pattern)

    fun methodSmali(desc: String): String? = active().methodSmali(rawOf(desc), desc.substringAfter("->"))

    fun methodInstructions(desc: String): List<Map<String, Any?>>? =
        active().methodInstructions(rawOf(desc), desc.substringAfter("->"))

    fun classStrings(desc: String): List<String> = active().classStrings(rawOf(desc))

    fun classInfo(desc: String): Map<String, Any?>? = active().classInfo(rawOf(desc))

    fun methodInfo(desc: String): Map<String, Any?>? = active().methodInfo(rawOf(desc), desc.substringAfter("->"))

    fun fieldInfo(desc: String): Map<String, Any?>? =
        active().fieldInfo(rawOf(desc), desc.substringAfter("->").substringBefore(':'))

    fun searchCode(pattern: String, limit: Int): List<Map<String, Any?>> = active().searchCode(pattern, limit)

    fun allStrings(): List<Map<String, Any?>> = active().allStrings()

    fun fieldReads(desc: String): List<String> = active().fieldAccess(desc, write = false)

    fun fieldWrites(desc: String): List<String> = active().fieldAccess(desc, write = true)

    fun offsetAtLine(desc: String, line: Int): Int? = active().offsetAtLine(rawOf(desc), line)

    fun xrefsTo(desc: String): List<String> {
        val kind = when {
            "->" !in desc -> SymbolKind.TYPE
            '(' in desc.substringAfter("->") -> SymbolKind.METHOD
            else -> SymbolKind.FIELD
        }
        val usages = active().usages(Symbol(kind, desc)) ?: return emptyList()
        return usages.map { u ->
            val cls = descOf(u.rawName)
            when {
                u.shortId != null -> "$cls->${u.shortId}"
                u.fieldName != null -> "$cls->${u.fieldName}"
                else -> cls
            }
        }
    }

    fun manifest(): String = active().manifest()

    fun permissions(): List<String> = active().permissions()

    fun components(tag: String): List<String> = active().components(tag)

    fun appPackage(): String? = active().appPackage

    fun mainActivity(): String? = active().mainActivity()

    fun dexShas(): List<String> = active().malformedDexes.map { it.sha }

    fun dexName(sha: String): String = malformed(sha)?.name ?: ""

    fun dexProblems(sha: String): List<String> = malformed(sha)?.problems ?: emptyList()

    fun dexBytes(sha: String): ByteArray = malformed(sha)?.effective ?: ByteArray(0)

    fun dexSourceBytes(sha: String): ByteArray = malformed(sha)?.source ?: ByteArray(0)

    fun dexMalformed(sha: String): Boolean = malformed(sha)?.let { Dex.parseBroken(it.effective) } ?: false

    fun validateDex(bytes: ByteArray): List<String> = Dex.validate(bytes)

    fun repairDex(sha: String): Boolean {
        val md = malformed(sha) ?: return false
        val repaired = Dex.repair(md.effective)
        dexStore().savePatch(sha, DexPatch.between(md.source, repaired))
        onReanalyze()
        return !Dex.parseBroken(repaired)
    }

    fun saveDex(sha: String, bytes: ByteArray) {
        val md = malformed(sha) ?: return
        dexStore().savePatch(sha, DexPatch.between(md.source, bytes))
        onReanalyze()
    }

    fun rename(key: String, name: String?) {
        renameStore().setRename(key, name?.takeIf { it.isNotBlank() })
        onChanged()
    }

    fun fileNames(): List<String> = active().entryNames()

    fun readFile(path: String): ByteArray = active().readFile(path)

    fun importDex(name: String, bytes: ByteArray) = importer(name, bytes)

    fun uiMessage(text: String, error: Boolean) = ui.message(text, error)

    fun uiInput(prompt: String, default: String): String? = ui.input(prompt, default)

    fun uiConfirm(text: String): Boolean = ui.confirm(text)

    fun uiGotoOffset(offset: Long) = ui.gotoOffset(offset)

    fun uiOpen(desc: String) = ui.open(desc)

    fun jadx(): JadxDecompiler = active().decompiler()
}

interface ScriptUi {
    fun message(text: String, error: Boolean) {}
    fun input(prompt: String, default: String): String? = null
    fun confirm(text: String): Boolean = false
    fun gotoOffset(offset: Long) {}
    fun open(desc: String) {}
}

object NoScriptUi : ScriptUi
