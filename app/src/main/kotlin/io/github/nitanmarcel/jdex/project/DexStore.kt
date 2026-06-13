package io.github.nitanmarcel.jdex.project

interface DexStore {
    fun importedDexes(): List<StoredDex>
    fun patch(sha: String): DexPatch?
    fun savePatch(sha: String, patch: DexPatch)
    fun saveImported(sha: String, name: String, bytes: ByteArray)
}

object NoDexStore : DexStore {
    override fun importedDexes(): List<StoredDex> = emptyList()
    override fun patch(sha: String): DexPatch? = null
    override fun savePatch(sha: String, patch: DexPatch) = Unit
    override fun saveImported(sha: String, name: String, bytes: ByteArray) = Unit
}

class StoredDex(val sha: String, val name: String, val bytes: ByteArray)

class MalformedDex(val name: String, val source: ByteArray, val sha: String, val effective: ByteArray, val problems: List<String>)
