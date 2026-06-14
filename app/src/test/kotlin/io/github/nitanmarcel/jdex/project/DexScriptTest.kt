package io.github.nitanmarcel.jdex.project

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipFile

class DexScriptTest {

    private val apk = File(System.getProperty("user.home"), "Downloads/pinning-demo.apk")

    @Test
    fun scriptInspectsAndRepairsMalformedDex(@TempDir dir: File) {
        assumeTrue(apk.exists(), "sample apk not present")
        val classes = ZipFile(apk).use { zip ->
            val entry = zip.getEntry("classes.dex")!!
            zip.getInputStream(entry).use { it.readBytes() }
        }
        val broken = classes.copyOf().also { it[0x24] = 0 }
        assertTrue(Dex.parseBroken(broken), "fixture should be malformed")

        val brokenFile = File(dir, "classes.dex").apply { writeBytes(broken) }

        val patches = HashMap<String, DexPatch>()
        val store = object : DexStore {
            override fun importedDexes(): List<StoredDex> = emptyList()
            override fun patch(sha: String): DexPatch? = patches[sha]
            override fun savePatch(sha: String, patch: DexPatch) { patches[sha] = patch }
            override fun saveImported(sha: String, name: String, bytes: ByteArray) = Unit
        }
        var reanalyzed = 0
        val session = ApkSession.load(brokenFile, "broken", store)
        try {
            val api = ScriptApi({ session }, dexStore = { store }, onReanalyze = { reanalyzed++ })
            val out = ByteArrayOutputStream()
            ScriptEngine(api, out).use { engine ->
                engine.eval(
                    """
                    dexes = jdex.malformed_dexes()
                    print('count', len(dexes))
                    d = dexes[0]
                    print('name', d.name)
                    print('problems', len(d.problems))
                    print('malformed', d.malformed)
                    print('bytes', len(d.bytes()))
                    print('repaired', d.repair())
                    """.trimIndent()
                )
            }
            val text = out.toString(Charsets.UTF_8)
            println(text)
            fun field(name: String) = Regex("""$name (.+)""").find(text)!!.groupValues[1].trim()

            assertEquals(1, field("count").toInt(), "one malformed dex expected")
            assertEquals("classes.dex", field("name"))
            assertTrue(field("problems").toInt() > 0, "expected validation problems")
            assertEquals("True", field("malformed"))
            assertEquals(broken.size.toString(), field("bytes"))
            assertEquals("True", field("repaired"), "repair should report valid")

            assertEquals(1, patches.size, "repair should have saved a patch")
            assertTrue(reanalyzed >= 1, "repair should trigger re-analyze")
            val sha = patches.keys.first()
            assertTrue(!Dex.parseBroken(patches.getValue(sha).apply(broken)), "saved patch should yield a valid dex")
        } finally {
            session.close()
        }
    }
}
