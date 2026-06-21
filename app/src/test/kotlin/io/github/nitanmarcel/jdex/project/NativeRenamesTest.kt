package io.github.nitanmarcel.jdex.project

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NativeRenamesTest {

    private class MapStore(val map: MutableMap<String, String> = HashMap()) : RenameStore {
        override fun renames() = map
        override fun setRename(key: String, name: String?) { if (name == null) map.remove(key) else map[key] = name }
    }

    @Test
    fun nativeOverlayAppliesPerLibScopedRenames() {
        val store = MapStore()
        store.setRename("n:abc123:libfoo.so:sub_1234", "decrypt")
        store.setRename("n:abc123:libfoo.so:sub_5678", "checkRoot")
        val r = Renames(store); r.reload()

        val lib = "abc123:libfoo.so"
        assertEquals("decrypt", r.nativeName(lib, "sub_1234"))
        assertEquals("sub_1234", r.nativeRaw(lib, "decrypt"))
        assertEquals("00001000: bl      decrypt", r.nativeDisplay("00001000: bl      sub_1234", lib))
        assertEquals("    x0 = checkRoot();", r.nativeDisplay("    x0 = sub_5678();", lib))
        assertEquals("00001000: b       sub_12345", r.nativeDisplay("00001000: b       sub_12345", lib))
    }

    @Test
    fun nativeRenamesAreLibIsolatedAndDontLeakIntoDex() {
        val store = MapStore()
        store.setRename("n:hashA:liba.so:sub_10", "a_fn")
        store.setRename("n:hashB:libb.so:sub_10", "b_fn")
        store.setRename("Lcom/x;->a()V", "doThing")
        val r = Renames(store); r.reload()

        assertEquals("a_fn", r.nativeName("hashA:liba.so", "sub_10"))
        assertEquals("b_fn", r.nativeName("hashB:libb.so", "sub_10"))
        assertNull(r.nativeName("hashA:liba.so", "sub_99"))
        assertEquals("doThing", r.nameFor("Lcom/x;->a()V"))
        assertNull(r.nativeName("hashA:liba.so", "Lcom/x;"))
    }

    @Test
    fun jniBoundNativeDerivesDisplayFromDexRename() {
        val store = MapStore()
        val r = Renames(store)
        val dexKey = "Lcom/example/Native;->nativeCompute([BI)I"
        val token = "Java_com_example_Native_nativeCompute"
        r.setNativeJniBindings("a1:libfoo.so:cap.arm64.le", mapOf(token to dexKey))
        r.setNativeJniBindings("a2:libfoo.so:cap.arm.le", mapOf(token to dexKey))
        assertNull(r.nativeName("a1:libfoo.so:cap.arm64.le", token))

        store.setRename(dexKey, "decrypt")
        r.reload()
        assertEquals("decrypt", r.nativeName("a1:libfoo.so:cap.arm64.le", token))
        assertEquals("decrypt", r.nativeName("a2:libfoo.so:cap.arm.le", token))
        assertEquals(token, r.nativeRaw("a2:libfoo.so:cap.arm.le", "decrypt"))
        assertTrue(store.map.keys.none { it.startsWith("n:") }, "JNI rename must not write a per-lib n: key")
    }
}
