package io.github.nitanmarcel.jdex.disasm

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class JniNameTest {
    @Test
    fun manglesSimpleName() {
        assertEquals("Java_com_example_Native_compute", "Java_" + JniName.mangle("com/example/Native/compute"))
    }

    @Test
    fun demanglesSimpleName() {
        assertEquals(
            "com.example.jnitest.Native" to "nativeCompute",
            JniName.demangle("Java_com_example_jnitest_Native_nativeCompute"),
        )
    }

    @Test
    fun roundTripsUnderscoreInName() {
        val cls = "com/example/Native"
        val method = "native_compute"
        val symbol = "Java_" + JniName.mangle(cls) + "_" + JniName.mangle(method)
        assertEquals("com.example.Native" to "native_compute", JniName.demangle(symbol))
    }

    @Test
    fun roundTripsInnerClassDollar() {
        val symbol = "Java_" + JniName.mangle("com/example/Outer\$Inner") + "_f"
        assertEquals("com.example.Outer\$Inner" to "f", JniName.demangle(symbol))
    }

    @Test
    fun dropsOverloadArgSuffix() {
        assertEquals(
            "com.example.Native" to "foo",
            JniName.demangle("Java_com_example_Native_foo__Ljava_lang_String_2"),
        )
    }

    @Test
    fun rejectsNonJavaSymbol() {
        assertNull(JniName.demangle("sub_b8930"))
        assertNull(JniName.demangle("JNI_OnLoad"))
    }

    @Test
    fun overloadArgDescriptor() {
        assertEquals("Ljava/lang/String;I", JniName.demangleArgs("Java_com_example_Native_foo__Ljava_lang_String_2I"))
        assertEquals("[BI", JniName.demangleArgs("Java_com_example_Native_foo___3BI"))
        assertNull(JniName.demangleArgs("Java_com_example_Native_foo"))
        assertNull(JniName.demangleArgs("sub_b8930"))
    }
}
