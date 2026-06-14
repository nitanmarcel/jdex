package io.github.nitanmarcel.jdex.project

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.File

class ScriptEngineTest {

    private val apk = File(System.getProperty("user.home"), "Downloads/pinning-demo.apk")

    @Test
    fun objectModelNavigatesOffsetsAndRenames() {
        assumeTrue(apk.exists(), "sample apk not present")
        val session = ApkSession.load(apk, "pinning-demo")
        val renamed = HashMap<String, String?>()
        val store = object : RenameStore {
            override fun renames(): Map<String, String> = renamed.filterValues { it != null }.mapValues { it.value!! }
            override fun setRename(key: String, name: String?) { renamed[key] = name }
        }
        var refreshes = 0
        try {
            val api = ScriptApi({ session }, { store }, { refreshes++ })
            val out = ByteArrayOutputStream()
            ScriptEngine(api, out).use { engine ->
                engine.eval(
                    """
                    classes = jdex.classes()
                    print('classes', len(classes))
                    c = jdex.get_class(jdex.main_activity()) or classes[0]
                    print('target', c.descriptor)
                    print('methods', len(c.methods()))
                    print('smali', len(c.smali()) > 0)
                    print('java', len(c.java()) > 0)
                    print('raw', jdex.jadx().getClassesWithInners().size())
                    print('perms', len(jdex.permissions()))
                    print('manifest', len(jdex.manifest()) > 0)
                    found = None
                    for cls in classes[:300]:
                        for line in range(1, 80):
                            o = cls.offset_at_line(line)
                            if o is not None:
                                found = o
                                break
                        if found is not None:
                            break
                    print('offset', found)
                    c.rename('RenamedByScript')
                    print('renamed_key', c.descriptor)
                    """.trimIndent()
                )
            }
            val text = out.toString(Charsets.UTF_8)
            println(text)
            fun field(name: String) = Regex("""$name (.+)""").find(text)!!.groupValues[1].trim()

            assertTrue(field("classes").toInt() > 0, "no classes")
            assertEquals(field("classes").toInt(), field("raw").toInt(), "object model vs raw class count")
            assertTrue(field("smali") == "True", "empty smali")
            assertTrue(field("java") == "True", "empty java")
            assertTrue(field("manifest") == "True", "empty manifest")
            assertTrue(field("offset").toIntOrNull() != null, "no bytecode offset resolved anywhere")

            val key = field("renamed_key")
            assertEquals("RenamedByScript", renamed[key], "rename not written to store for $key")
            assertTrue(refreshes >= 1, "rename did not trigger a refresh")
        } finally {
            session.close()
        }
    }

    @Test
    fun quickWinsFindInfoStringsAndMethodSmali() {
        assumeTrue(apk.exists(), "sample apk not present")
        val session = ApkSession.load(apk, "pinning-demo")
        try {
            val api = ScriptApi({ session })
            val out = ByteArrayOutputStream()
            ScriptEngine(api, out).use { engine ->
                engine.eval(
                    """
                    inits = jdex.find_methods(r'-><init>\(')
                    print('find_methods', len(inits) > 0)
                    print('find_methods_type', type(inits[0]).__name__)
                    serial = jdex.find_fields(r'serialVersionUID')
                    print('find_fields', len(serial) >= 0)

                    cls = None
                    for c in jdex.classes():
                        ms = c.methods()
                        if ms and any(len(m.smali() or '') > 0 for m in ms):
                            cls = c
                            break
                    print('cls', cls is not None)

                    ci = cls.info()
                    print('class_info_dict', isinstance(ci, dict))
                    print('class_info_desc', ci['descriptor'] == cls.descriptor)
                    print('class_info_iface', isinstance(ci['interfaces'], list))

                    m = None
                    for cand in cls.methods():
                        if m is None and len(cand.smali() or '') > 0:
                            m = cand
                    mi = m.info()
                    print('method_info_dict', isinstance(mi, dict))
                    print('method_info_args', isinstance(mi['arg_types'], list))
                    print('method_info_regs', isinstance(mi['registers'], int))
                    print('method_smali', len((m.smali() or '')) > 0)

                    insns = m.instructions()
                    print('insns_list', isinstance(insns, list) and len(insns) > 0)
                    row = insns[0]
                    print('insns_row', isinstance(row, dict) and 'mnemonic' in row and 'offset' in row)
                    print('insns_offset_int', isinstance(row['offset'], int))

                    flds = cls.fields()
                    if flds:
                        fi = flds[0].info()
                        print('field_info_dict', isinstance(fi, dict) and 'type' in fi)
                    else:
                        print('field_info_dict', True)

                    print('strings_list', isinstance(cls.strings(), list))
                    """.trimIndent()
                )
            }
            val text = out.toString(Charsets.UTF_8)
            println(text)
            fun flag(name: String) = Regex("""$name (.+)""").find(text)!!.groupValues[1].trim()

            assertEquals("True", flag("find_methods"), "find_methods empty")
            assertEquals("Method", flag("find_methods_type"), "find_methods returned wrong type")
            assertEquals("True", flag("cls"), "no class with method smali found")
            assertEquals("True", flag("class_info_dict"), "class info not a dict")
            assertEquals("True", flag("class_info_desc"), "class info descriptor mismatch")
            assertEquals("True", flag("class_info_iface"), "class info interfaces not a list")
            assertEquals("True", flag("method_info_dict"), "method info not a dict")
            assertEquals("True", flag("method_info_args"), "method info arg_types not a list")
            assertEquals("True", flag("method_info_regs"), "method info registers not an int")
            assertEquals("True", flag("method_smali"), "method smali empty")
            assertEquals("True", flag("insns_list"), "instructions not a non-empty list")
            assertEquals("True", flag("insns_row"), "instruction row missing keys")
            assertEquals("True", flag("insns_offset_int"), "instruction offset not an int")
            assertEquals("True", flag("field_info_dict"), "field info not a usable dict")
            assertEquals("True", flag("strings_list"), "strings not a list")
        } finally {
            session.close()
        }
    }

    @Test
    fun globalSearchStringsAndFieldAccessSplit() {
        assumeTrue(apk.exists(), "sample apk not present")
        val session = ApkSession.load(apk, "pinning-demo")
        try {
            val api = ScriptApi({ session })
            val out = ByteArrayOutputStream()
            ScriptEngine(api, out).use { engine ->
                engine.eval(
                    """
                    hits = jdex.search_code(r'invoke', limit=50)
                    print('search_capped', isinstance(hits, list) and len(hits) <= 50)
                    print('search_row', bool(hits) and {'method', 'offset', 'text'} <= set(hits[0].keys()))

                    strs = jdex.strings()
                    print('strings_rows', isinstance(strs, list) and (len(strs) == 0 or {'value', 'method'} <= set(strs[0].keys())))

                    # find a field that is both read and written somewhere
                    target = None
                    for f in jdex.find_fields(r'->'):
                        r = f.reads()
                        w = f.writes()
                        if r or w:
                            target = (f, r, w)
                            break
                    print('field_found', target is not None)
                    if target is not None:
                        f, r, w = target
                        print('reads_type', len(r) == 0 or type(r[0]).__name__ == 'Method')
                        print('writes_type', len(w) == 0 or type(w[0]).__name__ == 'Method')
                    else:
                        print('reads_type', True)
                        print('writes_type', True)
                    """.trimIndent()
                )
            }
            val text = out.toString(Charsets.UTF_8)
            println(text)
            fun flag(name: String) = Regex("""$name (.+)""").find(text)!!.groupValues[1].trim()

            assertEquals("True", flag("search_capped"), "search_code ignored limit or wrong type")
            assertEquals("True", flag("search_row"), "search_code row missing keys")
            assertEquals("True", flag("strings_rows"), "global strings rows malformed")
            assertEquals("True", flag("field_found"), "no field with read/write access found")
            assertEquals("True", flag("reads_type"), "field.reads() returned non-Method")
            assertEquals("True", flag("writes_type"), "field.writes() returned non-Method")
        } finally {
            session.close()
        }
    }
}
