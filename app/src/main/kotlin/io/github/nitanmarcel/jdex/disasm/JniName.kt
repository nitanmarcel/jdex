package io.github.nitanmarcel.jdex.disasm

object JniName {
    fun mangle(s: String): String = buildString {
        for (c in s) when {
            c == '/' -> append('_')
            c == '_' -> append("_1")
            c == ';' -> append("_2")
            c == '[' -> append("_3")
            c.code in 48..57 || c.code in 65..90 || c.code in 97..122 -> append(c)
            else -> append("_0%04x".format(c.code))
        }
    }

    fun demangle(symbol: String): Pair<String, String>? {
        if (!symbol.startsWith("Java_")) return null
        val body = symbol.removePrefix("Java_").substringBefore("__")
        val full = unmangle(body) ?: return null
        val slash = full.lastIndexOf('/')
        if (slash <= 0) return null
        return full.substring(0, slash).replace('/', '.') to full.substring(slash + 1)
    }

    fun demangleArgs(symbol: String): String? {
        if (!symbol.startsWith("Java_")) return null
        val rest = symbol.removePrefix("Java_")
        val idx = rest.indexOf("__")
        if (idx < 0) return null
        return unmangle(rest.substring(idx + 2))
    }

    private fun unmangle(body: String): String? {
        val sb = StringBuilder()
        var i = 0
        while (i < body.length) {
            val c = body[i]
            if (c != '_') { sb.append(c); i++; continue }
            when (body.getOrNull(i + 1)) {
                '1' -> { sb.append('_'); i += 2 }
                '2' -> { sb.append(';'); i += 2 }
                '3' -> { sb.append('['); i += 2 }
                '0' -> {
                    if (i + 6 > body.length) return null
                    val code = body.substring(i + 2, i + 6).toIntOrNull(16) ?: return null
                    sb.append(code.toChar()); i += 6
                }
                else -> { sb.append('/'); i++ }
            }
        }
        return sb.toString()
    }
}
