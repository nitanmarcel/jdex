package io.github.nitanmarcel.jdex.disasm

object CppDemangler {
    fun demangle(symbol: String): String? = runCatching {
        val c = Cursor(symbol)
        val ast = parseMangledName(c) ?: return null
        if (!c.atEnd()) return null
        expandArgPacks(ast).render()
    }.getOrNull()

    private val CV_ORDER = listOf("const", "volatile", "restrict")
    private val INT_LIT_SUFFIX = mapOf(
        "int" to "", "unsigned int" to "u", "long" to "l", "unsigned long" to "ul",
        "long long" to "ll", "unsigned long long" to "ull",
    )

    private fun qualString(quals: Set<String>) = CV_ORDER.filter { it in quals }.joinToString(" ")

    private sealed interface Nd {
        fun render(): String
        fun left(): String = render()
        fun right(): String = ""
        fun mapC(f: (Nd) -> Nd): Nd = this
    }

    private class N(val kind: String, val value: Any?) : Nd {
        @Suppress("UNCHECKED_CAST")
        private fun list() = value as List<Nd>
        private fun nd() = value as Nd

        override fun render(): String = when (kind) {
            "name", "builtin", "decl" -> value as String
            "qual_name" -> renderQual(list())
            "tpl_args" -> "<" + list().joinToString(", ") { it.render() } + ">"
            "ctor" -> "{ctor}"
            "dtor" -> "{dtor}"
            "oper" -> (value as String).let { if (it.startsWith("new") || it.startsWith("delete")) "operator $it" else "operator$it" }
            "oper_cast" -> "operator " + nd().render()
            "pointer" -> nd().left() + "*" + nd().right()
            "lvalue" -> nd().left() + "&" + nd().right()
            "rvalue" -> nd().left() + "&&" + nd().right()
            "expand_arg_pack" -> nd().render() + "..."
            "vtable" -> "vtable for " + nd().render()
            "vtt" -> "VTT for " + nd().render()
            "typeinfo" -> "typeinfo for " + nd().render()
            "typeinfo_name" -> "typeinfo name for " + nd().render()
            "nonvirt_thunk" -> "non-virtual thunk to " + nd().render()
            "virt_thunk" -> "virtual thunk to " + nd().render()
            "guard_variable" -> "guard variable for " + nd().render()
            "transaction_clone" -> "transaction clone for " + nd().render()
            "tpl_param" -> "{T$value}"
            else -> kind
        }

        override fun left(): String = when (kind) {
            "pointer" -> nd().left() + "*"
            "lvalue" -> nd().left() + "&"
            "rvalue" -> nd().left() + "&&"
            else -> render()
        }

        override fun right(): String = if (kind == "pointer" || kind == "lvalue" || kind == "rvalue") nd().right() else ""

        override fun mapC(f: (Nd) -> Nd): Nd = when (kind) {
            "oper_cast", "pointer", "lvalue", "rvalue", "expand_arg_pack",
            "vtable", "vtt", "typeinfo", "typeinfo_name" -> N(kind, f(nd()))
            "qual_name", "tpl_args", "tpl_arg_pack" -> N(kind, list().map(f))
            else -> this
        }

        override fun equals(other: Any?) = other is N && other.kind == kind && other.value == value
        override fun hashCode() = 31 * kind.hashCode() + (value?.hashCode() ?: 0)
    }

    private class Qual(val kind: String, val value: Nd, val quals: Set<String>) : Nd {
        override fun render() = if (kind == "cv_qual") (listOf(value.render()) + CV_ORDER.filter { it in quals }).joinToString(" ") else value.render()
        override fun left() = render()
        override fun mapC(f: (Nd) -> Nd): Nd = if (kind == "cv_qual") Qual(kind, f(value), quals) else this
        override fun equals(other: Any?) = other is Qual && other.kind == kind && other.value == value && other.quals == quals
        override fun hashCode() = listOf(kind, value, quals).hashCode()
    }

    private class Lit(val text: String, val ty: Nd) : Nd {
        override fun render(): String {
            if (ty is N && ty.kind == "builtin" && ty.value == "bool") return if (text == "0") "false" else if (text == "1") "true" else text
            val v = if (text.length > 1 && text[0] == 'n' && text.drop(1).all { it.isDigit() }) "-" + text.drop(1) else text
            if (ty is N && ty.kind == "builtin") INT_LIT_SUFFIX[ty.value]?.let { return v + it }
            return "(" + ty.render() + ")" + v
        }
        override fun mapC(f: (Nd) -> Nd): Nd = Lit(text, f(ty))
        override fun equals(other: Any?) = other is Lit && other.text == text && other.ty == ty
        override fun hashCode() = 31 * text.hashCode() + ty.hashCode()
    }

    private class Func(val name: Nd?, val argTys: List<Nd>, val retTy: Nd?) : Nd {
        private fun argsStr() = if (argTys.size == 1 && argTys[0].let { it is N && it.kind == "builtin" && it.value == "void" }) "()"
        else "(" + argTys.joinToString(", ") { it.render() } + ")"

        private fun nameAndQual(): Pair<String, String> {
            var n = name
            var refSuffix = ""
            if (n is N && (n.kind == "lvalue" || n.kind == "rvalue")) { refSuffix = if (n.kind == "lvalue") " &" else " &&"; n = n.value as Nd }
            return if (n is Qual && n.kind == "cv_qual") n.value.render() to (" " + qualString(n.quals) + refSuffix)
            else (n?.render() ?: "") to refSuffix
        }

        override fun render(): String {
            val (nm, q) = nameAndQual()
            val pre = if (retTy != null) retTy.render() + " " else ""
            return pre + nm + argsStr() + q
        }

        override fun left(): String {
            val rl = retTy?.left() ?: ""
            val sep = if (rl.isEmpty() || rl.endsWith("*") || rl.endsWith("&")) "" else " "
            return rl + sep + "(" + (name?.render() ?: "")
        }

        override fun right(): String = ")" + argsStr() + (retTy?.right() ?: "")

        override fun mapC(f: (Nd) -> Nd): Nd =
            Func(name?.let(f), argTys.map(f), retTy?.let(f))

        fun withArgs(a: List<Nd>) = Func(name, a, retTy)
        override fun equals(other: Any?) = other is Func && other.name == name && other.argTys == argTys && other.retTy == retTy
        override fun hashCode() = listOf(name, argTys, retTy).hashCode()
    }

    private class Arr(val dimension: Nd?, val ty: Nd?) : Nd {
        override fun render() = (ty?.render() ?: "") + "[" + (dimension?.render() ?: "") + "]"
        override fun left() = (ty?.render() ?: "") + "("
        override fun right() = ")[" + (dimension?.render() ?: "") + "]"
        override fun mapC(f: (Nd) -> Nd): Nd = Arr(dimension?.let(f), ty?.let(f))
        override fun equals(other: Any?) = other is Arr && other.dimension == dimension && other.ty == ty
        override fun hashCode() = 31 * (dimension?.hashCode() ?: 0) + (ty?.hashCode() ?: 0)
    }

    private class Member(val method: Boolean, val clsTy: Nd?, val memberTy: Nd?) : Nd {
        private val cvSuffix = (memberTy as? Qual)?.takeIf { it.kind == "cv_qual" && it.value is Func }
            ?.let { " " + qualString(it.quals) } ?: ""
        private val fn = ((memberTy as? Qual)?.takeIf { it.kind == "cv_qual" }?.value ?: memberTy)
        private val isMethod = fn is Func

        override fun render() = if (isMethod) (fn?.left() ?: "") + (clsTy?.render() ?: "") + "::*" + (fn?.right() ?: "") + cvSuffix
        else (memberTy?.render() ?: "") + " " + (clsTy?.render() ?: "") + "::*"
        override fun left() = if (isMethod) (fn?.left() ?: "") + (clsTy?.render() ?: "") + "::*" else render()
        override fun right() = if (isMethod) (fn?.right() ?: "") + cvSuffix else ""
        override fun mapC(f: (Nd) -> Nd): Nd = Member(method, clsTy?.let(f), memberTy?.let(f))
        override fun equals(other: Any?) = other is Member && other.method == method && other.clsTy == clsTy && other.memberTy == memberTy
        override fun hashCode() = listOf(method, clsTy, memberTy).hashCode()
    }

    private fun renderQual(nodes: List<Nd>): String {
        val sb = StringBuilder()
        var lastName = ""
        for (n in nodes) {
            val isTpl = n is N && n.kind == "tpl_args"
            if (sb.isNotEmpty() && !isTpl) sb.append("::")
            when {
                n is N && n.kind == "ctor" -> sb.append(lastName)
                n is N && n.kind == "dtor" -> sb.append("~").append(lastName)
                else -> {
                    val s = n.render()
                    sb.append(s)
                    if (n is N && n.kind == "name") lastName = s
                }
            }
        }
        return sb.toString()
    }

    private class Cursor(val raw: String, var pos: Int = 0) {
        val substs = ArrayList<Nd>()
        fun atEnd() = pos >= raw.length
        fun peek() = raw.getOrNull(pos)
        fun peek2() = raw.substring(pos, minOf(pos + 2, raw.length))
        fun accept(d: String): Boolean { if (raw.startsWith(d, pos)) { pos += d.length; return true }; return false }
        fun advance(n: Int): String? { if (pos + n > raw.length) return null; val r = raw.substring(pos, pos + n); pos += n; return r }
        fun advanceUntil(d: String): String? { val i = raw.indexOf(d, pos); if (i < 0) return null; val r = raw.substring(pos, i); pos = i + d.length; return r }
        fun addSubst(node: Nd?) { if (node != null && substs.none { it == node }) substs.add(node) }
        fun resolveSubst(id: Int): Nd? = substs.getOrNull(id)
    }

    private val CTOR_DTOR = mapOf("C1" to "complete", "C2" to "base", "C3" to "allocating", "D0" to "deleting", "D1" to "complete", "D2" to "base")

    private val STD_ABBREV_EXPANSIONS: Set<List<Nd>> =
        listOf("St", "Sa", "Sb", "Ss", "Si", "So", "Sd").map { stdNames(it) }.toSet()

    private fun isStdAbbrev(node: N): Boolean {
        @Suppress("UNCHECKED_CAST") val l = node.value as List<Nd>
        return l in STD_ABBREV_EXPANSIONS
    }

    private fun stdNames(code: String): List<Nd> = when (code) {
        "St" -> listOf(N("name", "std"))
        "Sa" -> listOf(N("name", "std"), N("name", "allocator"))
        "Sb" -> listOf(N("name", "std"), N("name", "basic_string"))
        "Ss" -> listOf(N("name", "std"), N("name", "string"))
        "Si" -> listOf(N("name", "std"), N("name", "istream"))
        "So" -> listOf(N("name", "std"), N("name", "ostream"))
        "Sd" -> listOf(N("name", "std"), N("name", "iostream"))
        else -> emptyList()
    }

    private val OPERATORS = mapOf(
        "nw" to "new", "na" to "new[]", "dl" to "delete", "da" to "delete[]",
        "ps" to "+", "ng" to "-", "ad" to "&", "de" to "*", "co" to "~",
        "pl" to "+", "mi" to "-", "ml" to "*", "dv" to "/", "rm" to "%",
        "an" to "&", "or" to "|", "eo" to "^", "aS" to "=",
        "pL" to "+=", "mI" to "-=", "mL" to "*=", "dV" to "/=", "rM" to "%=",
        "aN" to "&=", "oR" to "|=", "eO" to "^=", "ls" to "<<", "rs" to ">>",
        "lS" to "<<=", "rS" to ">>=", "eq" to "==", "ne" to "!=", "lt" to "<",
        "gt" to ">", "le" to "<=", "ge" to ">=", "nt" to "!", "aa" to "&&",
        "oo" to "||", "pp" to "++", "mm" to "--", "cm" to ",", "pm" to "->*",
        "pt" to "->", "cl" to "()", "ix" to "[]", "qu" to "?",
    )

    private val BUILTINS = mapOf(
        "v" to "void", "w" to "wchar_t", "b" to "bool", "c" to "char", "a" to "signed char",
        "h" to "unsigned char", "s" to "short", "t" to "unsigned short", "i" to "int",
        "j" to "unsigned int", "l" to "long", "m" to "unsigned long", "x" to "long long",
        "y" to "unsigned long long", "n" to "__int128", "o" to "unsigned __int128",
        "f" to "float", "d" to "double", "e" to "long double", "g" to "__float128", "z" to "...",
        "Dd" to "_Decimal64", "De" to "_Decimal128", "Df" to "_Decimal32", "Dh" to "_Float16",
        "Di" to "char32_t", "Ds" to "char16_t", "Da" to "auto", "Dc" to "decltype(auto)", "Dn" to "std::nullptr_t",
    )

    private fun handleCv(quals: String, node: Nd): Nd {
        val set = sortedSetOf<String>()
        if ('r' in quals) set.add("restrict")
        if ('V' in quals) set.add("volatile")
        if ('K' in quals) set.add("const")
        return if (set.isNotEmpty()) Qual("cv_qual", node, set) else node
    }

    private fun handleIndirect(q: Char, node: Nd): Nd = when (q) {
        'P' -> N("pointer", node); 'R' -> N("lvalue", node); 'O' -> N("rvalue", node); else -> node
    }

    private fun parseNumber(c: Cursor): Int? {
        val start = c.pos
        while (!c.atEnd() && c.raw[c.pos].isDigit()) c.pos++
        if (c.pos == start) return null
        return c.raw.substring(start, c.pos).toInt()
    }

    private fun parseSeqId(c: Cursor): Int? {
        val s = c.advanceUntil("_") ?: return null
        return if (s.isEmpty()) 0 else 1 + s.toInt(36)
    }

    private fun parseSourceName(c: Cursor): String? {
        val len = parseNumber(c) ?: return null
        return c.advance(len)
    }

    private fun parseUntilEnd(c: Cursor, kind: String, fn: (Cursor) -> Nd?): Nd? {
        val nodes = ArrayList<Nd>()
        while (!c.accept("E")) {
            val node = fn(c) ?: return null
            if (c.atEnd()) return null
            nodes.add(node)
        }
        return N(kind, nodes)
    }

    private fun parseName(c: Cursor, isNested: Boolean = false, encodingName: Boolean = false): Nd? {
        var node: Nd?
        var isStdPrefix = false
        var isStdName = false
        var isSubst = false
        var isNameOper = false
        val p = c.peek() ?: return null
        val two = c.peek2()

        when {
            p.isDigit() -> {
                val name = parseSourceName(c) ?: return null
                node = N("name", name); isNameOper = true
            }
            two.length == 2 && two[0] == 'C' && two[1] in "123" -> { c.advance(2); node = N("ctor", CTOR_DTOR[two]) }
            two.length == 2 && two[0] == 'D' && two[1] in "012" -> { c.advance(2); node = N("dtor", CTOR_DTOR[two]) }
            two.length == 2 && two[0] == 'S' && two[1] in "absiod" -> {
                c.advance(2); node = N("qual_name", stdNames(two)); isStdName = true
                if (isNested && c.peek() == 'I') {
                    c.accept("I")
                    val tplArgs = parseUntilEnd(c, "tpl_args", ::parseType) ?: return null
                    node = N("qual_name", (node!!.let { (it as N).value as List<*> }).filterIsInstance<Nd>() + tplArgs)
                    c.addSubst(node)
                    isStdName = false
                }
            }
            two in OPERATORS -> { c.advance(2); node = N("oper", OPERATORS[two]); isNameOper = true }
            two == "cv" -> { c.advance(2); val ty = parseType(c) ?: return null; node = N("oper_cast", ty); isNameOper = true }
            two == "St" -> {
                c.advance(2)
                val name = parseName(c, isNested = true) ?: return null
                node = if (name is N && name.kind == "qual_name") N("qual_name", listOf(N("name", "std")) + (name.value as List<*>).filterIsInstance<Nd>())
                else N("qual_name", listOf(N("name", "std"), name))
                isStdPrefix = true
            }
            p == 'S' -> {
                c.advance(1)
                val seq = parseSeqId(c) ?: return null
                node = c.resolveSubst(seq) ?: return null
                isSubst = true
            }
            p == 'N' -> {
                c.advance(1)
                val cvStart = c.pos
                while (!c.atEnd() && c.raw[c.pos] in "rVK") c.pos++
                val cv = c.raw.substring(cvStart, c.pos)
                var ref = ' '
                if (!c.atEnd() && c.raw[c.pos] in "RO") { ref = c.raw[c.pos]; c.pos++ }
                val nodes = ArrayList<Nd>()
                var first = true
                while (true) {
                    val before = c.substs.size
                    val name = parseName(c, isNested = true) ?: return null
                    if (c.atEnd()) return null
                    val bareStdAbbrev = first && name is N && name.kind == "qual_name" &&
                        c.substs.size == before && isStdAbbrev(name)
                    if (name is N && name.kind == "qual_name") nodes.addAll((name.value as List<*>).filterIsInstance<Nd>()) else nodes.add(name)
                    first = false
                    if (c.accept("E")) break else if (!bareStdAbbrev) c.addSubst(N("qual_name", ArrayList(nodes)))
                }
                node = N("qual_name", nodes)
                node = handleCv(cv, node!!)
                if (ref != ' ') node = handleIndirect(ref, node!!)
            }
            p == 'T' -> { c.advance(1); val seq = parseSeqId(c) ?: return null; node = N("tpl_param", seq); c.addSubst(node) }
            p == 'I' -> { c.advance(1); node = parseUntilEnd(c, "tpl_args", ::parseType) }
            p == 'L' -> { c.advance(1); return parseName(c, isNested) }
            else -> return null
        }
        if (node == null) return null

        val abiTags = ArrayList<String>()
        while (c.accept("B")) parseSourceName(c)?.let { abiTags.add(it) }
        if (abiTags.isNotEmpty()) node = Qual("abi", node!!, abiTags.toSortedSet())

        if (!isNested && c.peek() == 'I' &&
            ((node is N && node!!.kind in setOf("name", "oper", "oper_cast")) || isStdPrefix || isStdName || isSubst)
        ) {
            if ((node is N && node!!.kind in setOf("name", "oper", "oper_cast")) || isStdPrefix) c.addSubst(node)
            c.accept("I")
            val tplArgs = parseUntilEnd(c, "tpl_args", ::parseType) ?: return null
            node = N("qual_name", listOf(node!!, tplArgs))
            if ((isStdPrefix || isStdName) && !encodingName) c.addSubst(node)
        }
        return node
    }

    private fun parseType(c: Cursor): Nd? {
        val p = c.peek() ?: return null
        val two = c.peek2()

        if (two.length == 2 && BUILTINS.containsKey(two) && two[0] == 'D') { c.advance(2); return N("builtin", BUILTINS[two]) }
        if (p in "rVK") {
            val start = c.pos
            while (!c.atEnd() && c.raw[c.pos] in "rVK") c.pos++
            val q = c.raw.substring(start, c.pos)
            val ty = parseType(c) ?: return null
            val node = handleCv(q, ty); c.addSubst(node); return node
        }
        if (p in "PRO") { c.advance(1); val ty = parseType(c) ?: return null; val node = handleIndirect(p, ty); c.addSubst(node); return node }
        when (p) {
            'F' -> {
                c.advance(1)
                val ret = parseType(c) ?: return null
                val args = ArrayList<Nd>()
                while (!c.accept("E")) { args.add(parseType(c) ?: return null) }
                val node = Func(null, args, ret); c.addSubst(node); return node
            }
            'L' -> return parseExprPrimary(c)
            'J' -> { c.advance(1); return parseUntilEnd(c, "tpl_arg_pack", ::parseType) }
            'A' -> {
                c.advance(1)
                val dim = parseNumber(c)?.let { Lit(it.toString(), N("builtin", "int")) } ?: return null
                if (!c.accept("_")) return null
                val ty = parseType(c)
                val node = Arr(dim, ty); c.addSubst(node); return node
            }
            'M' -> {
                c.advance(1)
                val cls = parseType(c)
                val member = parseType(c)
                return Member(member is Func, cls, member)
            }
            'D' -> { if (two == "Dp") { c.advance(2); return N("expand_arg_pack", parseType(c) ?: return null) }; return null }
            'X' -> return null
        }
        if (BUILTINS.containsKey(p.toString())) { c.advance(1); return N("builtin", BUILTINS[p.toString()]) }
        val node = parseName(c)
        if (!(node is N && node.kind == "qual_name" && isStdAbbrev(node))) c.addSubst(node)
        return node
    }

    private fun parseExprPrimary(c: Cursor): Nd? {
        if (!c.accept("L")) return null
        if (c.raw.startsWith("_Z", c.pos)) {
            val mn = c.advanceUntil("E") ?: return null
            return parseMangledName(Cursor(mn))
        }
        val ty = parseType(c) ?: return null
        val value = c.advanceUntil("E") ?: return null
        return Lit(value, ty)
    }

    private fun unwrapQualName(node: Nd?): N? {
        var n = node
        if (n is N && (n.kind == "lvalue" || n.kind == "rvalue")) n = n.value as Nd
        if (n is Qual && n.kind == "cv_qual") n = n.value
        return if (n is N && n.kind == "qual_name") n else null
    }

    private fun expandTemplateArgs(func: Func): Func {
        val name = unwrapQualName(func.name)
        if (name is N && name.kind == "qual_name") {
            val suffix = (name.value as List<*>).filterIsInstance<Nd>().lastOrNull()
            if (suffix is N && suffix.kind == "tpl_args") {
                @Suppress("UNCHECKED_CAST") val tplArgs = suffix.value as List<Nd>
                lateinit var mapper: (Nd) -> Nd
                mapper = { node ->
                    if (node is N && node.kind == "tpl_param" && (node.value as Int) < tplArgs.size) tplArgs[node.value]
                    else node.mapC(mapper)
                }
                return mapper(func) as Func
            }
        }
        return func
    }

    private fun parseEncoding(c: Cursor): Nd? {
        val name = parseName(c, encodingName = true) ?: return null
        if (c.atEnd()) return name

        val retTy: Nd? = run {
            val qn = unwrapQualName(name)
            if (qn != null) {
                val vs = (qn.value as List<*>).filterIsInstance<Nd>()
                val last = vs.lastOrNull()
                val secondLast = vs.getOrNull(vs.size - 2)
                if (last is N && last.kind == "tpl_args" && !(secondLast is N && secondLast.kind in setOf("ctor", "dtor", "oper_cast"))) {
                    return@run parseType(c) ?: return null
                }
            }
            null
        }

        val argTys = ArrayList<Nd>()
        while (!c.atEnd()) argTys.add(parseType(c) ?: return null)
        return if (argTys.isNotEmpty()) expandTemplateArgs(Func(name, argTys, retTy)) else name
    }

    private fun parseSpecial(c: Cursor): Nd? {
        val two = c.peek2()
        if (two.length == 2 && two[0] == 'T' && two[1] in "VTIS") {
            c.advance(2)
            val ty = parseType(c) ?: return null
            return N(when (two[1]) { 'V' -> "vtable"; 'T' -> "vtt"; 'I' -> "typeinfo"; else -> "typeinfo_name" }, ty)
        }
        if (two == "Th") {
            c.advance(2); if (c.peek() == 'n') c.advance(1); parseNumber(c); if (!c.accept("_")) return null
            return N("nonvirt_thunk", parseEncoding(c) ?: return null)
        }
        if (two == "Tv") {
            c.advance(2); if (c.peek() == 'n') c.advance(1); parseNumber(c); if (!c.accept("_")) return null
            if (c.peek() == 'n') c.advance(1); parseNumber(c); if (!c.accept("_")) return null
            return N("virt_thunk", parseEncoding(c) ?: return null)
        }
        if (two == "GV") { c.advance(2); return N("guard_variable", parseType(c) ?: return null) }
        if (c.raw.startsWith("GTt", c.pos)) { c.advance(3); return N("transaction_clone", parseEncoding(c) ?: return null) }
        return null
    }

    private fun parseMangledName(c: Cursor): Nd? {
        if (c.raw.startsWith("__Z", c.pos)) c.advance(1)
        if (!c.accept("_Z")) return null
        parseSpecial(c)?.let { return it }
        return parseEncoding(c)
    }

    private fun expandArgPacks(ast: Nd): Nd {
        lateinit var mapper: (Nd) -> Nd
        mapper = { node ->
            when {
                node is N && node.kind == "tpl_args" -> {
                    @Suppress("UNCHECKED_CAST") val args = node.value as List<Nd>
                    val exp = ArrayList<Nd>()
                    for (a in args) if (a is N && (a.kind == "tpl_arg_pack" || a.kind == "tpl_args")) {
                        @Suppress("UNCHECKED_CAST") val inner = a.value as List<Nd>; exp.addAll(inner)
                    } else exp.add(a)
                    N("tpl_args", exp.map(mapper))
                }
                node is Func -> {
                    val m = node.mapC(mapper) as Func
                    val exp = ArrayList<Nd>()
                    for (arg in m.argTys) {
                        if (arg is N && arg.kind == "expand_arg_pack") {
                            val w = arg.value
                            val inner = if (w is N && (w.kind == "pointer" || w.kind == "lvalue" || w.kind == "rvalue")) w.value else w
                            if (inner is N && (inner.kind == "tpl_arg_pack" || inner.kind == "tpl_args")) {
                                @Suppress("UNCHECKED_CAST") val l = inner.value as List<Nd>; exp.addAll(l); continue
                            }
                        }
                        exp.add(arg)
                    }
                    m.withArgs(exp)
                }
                else -> node.mapC(mapper)
            }
        }
        return mapper(ast)
    }
}
