package io.github.nitanmarcel.jdex.disasm

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test

class ElfDisasmTest {

    private fun hostLibBytes(): ByteArray? {
        val os = System.getProperty("os.name").lowercase()
        val arch = when (val a = System.getProperty("os.arch").lowercase()) {
            "amd64", "x86_64" -> "x86-64"; "aarch64", "arm64" -> "aarch64"; "arm" -> "arm"; else -> a
        }
        val dir = when { os.contains("win") -> "win32-$arch"; os.contains("mac") -> "darwin"; else -> "linux-$arch" }
        val lib = when { os.contains("win") -> "capstone.dll"; os.contains("mac") -> "libcapstone.dylib"; else -> "libcapstone.so" }
        return javaClass.getResourceAsStream("/$dir/$lib")?.readBytes()
    }

    @Test
    fun parsesAndDisassemblesHostLibrary() {
        val bytes = hostLibBytes()
        assumeTrue(bytes != null, "host libcapstone resource not present")
        val elf = ElfFile.parse(bytes!!)!!
        assertTrue(elf.is64)
        assertTrue(elf.functions.isNotEmpty(), "expected function symbols")
        val text = elf.textSections.first { it.name == ".text" }
        assertTrue(text.size > 0)
        val code = elf.sectionBytes(text).copyOf(minOf(8192, text.size.toInt()))
        val insns = CapstoneDisassembler.disassemble(code, text.addr, elf.arch)
        assertTrue(insns.size > 200, "expected many instructions, got ${insns.size}")
        assertEquals(text.addr, insns.first().address)
    }

    @Test
    fun ehFrameHdrRendersStructured() {
        val bytes = javaClass.getResourceAsStream("/jni/libjnitest_arm64-v8a.so")?.readBytes()
        assumeTrue(bytes != null, "arm64 fixture not present")
        val elf = ElfFile.parse(bytes!!)!!
        assumeTrue(elf.sections.any { it.name == ".eh_frame_hdr" && it.size > 4 }, "no .eh_frame_hdr")
        val src = NativeListing.build(elf, CapstoneDisassembler, elf.arch, elf.littleEndian, { _, _ -> }, { false })!!
        val all = (0 until src.lineCount).map { src.lines(it, 1).first() }; src.close()
        val hdrIdx = all.indexOfFirst { it.contains("; eh_frame_hdr") }
        assertTrue(hdrIdx >= 0, "eh_frame_hdr header line should be decoded")
        val window = all.subList(hdrIdx, minOf(hdrIdx + 40, all.size))
        assertTrue(window.any { it.contains("; fde_count") }, "fde_count should be labelled")
        assertTrue(window.any { it.contains("  unwind ") }, "table entries should render as unwind <fn>")
    }

    @Test
    fun resolvesPltImportNamesBothX86Abis() {
        for (n in listOf("libjnitest_x86.so", "libjnitest_x86_64.so")) {
            val bytes = javaClass.getResourceAsStream("/jni/$n")?.readBytes()
            assumeTrue(bytes != null, "$n fixture not present")
            val elf = ElfFile.parse(bytes!!)!!
            val plt = NativeListing.buildPltNames(elf, CapstoneDisassembler, elf.arch, elf.littleEndian)
            assertTrue(plt.isNotEmpty(), "$n: x86 PLT stubs should resolve to import names")
            assertTrue(plt.values.any { it in elf.relocs.values }, "$n: resolved names should be real dynamic imports")
        }
    }

    @Test
    fun dynamicNeededLibraries() {
        val bytes = javaClass.getResourceAsStream("/jni/libjnitest_arm64-v8a.so")?.readBytes()
        assumeTrue(bytes != null, "arm64 fixture not present")
        val elf = ElfFile.parse(bytes!!)!!
        val dyn = elf.dynamic()
        assertTrue(dyn.needed.isNotEmpty(), "expected DT_NEEDED libraries")
        assertTrue(dyn.needed.all { it.endsWith(".so") }, "needed entries should be soname-like: ${dyn.needed}")
    }

    @Test
    fun listingHeaderRendersAsComments() {
        val bytes = javaClass.getResourceAsStream("/jni/libjnitest_arm64-v8a.so")?.readBytes()
        assumeTrue(bytes != null, "arm64 fixture not present")
        val elf = ElfFile.parse(bytes!!)!!
        val src = NativeListing.build(elf, CapstoneDisassembler, elf.arch, elf.littleEndian, { _, _ -> }, { false }, listOf("File format : test"))!!
        val head = (0 until minOf(6, src.lineCount)).map { src.lines(it, 1).first() }; src.close()
        assertTrue(head.any { it.contains("; File format : test") }, "header should appear as comments at top:\n$head")
    }

    @Test
    fun noReturnCallEndsBlockWithoutFallthrough() {
        val listing = listOf(
            "00001000: ff4300d1 sub     sp, sp, #0x10",
            "00001004: 00000094 bl      __stack_chk_fail",
            "00001008: 00008052 mov     w0, #0",
            "0000100c: c0035fd6 ret",
        )
        val cfg = NativeCfg.fromListing("f", listing)!!
        val blockOf = { addr: Int -> cfg.blocks.indexOfLast { it.startOffset <= addr } }
        val noret = blockOf(0x1004)
        assertTrue(cfg.edges.none { it.from == noret }, "no-return call block must have no outgoing edge:\n${cfg.edges}")
    }

    @Test
    fun armBranchTargetsAreValidBoundaries() {
        val bytes = javaClass.getResourceAsStream("/jni/libjnitest_armeabi-v7a.so")?.readBytes()
        assumeTrue(bytes != null, "armeabi-v7a fixture not present")
        val elf = ElfFile.parse(bytes!!)!!
        assumeTrue(elf.arch == ElfArch.ARM, "need ARM")
        NativeFunctions.detectArmMode(elf, CapstoneDisassembler, elf.littleEndian)
        val src = NativeListing.build(elf, CapstoneDisassembler, elf.arch, elf.littleEndian, { _, _ -> }, { false })!!
        val all = (0 until src.lineCount).map { src.lines(it, 1).first() }; src.close()
        val starts = HashSet<Long>()
        for (l in all) { val t = l.trimStart(); if (t.length >= 9 && t[8] == ':') t.substring(0, 8).toLongOrNull(16)?.let { starts.add(it) } }
        var mid = 0
        for (l in all) { if (!l.contains(": ")) continue
            Regex("""\bloc_([0-9a-f]+)\b""").findAll(l).forEach { m -> m.groupValues[1].toLongOrNull(16)?.let { if (it !in starts) mid++ } } }
        assertEquals(0, mid, "no branch should reference a mid-instruction loc_")
    }

    @Test
    fun armFuncSymbolThumbBitsDriveModeMap() {
        val bytes = javaClass.getResourceAsStream("/jni/libjnitest_armeabi-v7a.so")?.readBytes()
        assumeTrue(bytes != null, "armeabi-v7a fixture not present")
        val elf = ElfFile.parse(bytes!!)!!
        assumeTrue(elf.arch == ElfArch.ARM && elf.functions.isNotEmpty(), "need ARM FUNC symbols")
        NativeFunctions.detectArmMode(elf, CapstoneDisassembler, elf.littleEndian)
        for (f in elf.functions) assertEquals(f.thumb, elf.armThumbAt(f.address), "mode at ${f.name}@${f.address.toString(16)}")
        val thumb = elf.functions.count { it.thumb }; val arm = elf.functions.count { !it.thumb }
        assertEquals(thumb > arm, elf.defaultThumb)
    }

    @Test
    fun disassemblesArm64() {
        val insns = CapstoneDisassembler.disassemble(byteArrayOf(0xC0.toByte(), 0x03, 0x5F, 0xD6.toByte()), 0x1000, ElfArch.ARM64)
        assertEquals("ret", insns.single().mnemonic)
    }

    @Test
    fun disassemblesX8664() {
        val insns = CapstoneDisassembler.disassemble(byteArrayOf(0x55, 0x48, 0x89.toByte(), 0xE5.toByte(), 0xC3.toByte()), 0x1000, ElfArch.X86_64)
        assertEquals("push", insns.first().mnemonic)
        assertEquals("ret", insns.last().mnemonic)
    }

    @Test
    fun disassemblesMips() {
        val insns = CapstoneDisassembler.disassemble(byteArrayOf(0x0C, 0x00, 0x00, 0x00), 0x1000, ElfArch.MIPS)
        assertEquals("syscall", insns.single().mnemonic)
    }

    @Test
    fun buildsIdaStyleListing() {
        val bytes = hostLibBytes()
        assumeTrue(bytes != null, "host libcapstone resource not present")
        val elf = ElfFile.parse(bytes!!)!!
        val src = NativeListing.build(elf, CapstoneDisassembler, elf.arch, elf.littleEndian, { _, _ -> }, { false })
        assertTrue(src != null && src.lineCount > 100, "expected a populated listing")
        val sample = (0 until minOf(src!!.lineCount, 800)).joinToString("\n") { src.lines(it, 1).first() }
        assertTrue(sample.contains(":"), "expected address/label lines")
        assertTrue(elf.functions.isEmpty() || src.sectionStart(elf.functions.first().name) != null, "function should be navigable")
        src.close()
    }

    private fun sleb128(v: Long): ByteArray {
        var value = v
        val out = ArrayList<Byte>()
        var more = true
        while (more) {
            var b = (value and 0x7F).toInt()
            value = value shr 7
            if ((value == 0L && b and 0x40 == 0) || (value == -1L && b and 0x40 != 0)) more = false
            else b = b or 0x80
            out.add(b.toByte())
        }
        return out.toByteArray()
    }

    @Test
    fun decodesAndroidPackedRelocations() {
        val info = (7L shl 32) or 0x401L
        val body = ArrayList<Byte>()
        body.addAll("APS2".toByteArray().toList())
        body.addAll(sleb128(3).toList())
        body.addAll(sleb128(0x1000).toList())
        body.addAll(sleb128(3).toList())
        body.addAll(sleb128(0b011).toList())
        body.addAll(sleb128(8).toList())
        body.addAll(sleb128(info).toList())
        val bytes = body.toByteArray()

        val offsets = ArrayList<Long>()
        val syms = ArrayList<Int>()
        val addends = ArrayList<Long>()
        ElfFile.parsePackedRelocs(bytes, 0, bytes.size, true) { off, sym, add -> offsets.add(off); syms.add(sym); addends.add(add) }
        assertEquals(listOf(0x1008L, 0x1010L, 0x1018L), offsets)
        assertEquals(listOf(7, 7, 7), syms)
        assertEquals(listOf(0L, 0L, 0L), addends)
    }

    @Test
    fun decodesRelr() {
        val bytes = ByteArray(16)
        val buf = java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        buf.putLong(0, 0x1000L); buf.putLong(8, 0xBL)
        val slots = ArrayList<Long>()
        ElfFile.parseRelr(bytes, 0, bytes.size, true) { slots.add(it) }
        assertEquals(listOf(0x1000L, 0x1008L, 0x1018L), slots)
    }

    @Test
    fun structuresIfElse() {
        val blocks = listOf(
            NativeStructurer.SBlock(0x10, listOf("x = 1"), NativeStructurer.Term.Cond("x == 0", 0x30)),
            NativeStructurer.SBlock(0x20, listOf("y = 2"), NativeStructurer.Term.Goto(0x40)),
            NativeStructurer.SBlock(0x30, listOf("y = 3"), NativeStructurer.Term.Fall),
            NativeStructurer.SBlock(0x40, listOf("z = y"), NativeStructurer.Term.Return),
        )
        val out = NativeStructurer.structure(blocks)
        assertTrue(out.contains("if (x == 0) {"), "expected structured if:\n$out")
        assertTrue(out.contains("} else {"), "expected else arm:\n$out")
        assertFalse(out.contains("goto"), "if/else should not need goto:\n$out")
        assertTrue(out.contains("return;"))
    }

    @Test
    fun structuresSelfLoop() {
        val blocks = listOf(
            NativeStructurer.SBlock(0x10, listOf("i = 0"), NativeStructurer.Term.Fall),
            NativeStructurer.SBlock(0x20, listOf("i += 1"), NativeStructurer.Term.Cond("i < 10", 0x20)),
            NativeStructurer.SBlock(0x30, emptyList(), NativeStructurer.Term.Return),
        )
        val out = NativeStructurer.structure(blocks)
        assertTrue(out.contains("while (true) {"), "back-edge should become a loop:\n$out")
        assertTrue(out.contains("if (i < 10) continue;"), "loop back-edge should be continue:\n$out")
        assertTrue(out.contains("break;"), "loop exit should be break:\n$out")
        assertFalse(out.contains("goto"), "structured loop should not need goto:\n$out")
    }

    @Test
    fun structuresInvertedIf() {
        val blocks = listOf(
            NativeStructurer.SBlock(0x10, listOf("x = a"), NativeStructurer.Term.Cond("a == 0", 0x30)),
            NativeStructurer.SBlock(0x20, listOf("body()"), NativeStructurer.Term.Fall),
            NativeStructurer.SBlock(0x30, listOf("z = x"), NativeStructurer.Term.Return),
        )
        val out = NativeStructurer.structure(blocks)
        assertTrue(out.contains("if (!(a == 0)) {"), "inverted-if should invert the condition:\n$out")
        assertTrue(out.contains("body()"), "body must be present:\n$out")
        assertFalse(out.contains("if (a == 0) {"), "should not emit an empty then:\n$out")
    }

    @Test
    fun irreducibleKeepsBothEdges() {
        val blocks = listOf(
            NativeStructurer.SBlock(0x10, emptyList(), NativeStructurer.Term.Cond("c0", 0x30)),
            NativeStructurer.SBlock(0x20, listOf("a()"), NativeStructurer.Term.Cond("ca", 0x40)),
            NativeStructurer.SBlock(0x30, listOf("b()"), NativeStructurer.Term.Goto(0x20)),
            NativeStructurer.SBlock(0x40, emptyList(), NativeStructurer.Term.Return),
        )
        val out = NativeStructurer.structure(blocks)
        val labels = Regex("""(?m)^\s*(loc_[0-9a-f]+):""").findAll(out).map { it.groupValues[1] }.toSet()
        Regex("""goto (loc_[0-9a-f]+);""").findAll(out).forEach {
            assertTrue(it.groupValues[1] in labels, "dangling ${it.value}:\n$out")
        }
        assertTrue(out.contains("ca"), "the ca-conditional edge must be represented:\n$out")
    }

    @Test
    fun structuresWhileLoopWithBody() {
        val blocks = listOf(
            NativeStructurer.SBlock(0x10, listOf("n = 0"), NativeStructurer.Term.Fall),
            NativeStructurer.SBlock(0x20, listOf("t = n < 10"), NativeStructurer.Term.Cond("n < 10", 0x30)),
            NativeStructurer.SBlock(0x40, listOf("done()"), NativeStructurer.Term.Return),
            NativeStructurer.SBlock(0x30, listOf("n += 1"), NativeStructurer.Term.Goto(0x20)),
        )
        val out = NativeStructurer.structure(blocks)
        assertTrue(out.contains("while (true) {"), "expected a loop:\n$out")
        assertTrue(out.contains("continue;"), "body back-edge should be continue:\n$out")
        assertTrue(out.contains("break;") || out.contains("goto loc_40"), "exit should break/goto follow:\n$out")
        assertTrue(out.contains("n += 1"), "loop body should be present:\n$out")
    }

    @Test
    fun pseudoCStructuresArm64() {
        val listing = listOf(
            "00001000: 080040b9 ldr     w8, [x0]",
            "00001004: 1f0501f1 cmp     x8, #0x41",
            "00001008: 61000054 b.ne    loc_1014",
            "0000100c: 000080d2 mov     x0, #0",
            "00001010: c0035fd6 ret",
            "loc_1014:",
            "00001014: 200080d2 mov     x0, #1",
            "00001018: c0035fd6 ret",
        )
        val out = NativePseudo.forFunction("sub_1000", listing)
        assertTrue(out.contains("if (x8 != 0x41)"), "expected condition from cmp:\n$out")
        assertTrue(out.contains("return"), "expected returns:\n$out")
    }

    @Test
    fun pseudoCFoldsShiftedOperandAndMovn() {
        val listing = listOf(
            "00001000: 00000000 movn    x3, #0",
            "00001004: 00000000 add     x0, x1, x2, lsl #3",
            "00001008: c0035fd6 ret",
        )
        val out = NativePseudo.forFunction("sub_1000", listing)
        assertTrue(out.contains("x3 = ~0"), "movn should be bitwise-not:\n$out")
        assertTrue(out.contains("x0 = x1 + (x2 << 3)"), "shifted operand must not be dropped:\n$out")
    }

    @Test
    fun pseudoCStopsAtNoReturnCall() {
        val listing = listOf(
            "00001000: 00000094 bl      __stack_chk_fail",
            "00001004: 1f2003d5 nop",
            "00001008: c0035fd6 ret",
        )
        val out = NativePseudo.forFunction("sub_1000", listing)
        assertTrue(out.contains("__stack_chk_fail("), "call should be emitted:\n$out")
        assertTrue(Regex("""__stack_chk_fail\(\);\s*\n\s*return;""").containsMatchIn(out), "no-return call must terminate the block (no fall-through):\n$out")
    }

    @Test
    fun pseudoCDetectsArm32AndReturns() {
        val listing = listOf(
            "00001000: 000051e3 cmp     r0, #0",
            "00001004: 0100000a beq     loc_1018",
            "00001008: 003090e5 ldr     r3, [r0]",
            "0000100c: 030081e0 add     r0, r1, r3",
            "00001010: 1eff2fe1 bx      lr",
            "loc_1018:",
            "00001018: 0000a0e3 mov     r0, #0",
            "0000101c: 1eff2fe1 bx      lr",
        )
        val out = NativePseudo.forFunction("sub_1000", listing)
        assertTrue(out.contains("r3 = *r0"), "ARM32 ldr should deref (not be x86-misdetected):\n$out")
        assertTrue(out.contains("if (r0 == 0)"), "expected condition:\n$out")
        assertTrue(out.contains("return"), "bx lr should be a return:\n$out")
        assertFalse(out.contains("goto *lr"), "bx lr should not be an indirect goto:\n$out")
        assertFalse(out.contains("ldr "), "ldr should be translated:\n$out")
    }

    @Test
    fun pseudoCSubsComparesOperands() {
        val listing = listOf(
            "00001000: 021051e0 subs    r1, r1, r2",
            "00001004: 0200008a bhi     loc_1010",
            "00001008: 0000a0e3 mov     r0, #0",
            "0000100c: 1eff2fe1 bx      lr",
            "loc_1010:",
            "00001010: 0100a0e3 mov     r0, #1",
            "00001014: 1eff2fe1 bx      lr",
        )
        val out = NativePseudo.forFunction("sub_1000", listing)
        assertTrue(out.contains("r1 = r1 - r2"), "subs should still compute:\n$out")
        assertTrue(out.contains("(unsigned)r1 > (unsigned)r2"), "subs+bhi should compare operands unsigned:\n$out")
    }

    @Test
    fun pseudoCTranslatesVfpScalarArith() {
        val listing = listOf(
            "00001000: 200a30ee vadd.f32 s0, s0, s1",
            "00001004: 010b20ee vmul.f64 d0, d0, d1",
            "00001008: 600a30ee vsub.f32 s0, s0, s1",
            "0000100c: 010b80ee vdiv.f64 d0, d0, d1",
            "00001010: 400ab1ee vneg.f32 s0, s0",
            "00001014: c00bb0ee vabs.f64 d0, d0",
            "00001018: c00ab1ee vsqrt.f32 s0, s0",
            "0000101c: 1eff2fe1 bx      lr",
        )
        val out = NativePseudo.forFunction("sub_1000", listing)
        assertTrue(out.contains("s0 = s0 + s1"), "vadd.f32:\n$out")
        assertTrue(out.contains("d0 = d0 * d1"), "vmul.f64:\n$out")
        assertTrue(out.contains("s0 = s0 - s1"), "vsub.f32:\n$out")
        assertTrue(out.contains("d0 = d0 / d1"), "vdiv.f64:\n$out")
        assertTrue(out.contains("s0 = -s0"), "vneg:\n$out")
        assertTrue(out.contains("d0 = fabs(d0)"), "vabs:\n$out")
        assertTrue(out.contains("s0 = sqrt(s0)"), "vsqrt:\n$out")
        assertFalse(out.contains("vadd") || out.contains("vsqrt"), "vfp should not be raw:\n$out")
    }

    @Test
    fun pseudoCTranslatesVfpConvLoadStoreMla() {
        val listing = listOf(
            "00001000: c07afdee vcvt.s32.f32 s15, s0",
            "00001004: c00ab8ee vcvt.f32.s32 s0, s0",
            "00001008: c00bb8ee vcvt.f64.s32 d0, s0",
            "0000100c: 000a90ed vldr    s0, [r0]",
            "00001010: 000a81ed vstr    s0, [r1]",
            "00001014: 201a00ee vmla.f32 s2, s0, s1",
            "00001018: 601a00ee vmls.f32 s2, s0, s1",
            "0000101c: 410ab0ee vmov.f32 s0, s2",
            "00001020: 1eff2fe1 bx      lr",
        )
        val out = NativePseudo.forFunction("sub_1000", listing)
        assertTrue(out.contains("s15 = (int32_t)s0"), "vcvt to int:\n$out")
        assertTrue(out.contains("s0 = (float)s0"), "vcvt to float:\n$out")
        assertTrue(out.contains("d0 = (double)s0"), "vcvt to double:\n$out")
        assertTrue(out.contains("s0 = *r0"), "vldr:\n$out")
        assertTrue(out.contains("*r1 = s0"), "vstr:\n$out")
        assertTrue(out.contains("s2 += s0 * s1"), "vmla:\n$out")
        assertTrue(out.contains("s2 -= s0 * s1"), "vmls:\n$out")
        assertTrue(out.contains("s0 = s2"), "vmov.f32:\n$out")
        assertFalse(out.contains("vcvt") || out.contains("vldr") || out.contains("vmla"), "vfp raw:\n$out")
    }

    @Test
    fun pseudoCVfpCompareDrivesCondition() {
        val listing = listOf(
            "00001000: e00ab4ee vcmpe.f32 s0, s1",
            "00001004: 10faf1ee vmrs    apsr_nzcv, fpscr",
            "00001008: 0100a0c3 movgt   r0, #1",
            "0000100c: 0000a0d3 movle   r0, #0",
            "00001010: 1eff2fe1 bx      lr",
        )
        val out = NativePseudo.forFunction("sub_1000", listing)
        assertTrue(out.contains("if (s0 > s1) r0 = 1"), "vcmp+movgt should compare operands:\n$out")
        assertTrue(out.contains("if (s0 <= s1) r0 = 0"), "vcmp+movle:\n$out")
        assertFalse(out.contains("vmrs") || out.contains("vcmp"), "vcmp/vmrs should not be raw:\n$out")
    }

    @Test
    fun pseudoCTranslatesDspAndPrefetch() {
        val listing = listOf(
            "00001000: 910f50e6 uadd8   r0, r0, r1",
            "00001004: 500001e1 qadd    r0, r0, r1",
            "00001008: 500021e1 qsub    r0, r0, r1",
            "0000100c: 00f0d0f5 pld     [r0]",
            "00001010: 1eff2fe1 bx      lr",
        )
        val out = NativePseudo.forFunction("sub_1000", listing)
        assertTrue(out.contains("r0 = __uadd8(r0, r1)"), "uadd8:\n$out")
        assertTrue(out.contains("r0 = __qadd(r0, r1)"), "qadd:\n$out")
        assertTrue(out.contains("r0 = __qsub(r0, r1)"), "qsub:\n$out")
        assertFalse(out.contains("pld ") || out.contains("pld[") || out.contains("    uadd8"), "dsp/pld raw:\n$out")
    }

    @Test
    fun pseudoCTranslatesLdmStmMultiReg() {
        val listing = listOf(
            "00001000: 0f0091e8 ldm     r1, {r0, r1, r2, r3}",
            "00001004: 0f008ce8 stm     ip, {r0, r1, r2, r3}",
            "00001008: 1eff2fe1 bx      lr",
        )
        val out = NativePseudo.forFunction("sub_1000", listing)
        assertTrue(out.contains("r0 = *r1"), "ldm first:\n$out")
        assertTrue(out.contains("r2 = *(r1 + 8)"), "ldm third with offset:\n$out")
        assertTrue(out.contains("r3 = *(r1 + 12)"), "ldm fourth:\n$out")
        assertTrue(out.contains("*ip = r0"), "stm first:\n$out")
        assertTrue(out.contains("*(ip + 12) = r3"), "stm fourth:\n$out")
        assertFalse(out.contains("ldm ") || out.contains("stm "), "ldm/stm raw:\n$out")
    }

    @Test
    fun pseudoCLdmDbWritebackOffsets() {
        val listing = listOf(
            "00001000: 0f002de9 stmdb   sp!, {r0, r1, r2, r3}",
            "00001004: 1eff2fe1 bx      lr",
        )
        val out = NativePseudo.forFunction("sub_1000", listing)
        assertTrue(out.contains("*(sp - 16) = r0"), "stmdb lowest reg lowest addr:\n$out")
        assertTrue(out.contains("*(sp - 4) = r3"), "stmdb highest reg:\n$out")
        assertTrue(out.contains("sp -= 16"), "writeback decrement:\n$out")
    }

    private fun section(name: String, addr: Long, size: Long, exec: Boolean) =
        ElfSection(name, 1, if (exec) 6L else 2L, addr, addr, size, 0)

    private fun elfWith(arch: ElfArch, sections: List<ElfSection>, bytes: ByteArray) =
        ElfFile(arch, true, true, 0, sections, emptyList(), emptyMap(), LongArray(0), IntArray(0), 0L, emptyMap(), bytes)

    private fun insn(addr: Long, mnem: String, ops: String) = Insn(addr, 4, ByteArray(4), mnem, ops)

    @Test
    fun resolvesArm64JumpTable() {
        val bytes = ByteArray(0x2010)
        val buf = java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        buf.putInt(0x2000, (0x1100 - 0x2000)); buf.putInt(0x2004, (0x1200 - 0x2000)); buf.putInt(0x2008, (0x1300 - 0x2000))
        val elf = elfWith(ElfArch.ARM64, listOf(section(".text", 0x1000, 0x1000, true), section(".rodata", 0x2000, 0x100, false)), bytes)
        val insns = listOf(
            insn(0x1000, "adrp", "x8, 0x2000"),
            insn(0x1004, "add", "x8, x8, #0"),
            insn(0x1008, "cmp", "w0, #2"),
            insn(0x100c, "ldrsw", "x9, [x8, x0, lsl #2]"),
            insn(0x1010, "add", "x8, x8, x9"),
            insn(0x1014, "br", "x8"),
        )
        val res = NativeJumpTable.resolve(insns, 5, elf, ElfArch.ARM64)
        assertTrue(res != null, "expected a resolved table")
        assertEquals(listOf(0x1100L, 0x1200L, 0x1300L), res!!.targets)
        assertEquals("x0", res.indexReg)
    }

    @Test
    fun resolvesArm64ByteTable() {
        val bytes = ByteArray(0xa50)
        bytes[0xa3c] = 4; bytes[0xa3d] = 8; bytes[0xa3e] = 0xc; bytes[0xa3f] = 0x10
        val elf = elfWith(ElfArch.ARM64, listOf(section(".text", 0x100, 0x400, true), section(".rodata", 0xa3c, 0x14, false)), bytes)
        val insns = listOf(
            insn(0x10, "cmp", "w0, #3"),
            insn(0x14, "adrp", "x1, #0"),
            insn(0x18, "add", "x1, x1, #0xa3c"),
            insn(0x1c, "ldrb", "w1, [x1, w0, uxtw]"),
            insn(0x20, "adr", "x0, #0x100"),
            insn(0x24, "add", "x1, x0, w1, sxtb #2"),
            insn(0x28, "br", "x1"),
        )
        val res = NativeJumpTable.resolve(insns, 6, elf, ElfArch.ARM64)
        assertTrue(res != null, "expected a resolved byte table")
        assertEquals(listOf(0x110L, 0x120L, 0x130L, 0x140L), res!!.targets)
    }

    @Test
    fun resolvesX86AbsoluteJumpTable() {
        val bytes = ByteArray(0x2020)
        val buf = java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        buf.putLong(0x2000, 0x1100); buf.putLong(0x2008, 0x1200); buf.putLong(0x2010, 0x1300)
        val elf = elfWith(ElfArch.X86_64, listOf(section(".text", 0x1000, 0x1000, true), section(".rodata", 0x2000, 0x100, false)), bytes)
        val insns = listOf(
            Insn(0xffa, 3, ByteArray(3), "cmp", "eax, 2"),
            Insn(0x1000, 7, ByteArray(7), "lea", "rdx, [rip + 0xff9]"),
            Insn(0x1007, 7, ByteArray(7), "jmp", "qword ptr [rdx + rax*8]"),
        )
        val res = NativeJumpTable.resolve(insns, 2, elf, ElfArch.X86_64)
        assertTrue(res != null, "expected a resolved table")
        assertEquals(listOf(0x1100L, 0x1200L, 0x1300L), res!!.targets)
    }

    @Test
    fun jaeGuardGivesExclusiveCaseCount() {
        val bytes = ByteArray(0x2020)
        val buf = java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        buf.putLong(0x2000, 0x1100); buf.putLong(0x2008, 0x1200); buf.putLong(0x2010, 0x1300) // 0x2018 stays 0 (invalid)
        val elf = elfWith(ElfArch.X86_64, listOf(section(".text", 0x1000, 0x1000, true), section(".rodata", 0x2000, 0x100, false)), bytes)
        val insns = listOf(
            Insn(0xfe8, 3, ByteArray(3), "cmp", "edi, 3"),
            Insn(0xfeb, 2, ByteArray(2), "jae", "0x2000"),
            Insn(0xff3, 2, ByteArray(2), "mov", "eax, edi"),
            Insn(0xff5, 7, ByteArray(7), "jmp", "qword ptr [rax*8 + 0x2000]"),
        )
        val res = NativeJumpTable.resolve(insns, 3, elf, ElfArch.X86_64)
        assertTrue(res != null && res.targets == listOf(0x1100L, 0x1200L, 0x1300L), "jae guard => 3 cases (0..N-1), not N+1:\n${res?.targets}")
    }

    @Test
    fun pseudoCTranslatesX86Sse() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 pxor    xmm3, xmm3",
            "00005004: 00 cvtsi2sd xmm3, edi",
            "00005008: 00 addsd   xmm3, xmm0",
            "0000500c: 00 mulsd   xmm3, xmm1",
            "00005010: 00 movapd  xmm0, xmm3",
            "00005014: 00 ret",
        ))
        assertTrue(out.contains("xmm3 = 0"), "pxor self => 0:\n$out")
        assertTrue(out.contains("xmm3 = (double)edi"), "cvtsi2sd => cast:\n$out")
        assertTrue(out.contains("xmm3 += xmm0"), "addsd => +=:\n$out")
        assertTrue(out.contains("xmm3 *= xmm1"), "mulsd => *=:\n$out")
        assertTrue(!out.contains("void f("), "xmm0 write => non-void:\n$out")
    }

    @Test
    fun pseudoCRendersPackedSseAsVector() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 addps   xmm0, xmm1",
            "00005004: 00 mulpd   xmm2, xmm3",
            "00005008: 00 ret",
        ))
        assertTrue(out.contains("xmm0 = vadd(xmm0, xmm1)"), "addps => vadd:\n$out")
        assertTrue(out.contains("xmm2 = vmul(xmm2, xmm3)"), "mulpd => vmul:\n$out")
        assertTrue(!out.contains("xmm0 += xmm1"), "packed must not render as scalar:\n$out")
    }

    @Test
    fun pseudoCArm64CarryConditions() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 cmp     x0, x1",
            "00001004: 00000000 csetm   x2, cc",
            "00001008: 00000000 cmp     x0, x1",
            "0000100c: 00000000 b.cs    loc_1014",
            "00001010: 00000000 ret",
            "loc_1014:",
            "00001014: 00000000 ret",
        ))
        assertTrue(out.contains("(unsigned)x0 < (unsigned)x1"), "cc => unsigned <:\n$out")
        assertTrue(out.contains("(unsigned)x0 >= (unsigned)x1"), "b.cs => unsigned >=:\n$out")
        assertTrue(out.contains("? -1 : 0"), "csetm => all-ones mask:\n$out")
        assertTrue(!out.contains("cond_cs") && !out.contains("cond_cc"), "no opaque cond_ placeholders:\n$out")
    }

    @Test
    fun pseudoCFoldsShiftedCompareOperand() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 cmp     w0, w1, lsl #2",
            "00001004: 00000000 b.lt    loc_1010",
            "00001008: 00000000 mov     x0, #0",
            "0000100c: 00000000 ret",
            "loc_1010:",
            "00001010: 00000000 neg     x2, x3, lsl #4",
            "00001014: 00000000 ret",
        ))
        assertTrue(out.contains("w0 < (w1 << 2)"), "cmp with shifted operand must keep shift:\n$out")
        assertTrue(out.contains("x2 = -(x3 << 4)"), "neg with shifted operand must keep shift:\n$out")
    }

    @Test
    fun dataStringTableRealignsAfterPadding() {
        val s1 = "AAAA_first_string"; val s2 = "BBBB_second_string"
        val bytes = ByteArray(0x1100)
        var o = 0x1000
        for (c in s1) bytes[o++] = c.code.toByte(); bytes[o++] = 0
        o = 0x1018
        for (c in s2) bytes[o++] = c.code.toByte(); bytes[o++] = 0
        val elf = elfWith(ElfArch.ARM64, listOf(section(".rodata", 0x1000, 0x100, false)), bytes)
        val src = NativeListing.build(elf, CapstoneDisassembler, elf.arch, elf.littleEndian, { _, _ -> }, { false })!!
        val all = (0 until src.lineCount).map { src.lines(it, 1).first() }; src.close()
        assertTrue(all.any { it.contains("\"$s1\"") }, "first string should render:\n$all")
        assertTrue(all.any { it.contains("\"$s2\"") }, "second string must render fully after padding, not mid-string:\n$all")
    }

    @Test
    fun pseudoCMipsSubWordLoadsAndSignExtend() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 lb      \$v0, 0(\$a0)",
            "00001004: 00000000 lbu     \$v1, 0(\$a1)",
            "00001008: 00000000 seb     \$t0, \$a2",
            "0000100c: 00000000 jr      \$ra",
            "00001010: 00000000 nop",
        ))
        assertTrue(out.contains("\$v0 = (int8_t)"), "lb must sign-extend:\n$out")
        assertTrue(out.contains("\$v1 = (uint8_t)"), "lbu must zero-extend:\n$out")
        assertTrue(out.contains("\$t0 = (int8_t)\$a2"), "seb must sign-extend:\n$out")
    }

    @Test
    fun pseudoCArm32LongMultiply() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 umull   r0, r1, r2, r3",
            "00001004: 00000000 umlal   r4, r5, r6, r7",
            "00001008: 00000000 bx      lr",
        ))
        assertTrue(out.contains("r0, r1 = r2 * r3"), "umull writes the 64-bit dest pair from both factors:\n$out")
        assertTrue(out.contains("r4, r5 += r6 * r7"), "umlal accumulates into the dest pair:\n$out")
    }

    @Test
    fun pseudoCArm32ExtendAndAdd() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 sxtab   r0, r1, r2",
            "00001004: 00000000 uxtab   r0, r1, r2",
            "00001008: 00000000 sxtah   r0, r1, r2",
            "0000100c: 00000000 uxtah   r0, r1, r2",
            "00001010: 00000000 revsh   r3, r4",
            "00001014: 00000000 bx      lr",
        ))
        assertTrue(out.contains("r0 = r1 + (int8_t)r2"), "sxtab sign-extends byte then adds:\n$out")
        assertTrue(out.contains("r0 = r1 + (uint8_t)r2"), "uxtab zero-extends byte then adds:\n$out")
        assertTrue(out.contains("r0 = r1 + (int16_t)r2"), "sxtah sign-extends halfword then adds:\n$out")
        assertTrue(out.contains("r0 = r1 + (uint16_t)r2"), "uxtah zero-extends halfword then adds:\n$out")
        assertTrue(out.contains("r3 = (int16_t)rev16(r4)"), "revsh reverses low halfword and sign-extends:\n$out")
        assertFalse(out.contains("sxtab ") || out.contains("revsh "), "must not pass through untranslated:\n$out")
    }

    @Test
    fun pseudoCArm32VmovCoreFpTransfers() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 vmov    r0, s15",
            "00001004: 00000000 vmov    s0, r2",
            "00001008: 00000000 vmov    r4, r5, d3",
            "0000100c: 00000000 vmov    d6, r7, r8",
            "00001010: 00000000 bx      lr",
        ))
        assertTrue(out.contains("r0 = s15"), "vmov FP->core is a plain move:\n$out")
        assertTrue(out.contains("s0 = r2"), "vmov core->FP is a plain move:\n$out")
        assertTrue(out.contains("r4, r5 = d3"), "vmov to two cores splits the double:\n$out")
        assertTrue(out.contains("d6 = r7, r8"), "vmov from two cores fills the double:\n$out")
        assertFalse(out.contains("vmov "), "vmov must not pass through untranslated:\n$out")
    }

    @Test
    fun pseudoCX86DestructiveSubCondition() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 sub     eax, ebp",
            "00001004: 00000000 jne     loc_1010",
            "00001008: 00000000 mov     eax, 0",
            "0000100c: 00000000 ret",
            "loc_1010:",
            "00001010: 00000000 ret",
        ))
        assertTrue(out.contains("eax -= ebp"), "destructive sub still computes the result:\n$out")
        assertTrue(out.contains("eax != 0"), "flag test must compare the result to 0:\n$out")
        assertFalse(out.contains("eax != ebp"), "must not compare the already-mutated dest to the operand:\n$out")
    }

    @Test
    fun pseudoCMapsLinesToInstructionAddresses() {
        val pc = NativePseudo.forFunctionMapped("f", listOf(
            "00001000: 00000000 mov     x0, #5",
            "00001004: 00000000 add     x0, x0, #1",
            "00001008: 00000000 ret",
        ))
        val lines = pc.text.split("\n")
        val movLine = lines.indexOfFirst { it.contains("x0 = 5") }
        val addLine = lines.indexOfFirst { it.contains("x0 = x0 + 1") }
        assertTrue(movLine >= 0 && addLine >= 0, "expected statements:\n${pc.text}")
        assertEquals(0x1000L, pc.lineAddrs[movLine], "mov line maps to its instruction:\n${pc.text}")
        assertEquals(0x1004L, pc.lineAddrs[addLine], "add line maps to its instruction:\n${pc.text}")
        assertEquals(-1L, pc.lineAddrs[0], "header line has no address")
    }

    @Test
    fun pseudoCMipsMtc1Direction() {
        val out = NativePseudo.forFunction("i2f", listOf(
            "00001000: 00000000 mtc1    \$a0, \$f0",
            "00001004: 00000000 jr      \$ra",
            "00001008: 00000000 nop",
        ))
        assertTrue(out.contains("\$f0 = \$a0"), "mtc1 moves the GPR into the FP register:\n$out")
        assertFalse(out.contains("\$a0 = \$f0"), "mtc1 direction must not be reversed:\n$out")
    }

    @Test
    fun pseudoCMipsFpConditionalMove() {
        val out = NativePseudo.forFunction("fsel", listOf(
            "00001000: 00000000 c.olt.s  \$f12, \$f14",
            "00001004: 00000000 movt.s   \$f0, \$f2, \$fcc0",
            "00001008: 00000000 movf.d   \$f4, \$f6, \$fcc0",
            "0000100c: 00000000 jr       \$ra",
            "00001010: 00000000 nop",
        ))
        assertTrue(out.contains("if (fp_cond) \$f0 = \$f2"), "movt.s must move on true FP condition:\n$out")
        assertTrue(out.contains("if (!fp_cond) \$f4 = \$f6"), "movf.d must move on false FP condition:\n$out")
        assertFalse(out.contains("movt.s") || out.contains("movf.d"), "FP conditional moves must not pass through raw:\n$out")
    }

    @Test
    fun pseudoCX86BitTest() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 bt      eax, ecx",
            "00001004: 00000000 setb    dl",
            "00001008: 00000000 bts     esi, edi",
            "0000100c: 00000000 ret",
        ))
        assertTrue(out.contains("(eax >> ecx) & 1"), "bt+setb must test the actual bit, not a stale compare:\n$out")
        assertTrue(out.contains("esi |= (1 << edi)"), "bts is a read-modify-write set:\n$out")
    }

    @Test
    fun pseudoCArm32ExclusiveStore() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 strex   ip, r2, [r3]",
            "00001004: 00000000 ldrexd  r4, r5, [r6]",
            "00001008: 00000000 bx      lr",
        ))
        assertTrue(out.contains("ip = __strex(*r3, r2)"), "strex stores Rt to memory with status in Rd:\n$out")
        assertTrue(out.contains("r4, r5 = *r6"), "ldrexd loads the register pair from memory:\n$out")
    }

    @Test
    fun pseudoCMipsDivUsesBothOperands() {
        val out = NativePseudo.forFunction("sd", listOf(
            "00001000: 00000000 div     \$zero, \$a0, \$a1",
            "00001004: 00000000 mflo    \$v0",
            "00001008: 00000000 jr      \$ra",
            "0000100c: 00000000 nop",
        ))
        assertTrue(out.contains("\$a0 / \$a1"), "MIPS div must use dividend/divisor, not the zero placeholder:\n$out")
        assertFalse(out.contains("\$zero / \$a0"), "must not divide using the zero placeholder:\n$out")
    }

    @Test
    fun pseudoCArm32LdrdStrd() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 strd    r2, r3, [r0]",
            "00001004: 00000000 ldrd    r4, r5, [r1]",
            "00001008: 00000000 bx      lr",
        ))
        assertTrue(out.contains("*r0 = r2, r3"), "strd must store the register pair to memory:\n$out")
        assertTrue(out.contains("r4, r5 = *r1"), "ldrd must load the register pair from memory:\n$out")
    }

    @Test
    fun pseudoCArm32ReverseSubCarry() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 rsc     r1, r3, r5",
            "00001004: 00000000 rsc     r2, r2",
            "00001008: 00000000 bx      lr",
        ))
        assertTrue(out.contains("r1 = r5 - r3 - carry"), "3-op rsc reverses operands:\n$out")
        assertTrue(out.contains("r2 = r2 - r2 - carry"), "2-op rsc:\n$out")
        assertFalse(out.contains("rsc "), "no raw passthrough:\n$out")
    }

    @Test
    fun pseudoCMipsCondBranchAndLink() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 bgezal  \$a0, loc_1100",
            "00001004: 00000000 nop",
            "00001008: 00000000 bltzal  \$a1, loc_1200",
            "0000100c: 00000000 nop",
            "00001010: 00000000 jr      \$ra",
            "00001014: 00000000 nop",
        ))
        assertTrue(out.contains("if (\$a0 >= 0)") && out.contains("loc_1100()"), "bgezal is a conditional call:\n$out")
        assertTrue(out.contains("if (\$a1 < 0)") && out.contains("loc_1200()"), "bltzal is a conditional call:\n$out")
    }

    @Test
    fun pseudoCMipsImmediateTraps() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 05008c04 teqi    \$a0, 5",
            "00001004: 0700ae04 tnei    \$a1, 7",
            "00001008: 0300c804 tgei    \$a2, 3",
            "0000100c: 0900ea04 tlti    \$a3, 9",
            "00001010: 04000905 tgeiu   \$t0, 4",
            "00001014: 06002b05 tltiu   \$t1, 6",
            "00001018: 0800e003 jr      \$ra",
            "0000101c: 00000000 nop",
        ))
        assertTrue(out.contains("if (\$a0 == 5) __trap()"), "teqi:\n$out")
        assertTrue(out.contains("if (\$a1 != 7) __trap()"), "tnei:\n$out")
        assertTrue(out.contains("if (\$a2 >= 3) __trap()"), "tgei:\n$out")
        assertTrue(out.contains("if (\$a3 < 9) __trap()"), "tlti:\n$out")
        assertTrue(out.contains("if ((unsigned)\$t0 >= (unsigned)4) __trap()"), "tgeiu:\n$out")
        assertTrue(out.contains("if ((unsigned)\$t1 < (unsigned)6) __trap()"), "tltiu:\n$out")
        assertFalse(Regex("(?m)^\\s*(teqi|tnei|tgei|tlti|tgeiu|tltiu)\\b").containsMatchIn(out), "no raw trap passthrough:\n$out")
    }

    @Test
    fun pseudoCMipsCop2LoadStore() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 000081c8 lwc2    \$1, (\$a0)",
            "00001004: 0400a1e8 swc2    \$1, 4(\$a1)",
            "00001008: 0800e003 jr      \$ra",
            "0000100c: 00000000 nop",
        ))
        assertTrue(out.contains("\$1 = *\$a0"), "lwc2 loads from memory:\n$out")
        assertTrue(out.contains("*(\$a1 + 4) = \$1"), "swc2 stores to memory:\n$out")
        assertFalse(Regex("(?m)^\\s*(lwc2|swc2)\\b").containsMatchIn(out), "no raw cop2 passthrough:\n$out")
    }

    @Test
    fun pseudoCMipsFpControlRegs() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00f84444 cfc1    \$a0, \$31",
            "00001004: 00f8c544 ctc1    \$a1, \$31",
            "00001008: 0800e003 jr      \$ra",
            "0000100c: 00000000 nop",
        ))
        assertTrue(out.contains("\$a0 = fcr(\$31)"), "cfc1 reads FP control reg:\n$out")
        assertTrue(out.contains("fcr(\$31) = \$a1"), "ctc1 writes FP control reg:\n$out")
        assertFalse(Regex("(?m)^\\s*(cfc1|ctc1)\\b").containsMatchIn(out), "no raw FP control passthrough:\n$out")
    }

    @Test
    fun pseudoCMipsFpBranchLikely() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 05000345 bc1tl   loc_1018",
            "00001004: 00000000 nop",
            "00001008: 06000245 bc1fl   loc_1024",
            "0000100c: 00000000 nop",
            "00001010: 0800e003 jr      \$ra",
            "00001014: 00000000 nop",
            "00001018: 00000000 nop",
            "0000101c: 00000000 nop",
            "00001020: 00000000 nop",
            "00001024: 00000000 nop",
        ))
        assertTrue(out.contains("if (fp_cond)"), "bc1tl is a branch on fp_cond:\n$out")
        assertTrue(out.contains("if (!fp_cond)"), "bc1fl is a branch on !fp_cond:\n$out")
        assertFalse(Regex("(?m)^\\s*(bc1tl|bc1fl)\\b").containsMatchIn(out), "no raw FP branch-likely passthrough:\n$out")
    }

    @Test
    fun pseudoCMipsSynciAndCp0() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00009f04 synci   (\$a0)",
            "00001004: 00600440 mfc0    \$a0, \$t4, 0",
            "00001008: 00608540 mtc0    \$a1, \$t4, 0",
            "0000100c: 0800e003 jr      \$ra",
            "00001010: 00000000 nop",
        ))
        assertTrue(out.contains("\$a0 = cp0(\$t4)"), "mfc0 reads CP0:\n$out")
        assertTrue(out.contains("cp0(\$t4) = \$a1"), "mtc0 writes CP0:\n$out")
        assertFalse(Regex("(?m)^\\s*(synci|mfc0|mtc0)\\b").containsMatchIn(out), "no raw synci/CP0 passthrough:\n$out")
    }

    @Test
    fun pseudoCMipsRdhwrAndEhb() {
        val rdhwr = CapstoneDisassembler.disassemble(byteArrayOf(0x3b, 0xe8.toByte(), 0x03, 0x7c), 0x1000, ElfArch.MIPS)
        assertEquals("rdhwr", rdhwr.singleOrNull()?.mnemonic, "rdhwr must decode via bundled capstone")
        val ehb = CapstoneDisassembler.disassemble(byteArrayOf(0xc0.toByte(), 0x00, 0x00, 0x00), 0x1000, ElfArch.MIPS)
        assertEquals("ehb", ehb.singleOrNull()?.mnemonic, "ehb must decode via bundled capstone")
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 3be8037c rdhwr   \$v1, \$29",
            "00001004: c0000000 ehb",
            "00001008: 0800e003 jr      \$ra",
            "0000100c: 00000000 nop",
        ))
        assertTrue(out.contains("\$v1 = hwr(\$29)"), "rdhwr must read a hardware register:\n$out")
        assertFalse(Regex("(?m)^\\s*(rdhwr|ehb)\\b").containsMatchIn(out), "no raw rdhwr/ehb passthrough:\n$out")
    }

    @Test
    fun pseudoCX86BmiOps() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00 andn    eax, ebx, ecx",
            "00001004: 00 blsr    edx, esi",
            "00001008: 00 mulx    eax, ecx, esi",
            "0000100c: 00 movbe   edi, dword ptr [rbp]",
            "00001010: 00 ret",
        ))
        assertTrue(out.contains("eax = ~ebx & ecx"), "andn:\n$out")
        assertTrue(out.contains("edx = esi & (esi - 1)"), "blsr:\n$out")
        assertTrue(out.contains("edx * esi"), "mulx high/low product:\n$out")
        assertTrue(out.contains("edi = bswap("), "movbe byte-swap load:\n$out")
    }

    @Test
    fun pseudoCX86ByteWidthMulDiv() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00 movzx   eax, dil",
            "00001004: 00 mul     bl",
            "00001008: 00 ret",
        ))
        val out2 = NativePseudo.forFunction("g", listOf(
            "00001000: 00 movzx   eax, dil",
            "00001004: 00 div     bl",
            "00001008: 00 ret",
        ))
        assertTrue(out.contains("ax = al * bl"), "8-bit mul writes ax = al*src:\n$out")
        assertTrue(out2.contains("al = ax / bl") && out2.contains("ah = ax % bl"), "8-bit div writes al/ah:\n$out2")
    }

    @Test
    fun resolvesThumbTbbJumpTable() {
        val bytes = ByteArray(0x600)
        val tbl = intArrayOf(0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x04)
        for ((i, v) in tbl.withIndex()) bytes[0x4b8 + i] = v.toByte()
        val elf = elfWith(ElfArch.ARM, listOf(section(".text", 0x4b0, 0x150, true)), bytes)
        val insns = listOf(
            insn(0x4b0, "cmp", "r0, #7"),
            insn(0x4b2, "bhi", "loc_4e0"),
            insn(0x4b4, "tbb", "[pc, r0]"),
        )
        val res = NativeJumpTable.resolve(insns, 2, elf, ElfArch.ARM)
        assertTrue(res != null, "Thumb tbb jump table must resolve")
        assertEquals(listOf(0x4c4L, 0x4c8L, 0x4ccL, 0x4d0L, 0x4d4L, 0x4d8L, 0x4dcL, 0x4c0L), res!!.targets)
        assertEquals("r0", res.indexReg)
    }

    @Test
    fun resolvesMipsPicJumpTable() {
        val gp = 0x19100L
        val bytes = ByteArray(0x400)
        val buf = java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        buf.putInt(0x35c, (0x1100L - gp).toInt())
        buf.putInt(0x360, (0x1200L - gp).toInt())
        buf.putInt(0x364, (0x1300L - gp).toInt())
        val elf = elfWith(ElfArch.MIPS, listOf(section(".text", 0x1000, 0x400, true), section(".rodata", 0x35c, 0x100, false)), bytes)
        val insns = listOf(
            insn(0x1000, "lui", "\$2, 0x2"),
            insn(0x1004, "addiu", "\$2, \$2, -0x7f00"),
            insn(0x1008, "sltiu", "\$1, \$4, 0x3"),
            insn(0x100c, "beqz", "\$1, loc_1100"),
            insn(0x1010, "addu", "\$gp, \$2, \$t9"),
            insn(0x1014, "sll", "\$1, \$4, 0x2"),
            insn(0x1018, "lw", "\$2, -0x7fe8(\$gp)"),
            insn(0x101c, "addu", "\$1, \$1, \$2"),
            insn(0x1020, "lw", "\$1, 0x35c(\$1)"),
            insn(0x1024, "addu", "\$1, \$gp, \$1"),
            insn(0x1028, "jr", "\$1"),
        )
        val res = NativeJumpTable.resolve(insns, 10, elf, ElfArch.MIPS)
        assertTrue(res != null, "MIPS PIC gp-relative jump table must resolve")
        assertEquals(listOf(0x1100L, 0x1200L, 0x1300L), res!!.targets)
        assertEquals("\$4", res.indexReg)
    }

    @Test
    fun resolvesI386PicJumpTable() {
        val addBase = 0x2004L
        val bytes = ByteArray(0x3010)
        val buf = java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        buf.putInt(0x3000, (0x1100L - addBase).toInt())
        buf.putInt(0x3004, (0x1200L - addBase).toInt())
        buf.putInt(0x3008, (0x1300L - addBase).toInt())
        val elf = elfWith(ElfArch.X86, listOf(section(".text", 0x1000, 0x400, true), section(".rodata", 0x3000, 0x100, false)), bytes)
        val insns = listOf(
            insn(0x1000, "call", "0x1004"),
            insn(0x1004, "pop", "ebx"),
            insn(0x1008, "add", "ebx, 0x1000"),
            insn(0x100c, "cmp", "eax, 2"),
            insn(0x1010, "mov", "eax, [ebx + eax*4 + 0xffc]"),
            insn(0x1014, "add", "eax, ebx"),
            insn(0x1018, "jmp", "eax"),
        )
        val res = NativeJumpTable.resolve(insns, 6, elf, ElfArch.X86)
        assertTrue(res != null, "i386 PIC GOT-relative jump table must resolve")
        assertEquals(listOf(0x1100L, 0x1200L, 0x1300L), res!!.targets)
    }

    @Test
    fun pseudoCLoadStoreWidthAndWriteback() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 ldrsb   w0, [x1]",
            "00001004: 00000000 ldrb    w2, [x3]",
            "00001008: 00000000 ldrsw   x4, [x5]",
            "0000100c: 00000000 ldr     x6, [x7], #8",
            "00001010: 00000000 str     x6, [x8, #16]!",
            "00001014: 00000000 rev16   w9, w9",
            "00001018: 00000000 ret",
        ))
        assertTrue(out.contains("w0 = (int8_t)*x1"), "ldrsb must sign-extend a byte:\n$out")
        assertTrue(out.contains("w2 = (uint8_t)*x3"), "ldrb must zero-extend a byte:\n$out")
        assertTrue(out.contains("x4 = (int32_t)*x5"), "ldrsw must sign-extend a word:\n$out")
        assertTrue(out.contains("x6 = *x7; x7 += 8"), "post-index must update base:\n$out")
        assertTrue(out.contains("*(x8 + 16) = x6; x8 += 16"), "pre-index must update base:\n$out")
        assertTrue(out.contains("w9 = rev16(w9)"), "rev16 must not collapse to full bswap:\n$out")
    }

    @Test
    fun jumpTableResolvesWithNegativeImmediateDefault() {
        val bytes = ByteArray(0xa50)
        bytes[0xa3c] = 4; bytes[0xa3d] = 8; bytes[0xa3e] = 0xc; bytes[0xa3f] = 0x10
        val elf = elfWith(ElfArch.ARM64, listOf(section(".text", 0x100, 0x400, true), section(".rodata", 0xa3c, 0x14, false)), bytes)
        val insns = listOf(
            insn(0x10, "cmp", "w0, #3"),
            insn(0x14, "adrp", "x1, #0"),
            insn(0x18, "add", "x1, x1, #0xa3c"),
            insn(0x1c, "ldrb", "w1, [x1, w0, uxtw]"),
            insn(0x20, "adr", "x0, #0x100"),
            insn(0x24, "add", "x1, x0, w1, sxtb #2"),
            insn(0x28, "mov", "w0, #-1"),
            insn(0x2c, "br", "x1"),
        )
        val res = NativeJumpTable.resolve(insns, 7, elf, ElfArch.ARM64)
        assertTrue(res != null, "table must resolve despite a negative-immediate default between cmp and br")
        assertEquals(listOf(0x110L, 0x120L, 0x130L, 0x140L), res!!.targets)
    }

    @Test
    fun pseudoCZeroRegisterAndWideShifts() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 csel    x0, x1, xzr, ne",
            "00001004: 00000000 str     xzr, [x2]",
            "00001008: 00000000 tbnz    x3, #40, loc_1014",
            "0000100c: 00000000 movk    x4, #0x1234, lsl #48",
            "00001010: 00000000 ret",
            "loc_1014:",
            "00001014: 00000000 ret",
        ))
        assertTrue(out.contains("? x1 : 0"), "xzr in csel must read as 0:\n$out")
        assertTrue(out.contains("*x2 = 0"), "str xzr must store 0:\n$out")
        assertTrue(out.contains("(1LL << 40)"), "tbnz bit>=32 needs 64-bit shift:\n$out")
        assertTrue(out.contains("0xffffL << 48"), "movk shift>=32 needs 64-bit mask:\n$out")
        assertFalse(out.contains("xzr") || out.contains("wzr"), "no raw zero register:\n$out")
    }

    @Test
    fun resolvesX86GccForms() {
        val bytes = ByteArray(0x2020)
        val buf = java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        buf.putLong(0x2000, 0x1100); buf.putLong(0x2008, 0x1200); buf.putLong(0x2010, 0x1300)
        val elf = elfWith(ElfArch.X86_64, listOf(section(".text", 0x1000, 0x1000, true), section(".rodata", 0x2000, 0x100, false)), bytes)
        val insns = listOf(
            Insn(0xff0, 3, ByteArray(3), "cmp", "edi, 2"),
            Insn(0xff3, 2, ByteArray(2), "mov", "eax, edi"),
            Insn(0xff5, 7, ByteArray(7), "notrack jmp", "qword ptr [rax*8 + 0x2000]"),
        )
        val res = NativeJumpTable.resolve(insns, 2, elf, ElfArch.X86_64)
        assertTrue(res != null, "expected a resolved table for the GCC notrack/no-base form")
        assertEquals(listOf(0x1100L, 0x1200L, 0x1300L), res!!.targets)
    }

    @Test
    fun structuresSwitch() {
        val blocks = listOf(
            NativeStructurer.SBlock(0x10, listOf("x = idx"), NativeStructurer.Term.Switch("idx", listOf(0x30, 0x40))),
            NativeStructurer.SBlock(0x30, listOf("y = 1"), NativeStructurer.Term.Return),
            NativeStructurer.SBlock(0x40, listOf("y = 2"), NativeStructurer.Term.Return),
        )
        val out = NativeStructurer.structure(blocks)
        assertTrue(out.contains("switch (idx) {"), "expected switch header:\n$out")
        assertTrue(out.contains("case 0: goto loc_30;"), "expected case 0:\n$out")
        assertTrue(out.contains("case 1: goto loc_40;"), "expected case 1:\n$out")
        assertTrue(out.contains("loc_30:") && out.contains("loc_40:"), "case targets should be labelled:\n$out")
    }

    @Test
    fun recoversArm64Arguments() {
        val listing = listOf(
            "00001000: 000040b9 ldr     w8, [x0]",
            "00001004: 1f0001eb cmp     x0, x1",
            "00001008: 080000d1 sub     x8, x0, x2",
            "0000100c: c0035fd6 ret",
        )
        val out = NativePseudo.forFunction("sub_1000", listing)
        assertTrue(out.contains("sub_1000(x0, x1, x2)"), "expected 3 recovered args:\n${out.lineSequence().first { it.contains("sub_1000(") }}")
    }

    @Test
    fun detectsVoidAndNonVoid() {
        val nonVoid = NativePseudo.forFunction("ret42", listOf(
            "00001000: b82a000000 mov     eax, 0x2a",
            "00001005: c3         ret",
        ))
        assertTrue(!nonVoid.contains("void ret42"), "value-returning fn should not be void:\n$nonVoid")
        val void = NativePseudo.forFunction("setg", listOf(
            "00001000: c70005000000 mov     dword ptr [rdi], 5",
            "00001006: c3           ret",
        ))
        assertTrue(void.contains("void setg("), "fn that never sets rax should be void:\n$void")
    }

    @Test
    fun jniAbiOffsets() {
        assertEquals("RegisterNatives", JniAbi.envFunction(0x6b8))
        assertEquals("FindClass", JniAbi.envFunction(0x30))
        assertEquals("GetVersion", JniAbi.envFunction(0x20))
        assertEquals(null, JniAbi.envFunction(0x18))
        assertEquals(null, JniAbi.envFunction(0x6b4))
        assertEquals(null, JniAbi.envFunction(0x10000))
    }

    @Test
    fun pseudoSurfacesJniAnnotation() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 blr     x8  ; JNIEnv->RegisterNatives",
            "00001004: c0035fd6 ret",
        ))
        assertTrue(out.contains("x8(") && out.contains("/* JNIEnv->RegisterNatives */"), "call should be annotated:\n$out")
    }

    @Test
    fun compareBranchGotoUsesTargetOnly() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 cbz     x8, 0xb4ef4",
            "00001004: 00000000 tbz     w0, #0, 0x36cf8c",
            "00001008: c0035fd6 ret",
        ))
        assertTrue(out.contains("goto 0xb4ef4;") && !out.contains("goto x8"), "cbz target:\n$out")
        assertTrue(out.contains("goto 0x36cf8c;") && !out.contains("goto w0"), "tbz target:\n$out")
    }

    @Test
    fun foldsScaledIndexIntoExpression() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 ldr     w10, [x11, x8, lsl #1]",
            "00001004: 00000000 ldr     x2, [x0, w1, sxtw #2]",
            "00001008: c0035fd6 ret",
        ))
        assertTrue(out.contains("w10 = *(x11 + (x8 << 1))"), "lsl-scaled index:\n$out")
        assertTrue(out.contains("x2 = *(x0 + (w1 << 2))"), "sxtw-scaled index:\n$out")
        assertFalse(out.contains("lsl") || out.contains("sxtw"), "no raw shift/extend leak:\n$out")
    }

    @Test
    fun translatesArmScalarMnemonics() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 madd    x0, x1, x2, x3",
            "00001004: 00000000 msub    x4, x5, x6, x7",
            "00001008: 00000000 umulh   x8, x9, x10",
            "0000100c: 00000000 bic     x0, x1, x2",
            "00001010: 00000000 ror     w8, w9, #5",
            "00001014: 00000000 rev     w0, w1",
            "00001018: 00000000 ubfx    x0, x1, #4, #8",
            "0000101c: 00000000 sxtb    w0, w1",
            "00001020: 00000000 movk    x9, #0x2889, lsl #16",
            "00001024: 00000000 cinc    w0, w1, eq",
            "00001028: c0035fd6 ret",
        ))
        assertTrue(out.contains("x0 = x1 * x2 + x3"), "madd:\n$out")
        assertTrue(out.contains("x4 = x7 - x5 * x6"), "msub:\n$out")
        assertTrue(out.contains("x8 = (x9 * x10) >> 64"), "umulh:\n$out")
        assertTrue(out.contains("x0 = x1 & ~x2"), "bic:\n$out")
        assertTrue(out.contains("w8 = rotr(w9, 5)"), "ror:\n$out")
        assertTrue(out.contains("w0 = bswap(w1)"), "rev:\n$out")
        assertTrue(out.contains("x0 = (x1 >> 4) & 0xff"), "ubfx:\n$out")
        assertTrue(out.contains("w0 = (int8_t)w1"), "sxtb:\n$out")
        assertTrue(out.contains("x9 = (x9 & ~(0xffffL << 16)) | ((long)0x2889 << 16)"), "movk:\n$out")
        assertTrue(out.contains("w0 = (w1 == 0) ? w1 + 1 : w1") || out.contains("? w1 + 1 : w1"), "cinc:\n$out")
        assertFalse(out.contains("madd ") || out.contains("umulh ") || out.contains("movk "), "no raw passthrough:\n$out")
    }

    @Test
    fun structuresMipsBranchesWithDelaySlots() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 beqz    \$a0, loc_1014",
            "00001004: 00000000 nop",
            "00001008: 00000000 addiu   \$v0, \$zero, 1",
            "0000100c: 00000000 jr      \$ra",
            "00001010: 00000000 nop",
            "00001014: 00000000 addiu   \$v0, \$zero, 0",
            "00001018: 00000000 jr      \$ra",
            "0000101c: 00000000 nop",
        ))
        assertTrue(out.contains("\$a0 == 0"), "branch condition:\n$out")
        assertTrue(out.contains("loc_1014:"), "branch target must be labelled:\n$out")
        assertTrue(out.contains("return"), "jr \$ra is a return:\n$out")
        assertFalse(out.contains("??") || out.contains("/* r */"), "no garbage condition:\n$out")
        val labels = Regex("(?m)^\\s*(loc_[0-9a-f]+):").findAll(out).map { it.groupValues[1] }.toSet()
        val dangling = Regex("goto (loc_[0-9a-f]+)").findAll(out).map { it.groupValues[1] }.filter { it !in labels }.toList()
        assertTrue(dangling.isEmpty(), "no dangling gotos, found $dangling:\n$out")
    }

    @Test
    fun finalReadabilityFixes() {
        val mx = NativePseudo.forFunction("g", listOf(
            "00002000: 00 movsx   eax, byte ptr [rdi]",
            "00002004: 00 movzx   ecx, word ptr [rsi]",
            "00002008: 00 ret",
        ))
        assertTrue(mx.contains("eax = (int8_t)*rdi"), "movsx:\n$mx")
        assertTrue(mx.contains("ecx = (uint16_t)*rsi"), "movzx:\n$mx")

        val md = NativePseudo.forFunction("h", listOf(
            "00003000: 00 mul     ecx",
            "00003004: 00 div     ecx",
            "00003008: 00 ret",
        ))
        assertTrue(md.contains("edx:eax = eax * ecx"), "mul:\n$md")
        assertTrue(md.contains("edx = eax % ecx") && md.contains("eax = eax / ecx"), "div:\n$md")

        val mi = NativePseudo.forFunction("h", listOf(
            "00004000: 00 imul    eax, ecx, 8",
            "00004004: 00 ret",
        ))
        assertTrue(mi.contains("eax = ecx * 8"), "3-operand imul must keep the immediate:\n$mi")

        val pr = NativePseudo.forFunction("k", listOf(
            "00004000: 00 mov     rax, [rcx - 0x40]",
            "00004004: 00 ret",
        ))
        assertTrue(pr.contains("rax = *(rcx - 0x40)"), "precedence:\n$pr")

        val cl = NativePseudo.forFunction("m", listOf(
            "00005000: 00 call    dword ptr [ecx + 0x10]",
            "00005004: 00 ret",
        ))
        assertTrue(cl.contains("*(ecx + 0x10)()"), "call target:\n$cl")
        assertFalse(cl.contains("dword ptr"), "no dword ptr leak:\n$cl")

        val mp = NativePseudo.forFunction("n", listOf(
            "00006000: 00 bnez    \$v0, 0x167f80",
            "00006004: 00 nop",
            "00006008: 00 jr      \$ra",
            "0000600c: 00 nop",
        ))
        assertTrue(mp.contains("goto 0x167f80"), "mips goto address:\n$mp")
        assertFalse(mp.contains("goto \$v0"), "no operand-string goto:\n$mp")
    }

    @Test
    fun conditionalCompareInvalidatesBranchCondition() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00 cmp     r8, #0",
            "00001004: 00 it      ne",
            "00001006: 00 cmpne   sb, #0",
            "0000100a: 00 beq     loc_1010",
            "0000100e: 00 bx      lr",
            "00001010: 00 movs    r0, #1",
            "00001014: 00 bx      lr",
        ))
        assertTrue(out.contains("cond_eq"), "opaque compound condition:\n$out")
        assertFalse(out.contains("r8 == 0"), "must not reuse the stale unconditional compare:\n$out")
    }

    @Test
    fun mipsUnsignedCompareIsCast() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00 sltiu   \$v0, \$a0, -2",
            "00001004: 00 slt     \$v1, \$a0, \$a1",
            "00001008: 00 jr      \$ra",
            "0000100c: 00 nop",
        ))
        assertTrue(out.contains("\$v0 = ((unsigned)\$a0 < (unsigned)-2)"), "sltiu unsigned cast:\n$out")
        assertTrue(out.contains("\$v1 = (\$a0 < \$a1)"), "slt signed:\n$out")
    }

    @Test
    fun foldsConstantIntoAliasRegister() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00 movw    ip, #0x1234",
            "00001004: 00 movt    ip, #0x5678",
            "00001008: 00 bx      lr",
        ))
        assertTrue(out.contains("ip = 0x56781234"), "fold into ip (r12):\n$out")
    }

    @Test
    fun arm2OperandFormsDoNotEmitPlaceholder() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 bic     r3, r2",
            "00001004: 00000000 lsl     r2, #4",
            "00001008: 00000000 lsr     r0, r1",
            "0000100c: 00000000 orn     r4, r5",
            "00001010: 00000000 sbcs    r6, r7",
            "00001014: 00000000 bx      lr",
        ))
        assertFalse(out.contains("?"), "no placeholder operand:\n$out")
        assertTrue(out.contains("r3 &= ~r2"), "bic 2-op:\n$out")
        assertTrue(out.contains("r2 <<= 4"), "lsl 2-op:\n$out")
        assertTrue(out.contains("r0 >>= r1"), "lsr 2-op:\n$out")
        assertTrue(out.contains("r6 = r6 - r7 - carry"), "sbcs 2-op:\n$out")
    }

    @Test
    fun stringMovsdNotMistranslatedAsScalarMove() {
        val sse = NativePseudo.forFunction("f", listOf(
            "00001000: 00 movsd   xmm0, qword ptr [rdi]",
            "00001004: 00 ret",
        ))
        assertTrue(sse.contains("xmm0 = *rdi"), "SSE movsd:\n$sse")
        val str = NativePseudo.forFunction("g", listOf(
            "00002000: 00 movsd   dword ptr es:[edi], dword ptr [esi]",
            "00002004: 00 ret",
        ))
        assertFalse(str.contains("*edi = *esi"), "string movsd must not become a scalar move:\n$str")
    }

    @Test
    fun mipsMultDefinesBothHiAndLo() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00 mult    \$a0, \$a1",
            "00001004: 00 mfhi    \$s5",
            "00001008: 00 mflo    \$v0",
            "0000100c: 00 jr      \$ra",
            "00001010: 00 nop",
        ))
        assertTrue(out.contains("hi:lo = \$a0 * \$a1"), "mult writes hi:lo:\n$out")
        assertTrue(out.contains("\$s5 = hi") && out.contains("\$v0 = lo"), "mfhi/mflo:\n$out")
    }

    @Test
    fun mipsDelaySlotHazardSnapshotsBranchRegister() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00 bnez    \$s3, loc_1010",
            "00001004: 00 nor     \$s3, \$zero, \$s6",
            "00001008: 00 jr      \$ra",
            "0000100c: 00 nop",
            "00001010: 00 move    \$v0, \$zero",
            "00001014: 00 jr      \$ra",
            "00001018: 00 nop",
        ))
        assertTrue(out.contains("\$s3_pre = \$s3"), "snapshot before delay slot:\n$out")
        assertTrue(out.contains("\$s3 = ~(\$zero | \$s6)"), "delay slot still emitted:\n$out")
        assertTrue(out.contains("\$s3_pre != 0"), "branch tests the pre-delay value:\n$out")
    }

    @Test
    fun translatesMoreScalarMnemonics() {
        val x = NativePseudo.forFunction("f", listOf(
            "00001000: 00 movabs  rax, 0x1122334455",
            "00001008: 00 movsd   xmm0, qword ptr [rdi]",
            "0000100c: 00 cdqe",
            "0000100e: 00 xorps   xmm1, xmm1",
            "00001011: 00 ret",
        ))
        assertTrue(x.contains("rax = 0x1122334455"), "movabs:\n$x")
        assertTrue(x.contains("xmm0 = *rdi"), "movsd:\n$x")
        assertTrue(x.contains("rax = (int32_t)eax"), "cdqe:\n$x")
        assertTrue(x.contains("xmm1 = 0"), "xorps self-zero:\n$x")

        val m = NativePseudo.forFunction("f", listOf(
            "00002000: 00 slt     \$v0, \$a0, \$a1",
            "00002004: 00 nor     \$v1, \$a0, \$a1",
            "00002008: 00 movn    \$s0, \$a0, \$a1",
            "0000200c: 00 mult    \$a0, \$a1",
            "00002010: 00 mflo    \$v0",
            "00002014: 00 jr      \$ra",
            "00002018: 00 nop",
        ))
        assertTrue(m.contains("\$v0 = (\$a0 < \$a1)"), "slt:\n$m")
        assertTrue(m.contains("\$v1 = ~(\$a0 | \$a1)"), "nor:\n$m")
        assertTrue(m.contains("if (\$a1 != 0) \$s0 = \$a0"), "movn:\n$m")
        assertTrue(m.contains("lo = \$a0 * \$a1") && m.contains("\$v0 = lo"), "mult/mflo:\n$m")

        val a = NativePseudo.forFunction("f", listOf(
            "00003000: 00 cmp     r0, #0",
            "00003004: 00 moveq   r1, #5",
            "00003008: 00 addne   r1, r1, #1",
            "0000300c: 00 pop     {r4, r5, pc}",
        ))
        assertTrue(a.contains("if (r0 == 0) r1 = 5"), "conditional moveq:\n$a")
        assertTrue(a.contains("if (r0 != 0) r1 = r1 + 1"), "conditional addne:\n$a")
        assertTrue(a.contains("return"), "pop{pc} is a return:\n$a")
    }

    @Test
    fun foldsArmWideConstants() {
        val a64 = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 mov     w2, #6",
            "00001004: 00000000 mov     w19, #6",
            "00001008: 00000000 movk    w2, #1, lsl #16",
            "0000100c: 00000000 movk    w19, #2, lsl #16",
            "00001010: 00000000 ret",
        ))
        assertTrue(a64.contains("w2 = 0x10006"), "aarch64 fold w2:\n$a64")
        assertTrue(a64.contains("w19 = 0x20006"), "aarch64 fold w19:\n$a64")
        assertFalse(a64.contains("movk") || a64.contains("0xffff << 16"), "no residual movk:\n$a64")

        val a32 = NativePseudo.forFunction("f", listOf(
            "00002000: 00000000 movw    r4, 6",
            "00002004: 00000000 movt    r4, 1",
            "00002008: 00000000 bx      lr",
        ))
        assertTrue(a32.contains("r4 = 0x10006"), "arm32 movw/movt fold:\n$a32")
        assertFalse(a32.contains("movt") || a32.contains("movw"), "no residual movw/movt:\n$a32")
    }

    @Test
    fun doesNotFoldConstantReadMidBuild() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 mov     w2, #6",
            "00001004: 00000000 add     w0, w2, #1",
            "00001008: 00000000 movk    w2, #1, lsl #16",
            "0000100c: 00000000 ret",
        ))
        assertTrue(out.contains("w2 = 6"), "partial value preserved:\n$out")
        assertFalse(out.contains("w2 = 0x10006"), "must not fold across a read:\n$out")
    }

    @Test
    fun namesMipsAtomicsAndResolvedGotLoads() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 lw      \$t9, -0x7f04(\$gp)  ; pthread_mutex_lock",
            "00001004: 00000000 nop",
            "00001008: 00000000 ll      \$v1, 8(\$a0)",
            "0000100c: 00000000 sc      \$at, 8(\$a0)",
            "00001010: 00000000 jr      \$ra",
            "00001014: 00000000 nop",
        ))
        assertTrue(out.contains("\$t9 = pthread_mutex_lock"), "resolved GOT load:\n$out")
        assertTrue(out.contains("\$v1 = __ll(\$a0 + 8)"), "load-linked:\n$out")
        assertTrue(out.contains("\$at = __sc(\$a0 + 8, \$at)"), "store-conditional:\n$out")
    }

    @Test
    fun translatesThumb2AndArm32Forms() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 movs    r0, #1",
            "00001004: 00000000 mvns    r2, r3",
            "00001008: 00000000 bic.w   r3, r3, r1",
            "0000100c: 00000000 ror.w   r4, r5, r6",
            "00001010: 00000000 bics.w  r5, r5, r6",
            "00001014: 00000000 rsb     r7, r8, r9",
            "00001018: 00000000 mov     r8, r9",
            "0000101c: 00000000 bx      lr",
        ))
        assertTrue(out.contains("r0 = 1"), "movs:\n$out")
        assertTrue(out.contains("r2 = ~r3"), "mvns:\n$out")
        assertTrue(out.contains("r3 = r3 & ~r1"), "bic.w:\n$out")
        assertTrue(out.contains("r4 = rotr(r5, r6)"), "ror.w:\n$out")
        assertTrue(out.contains("r5 = r5 & ~r6"), "bics.w:\n$out")
        assertTrue(out.contains("r7 = r9 - r8"), "rsb:\n$out")
        assertTrue(out.contains("r8 = r9"), "mov + ARM detection for r8/r9:\n$out")
        assertFalse(out.contains("movs ") || out.contains("bic.w") || out.contains("rsb ") || out.contains("mvns "), "no raw passthrough:\n$out")
    }

    @Test
    fun x86_32SuppressesRegisterArgsWhenArchKnown() {
        val listing = listOf(
            "00001000: b801000000 mov     eax, 1",
            "00001005: 31d2       xor     edx, edx",
            "00001007: c3         ret",
        )
        val as32 = NativePseudo.forFunction("f", listing, x86Is32 = true)
        assertTrue(as32.contains("f()"), "32-bit cdecl => no register args:\n$as32")
        assertFalse(as32.contains("(rdi") || as32.contains("(edi"), "no SysV reg args on x86-32:\n$as32")
    }

    @Test
    fun selfZeroXorIsNotAnIncomingArg() {
        val listing = listOf(
            "00002000: 8b07       mov     eax, dword ptr [rdi]",
            "00002002: 31d2       xor     edx, edx",
            "00002004: c3         ret",
        )
        val out = NativePseudo.forFunction("g", listing, x86Is32 = false)
        assertTrue(out.contains("g(rdi)"), "rdi is the only real arg:\n$out")
        assertFalse(out.contains("rdx") || out.contains("rsi"), "self-zeroed edx is not an arg:\n$out")
    }

    @Test
    fun forwardsJniCommentOnIndirectTailCall() {
        val listing = listOf(
            "00001000: 200080d2 mov     x0, #1",
            "00001004: 40001fd6 br      x2  ; JNIEnv->GetArrayLength",
        )
        val out = NativePseudo.forFunction("f", listing)
        assertTrue(out.contains("return x2() /* JNIEnv->GetArrayLength */"), "tail-call JNI comment kept:\n$out")
        assertFalse(out.contains("goto *x2"), "should not degrade to goto:\n$out")
    }

    @Test
    fun rendersOverflowCondition() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 cmp     x1, x2",
            "00001004: 00000000 cset    w0, vs",
            "00001008: c0035fd6 ret",
        ))
        assertTrue(out.contains("overflow(x1, x2)"), "vs overflow condition:\n$out")
        assertFalse(out.contains("??"), "no placeholder:\n$out")
    }

    private fun jniCorpus(abi: String): ByteArray? = javaClass.getResourceAsStream("/jni/libjnitest_$abi.so")?.readBytes()

    private fun jniAnnotations(bytes: ByteArray): Pair<List<String>, List<String>> {
        val elf = ElfFile.parse(bytes)!!
        val src = NativeListing.build(elf, CapstoneDisassembler, elf.arch, elf.littleEndian, { _, _ -> }, { false })!!
        val all = (0 until src.lineCount).map { src.lines(it, 1).first() }; src.close()
        val annos = all.filter { it.contains("; JNIEnv->") || it.contains("; JavaVM->") }.map { it.substringAfter("; ").trim() }
        val natives = all.filter { it.startsWith("; Java native: ") }.map { it.removePrefix("; Java native: ") }
        return annos to natives
    }

    @Test
    fun jniCorpusEndToEnd() {
        for (abi in listOf("arm64-v8a", "x86_64", "armeabi-v7a", "x86")) {
            val bytes = jniCorpus(abi) ?: continue
            val (annos, natives) = jniAnnotations(bytes)
            assertTrue(natives.any { it == "nativeCompute ([BI)I" }, "[$abi] registered native named with signature: $natives")
            assertTrue(annos.count { it == "JNIEnv->GetArrayLength" } >= 3, "[$abi] direct + delegated + Java_* GetArrayLength: $annos")
            assertTrue(annos.contains("JNIEnv->RegisterNatives"), "[$abi] $annos")
            assertTrue(annos.contains("JNIEnv->FindClass"), "[$abi] real FindClass in JNI_OnLoad: $annos")
            assertTrue(annos.contains("JavaVM->GetEnv"), "[$abi] GetEnv typed as JavaVM: $annos")
            assertFalse(annos.any { it.contains("Method") || it.startsWith("JNIEnv->New") }, "[$abi] no spurious annotation from the Widget vtable: $annos")
        }
    }

    @Test
    fun jniMultipleRegisterNativesInOneFunction() {
        for (name in listOf("multi_arm64", "multi_x86")) {
            val bytes = javaClass.getResourceAsStream("/jni/$name.so")?.readBytes() ?: continue
            val (_, natives) = jniAnnotations(bytes)
            assertTrue(natives.any { it == "a1 ([B)I" } && natives.any { it == "a2 ()I" } && natives.any { it == "b1 ([B)I" },
                "[$name] both registered classes' natives named: $natives")
        }
    }

    @Test
    fun jniRealCronetAllArches() {
        val apk = java.io.File("/home/nitanmarcel/Downloads/pinning-demo.apk")
        assumeTrue(apk.exists(), "pinning-demo.apk not present")
        java.util.zip.ZipFile(apk).use { zip ->
            for (abi in listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")) {
                val entry = zip.getEntry("lib/$abi/libcronet.119.0.6045.31.so") ?: continue
                val bytes = zip.getInputStream(entry).use { it.readBytes() }
                val elf = ElfFile.parse(bytes)!!
                NativeFunctions.detectArmMode(elf, CapstoneDisassembler, elf.littleEndian)
                val starts = NativeFunctions.discover(elf, CapstoneDisassembler, elf.arch, elf.littleEndian)
                val jni = NativeJni.analyze(elf, CapstoneDisassembler, elf.arch, elf.littleEndian, starts)
                assertTrue(jni.registered.size >= 100, "[$abi] real cronet should recover its registered natives, got ${jni.registered.size}")
                assertTrue(jni.registered.values.all { it.signature.startsWith("(") }, "[$abi] all recovered signatures well-formed")
            }
        }
    }

    @Test
    fun jniStackBuiltArrayObfuscated() {
        val bytes = jniCorpus("librootprobe") ?: javaClass.getResourceAsStream("/jni/librootprobe.so")?.readBytes()
        assumeTrue(bytes != null, "librootprobe fixture not present")
        val elf = ElfFile.parse(bytes!!)!!
        NativeFunctions.detectArmMode(elf, CapstoneDisassembler, elf.littleEndian)
        val starts = NativeFunctions.discover(elf, CapstoneDisassembler, elf.arch, elf.littleEndian)
        val jni = NativeJni.analyze(elf, CapstoneDisassembler, elf.arch, elf.littleEndian, starts)
        val natives = jni.registered.values.map { "${it.name} ${it.signature}" }.toSet()
        assertEquals(2, jni.registerCalls.size, "both RegisterNatives calls found")
        assertTrue(natives.containsAll(setOf("check ()I", "zYg0tE ()I", "bN8cF ()I", "mW3jY ()Z", "pL9vR ()[I", "x7kQ2 ()V")),
            "all 6 stack-built registrations recovered: $natives")
    }

    @Test
    fun jniX86_32StackModel() {
        val bytes = jniCorpus("x86")
        assumeTrue(bytes != null, "x86 JNI corpus fixture not present")
        val (annos, _) = jniAnnotations(bytes!!)
        assertTrue(annos.contains("JavaVM->GetEnv") && annos.contains("JNIEnv->FindClass"),
            "GetEnv chain recovered through the stack: $annos")
    }

    @Test
    fun jniEnvProvenanceGatesCalls() {
        val et = NativeJni.newEnvTrack(ElfArch.ARM64)!!
        et.seed(mapOf(0 to NativeJni.Tag.ENV))
        fun run(m: String, ops: String) = et.track(Insn(0, 4, ByteArray(4), m, ops))
        run("mov", "x19, x0")
        run("ldr", "x8, [x19]")
        run("ldr", "x9, [x8, #0x558]")
        assertEquals(0x558L, et.vtSlot["x9"]); assertEquals(NativeJni.Tag.ENV, et.vtTag["x9"])
        run("ldr", "x10, [x1]")
        run("ldr", "x11, [x10, #0x558]")
        assertNull(et.vtTag["x11"], "a non-env object must not be flagged as a JNIEnv call")
        et.typedRegs["x0"] = NativeJni.Tag.ENV
        run("bl", "#0x1000")
        assertFalse("x0" in et.typedRegs); assertTrue("x19" in et.typedRegs)
    }

    @Test
    fun jniGetEnvBridgesJavaVmToEnv() {
        val et = NativeJni.newEnvTrack(ElfArch.ARM64)!!
        et.seed(mapOf(0 to NativeJni.Tag.VM))
        fun run(m: String, ops: String) = et.track(Insn(0, 4, ByteArray(4), m, ops))
        run("ldr", "x8, [x0]")
        run("add", "x1, x29, #0x18")
        run("ldr", "x8, [x8, #0x30]")
        run("blr", "x8")
        run("ldr", "x0, [x29, #0x18]")
        run("ldr", "x8, [x0]")
        run("ldr", "x9, [x8, #0x30]")
        assertEquals(NativeJni.Tag.ENV, et.vtTag["x9"], "env recovered from GetEnv out-parameter")
    }

    @Test
    fun namesStackLocals() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 str     x0, [x29, #0x18]",
            "00001004: 00000000 ldr     x1, [x29, #0x18]",
            "00001008: 00000000 ldr     w2, [sp, #0x10]",
            "0000100c: 00000000 add     x3, x29, #0x18",
            "00001010: 00000000 ldr     x4, [x0, x1]",
            "00001014: c0035fd6 ret",
        ))
        assertTrue(out.contains("var_18 = x0") && out.contains("x1 = var_18"), "frame local named consistently:\n$out")
        assertTrue(out.contains("w2 = var_s10"), "sp-relative local in its own namespace:\n$out")
        assertTrue(out.contains("x3 = &var_18"), "address-of a local:\n$out")
        assertTrue(out.contains("x4 = *(x0 + x1)"), "indexed access stays a raw deref:\n$out")
    }

    @Test
    fun translatesLoadStoreVariants() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 sturb   w3, [x29, #-4]",
            "00001004: 00000000 ldursw  x8, [x29, #-0xc]",
            "00001008: 00000000 ldrsb   w0, [x1]",
            "0000100c: c0035fd6 ret",
        ))
        assertTrue(out.contains("var_m4 = w3"), "sturb store to a frame local (x29-4):\n$out")
        assertTrue(out.contains("x8 = (int32_t)var_mc"), "ldursw sign-extends a frame local (x29-0xc):\n$out")
        assertTrue(out.contains("w0 = (int8_t)*x1"), "non-frame ldrsb load sign-extends:\n$out")
        assertFalse(out.contains("sturb") || out.contains("ldursw"), "no raw passthrough:\n$out")
    }

    @Test
    fun rendersTailCall() {
        val out = NativePseudo.forFunction("JNI_OnLoad", listOf(
            "000b34d0: 5f2403d5 bti     c",
            "000b34d4: 17150014 b       sub_b8930",
        ))
        assertTrue(out.contains("return sub_b8930()"), "tail branch to a function should be a return-call:\n$out")
        assertFalse(out.contains("goto sub_b8930"), "should not be a goto:\n$out")
        val ind = NativePseudo.forFunction("g", listOf("00001000: 00001fd6 br      x8"))
        assertFalse(ind.contains("return x8()"), "indirect branch is not a tail call:\n$ind")
    }

    @Test
    fun dropsDeadAdrpPageLoad() {
        val listing = listOf(
            "00001000: 00000090 adrp    x0, 0x1c000",
            "00001004: 00000091 add     x0, x0, #0x123  ; \"Destroy\"",
            "00001008: c0035fd6 ret",
        )
        val out = NativePseudo.forFunction("f", listing)
        assertTrue(out.contains("x0 = \"Destroy\""), "resolved string must show:\n$out")
        assertFalse(out.contains("x0 = 0x1c000"), "the dead adrp page-load should be dropped:\n$out")
    }

    @Test
    fun materializesConditionFromCompare() {
        val withCmp = NativePseudo.forFunction("f", listOf(
            "00001000: 1f0001eb cmp     x0, x1",
            "00001004: e0179f9a cset    w0, eq",
            "00001008: c0035fd6 ret",
        ))
        assertTrue(withCmp.contains("w0 = (x0 == x1)"), "cset after cmp should show the comparison:\n$withCmp")
        val afterCall = NativePseudo.forFunction("g", listOf(
            "00001000: 1f0001eb cmp     x0, x1",
            "00001004: 00000094 bl      helper",
            "00001008: e0179f9a cset    w0, eq",
            "0000100c: c0035fd6 ret",
        ))
        assertTrue(afterCall.contains("w0 = (eq)"), "cset after a call must not reuse the pre-call cmp:\n$afterCall")
    }

    @Test
    fun hidesFrameManagement() {
        val listing = listOf(
            "00001000: fd7bbfa9 stp     x29, x30, [sp, #-0x10]!",
            "00001004: fd030091 mov     x29, sp",
            "00001008: 00040091 add     x0, x0, #1",
            "0000100c: fd7bc1a8 ldp     x29, x30, [sp], #0x10",
            "00001010: c0035fd6 ret",
        )
        val out = NativePseudo.forFunction("f", listing)
        assertTrue(out.contains("x0 = x0 + 1"), "real logic must survive:\n$out")
        assertFalse(out.contains("x29"), "frame save/restore + fp setup should be hidden:\n$out")
        assertFalse(out.contains("sp"), "frame ops should be hidden:\n$out")
    }

    @Test
    fun callSiteUsesCalleeArity() {
        val listing = listOf(
            "00001000: bf01000000 mov     edi, 1",
            "00001005: be02000000 mov     esi, 2",
            "0000100a: ba03000000 mov     edx, 3",
            "0000100f: e800000000 call    worker",
            "00001014: c3         ret",
        )
        val guessed = NativePseudo.forFunction("caller", listing)
        assertTrue(guessed.contains("worker(rdi, rsi, rdx)"), "without callee info, guesses from set-up regs:\n$guessed")
        val exact = NativePseudo.forFunction("caller", listing) { if (it == "worker") 1 else null }
        assertTrue(exact.contains("worker(rdi)") && !exact.contains("worker(rdi,"), "callee arity should win:\n$exact")
    }

    @Test
    fun argCountMatchesSignature() {
        val worker = listOf(
            "00002000: 8b07     mov     eax, dword ptr [rdi]",
            "00002002: 0307     add     eax, dword ptr [rsi]",
            "00002004: c3       ret",
        )
        assertEquals(2, NativePseudo.argCount(worker))
    }

    @Test
    fun recoversCallSiteArguments() {
        val listing = listOf(
            "00001000: 000080d2 mov     x0, #5",
            "00001004: 210080d2 mov     x1, #7",
            "00001008: 00000094 bl      helper",
            "0000100c: c0035fd6 ret",
        )
        val out = NativePseudo.forFunction("sub_1000", listing)
        assertTrue(out.contains("helper(x0, x1)"), "expected call args from set-up registers:\n$out")
    }

    @Test
    fun noArgsWhenRegistersWrittenFirst() {
        val listing = listOf(
            "00001000: 000080d2 mov     x0, #0",
            "00001004: 210080d2 mov     x1, #1",
            "00001008: 00000091 add     x0, x0, x1",
            "0000100c: c0035fd6 ret",
        )
        val out = NativePseudo.forFunction("sub_1000", listing)
        assertTrue(out.contains("sub_1000()"), "registers written first are not args:\n$out")
    }

    @Test
    fun pseudoCRendersSwitchComment() {
        val listing = listOf(
            "00001000: 00000000 br      x8  ; switch (x0): loc_1010, loc_1020, loc_1030",
            "loc_1010:",
            "00001010: 200080d2 mov     x0, #1",
            "00001014: c0035fd6 ret",
            "loc_1020:",
            "00001020: 400080d2 mov     x0, #2",
            "00001024: c0035fd6 ret",
            "loc_1030:",
            "00001030: 600080d2 mov     x0, #3",
            "00001034: c0035fd6 ret",
        )
        val out = NativePseudo.forFunction("sub_1000", listing)
        assertTrue(out.contains("switch (x0) {"), "expected switch:\n$out")
        assertTrue(out.contains("case 2: goto loc_1030;"), "expected all cases:\n$out")
    }

    @Test
    fun discoversPacEntries() {
        val bytes = ByteArray(0x1080)
        fun put(off: Int, word: Long) { for (k in 0 until 4) bytes[off + k] = ((word ushr (k * 8)) and 0xFF).toByte() }
        for (off in 0x1000..0x101c step 4) put(off, 0xD503233F)
        put(0x1040, 0xD503245F)
        put(0x1044, 0xD503233F)
        val elf = elfWith(ElfArch.ARM64, listOf(section(".text", 0x1000, 0x60, true)), bytes)
        val starts = NativeFunctions.discover(elf).toSet()
        assertTrue(0x1000L in starts, "standalone paciasp entry")
        assertTrue(0x1040L in starts, "bti+paciasp entry should back up to the bti")
        assertFalse(0x1044L in starts, "paciasp address itself is not the entry when a bti precedes it")
    }

    @Test
    fun armMappingDataRegions() {
        val elf = ElfFile(
            ElfArch.ARM, true, true, 0, emptyList(), emptyList(), emptyMap(),
            longArrayOf(0x1000, 0x1010, 0x1020), intArrayOf(ElfFile.MAP_THUMB, ElfFile.MAP_DATA, ElfFile.MAP_ARM), 0L, emptyMap(), ByteArray(0),
        )
        assertTrue(elf.armThumbAt(0x1004), "thumb region")
        assertFalse(elf.armThumbAt(0x1024), "arm region")
        assertEquals(0x1020L, elf.dataRegionEnd(0x1014))
        assertEquals(null, elf.dataRegionEnd(0x1004))
        assertEquals(null, elf.dataRegionEnd(0x1024))
    }

    @Test
    fun backendSupportsAllMappedArches() {
        for (arch in listOf(ElfArch.ARM, ElfArch.ARM64, ElfArch.X86, ElfArch.X86_64, ElfArch.MIPS, ElfArch.MIPS64)) {
            assertTrue(CapstoneDisassembler.supports(arch), "expected support for $arch")
        }
        assertFalse(CapstoneDisassembler.supports(ElfArch.UNKNOWN))
        assertEquals(listOf(CapstoneDisassembler), Disassemblers.available(ElfArch.X86_64))
    }

    @Test
    fun mipsBitfieldExtractAndInsert() {
        val ext = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 ext     \$v0, \$a0, 4, 8",
            "00001004: 00000000 jr      \$ra",
        ))
        assertTrue(ext.contains("\$v0 = (\$a0 >> 4) & ((1 << 8) - 1)"), "ext:\n$ext")
        assertFalse(ext.contains("ext "), "ext must not pass through:\n$ext")
        val ins = NativePseudo.forFunction("g", listOf(
            "00001000: 00000000 ins     \$v0, \$a0, 4, 8",
            "00001004: 00000000 jr      \$ra",
        ))
        assertTrue(ins.contains("\$v0 = (\$v0 & ~(((1 << 8) - 1) << 4)) | ((\$a0 & ((1 << 8) - 1)) << 4)"), "ins:\n$ins")
    }

    @Test
    fun mipsRotateAndNot() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 rotrv   \$v0, \$a0, \$a1",
            "00001004: 00000000 rotr    \$v1, \$a0, 5",
            "00001008: 00000000 not     \$t0, \$a0",
            "0000100c: 00000000 jr      \$ra",
        ))
        assertTrue(out.contains("\$v0 = rotr(\$a0, \$a1)"), "rotrv:\n$out")
        assertTrue(out.contains("\$v1 = rotr(\$a0, 5)"), "rotr imm:\n$out")
        assertTrue(out.contains("\$t0 = ~\$a0"), "not:\n$out")
    }

    @Test
    fun mipsFpArithLoadsAndStores() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 lwc1    \$f0, 4(\$sp)",
            "00001004: 00000000 ldc1    \$f2, 8(\$sp)",
            "00001008: 00000000 add.s   \$f0, \$f12, \$f14",
            "0000100c: 00000000 sub.d   \$f4, \$f0, \$f2",
            "00001010: 00000000 mul.d   \$f6, \$f0, \$f2",
            "00001014: 00000000 div.s   \$f8, \$f0, \$f2",
            "00001018: 00000000 swc1    \$f0, 0(\$sp)",
            "0000101c: 00000000 sdc1    \$f2, 16(\$sp)",
            "00001020: 00000000 jr      \$ra",
        ))
        assertTrue(out.contains("\$f0 = *(\$sp + 4)"), "lwc1 load:\n$out")
        assertTrue(out.contains("\$f0 = \$f12 + \$f14"), "add.s:\n$out")
        assertTrue(out.contains("\$f4 = \$f0 - \$f2"), "sub.d:\n$out")
        assertTrue(out.contains("\$f6 = \$f0 * \$f2"), "mul.d:\n$out")
        assertTrue(out.contains("\$f8 = \$f0 / \$f2"), "div.s:\n$out")
        assertTrue(out.contains("*\$sp = \$f0"), "swc1 store:\n$out")
        assertFalse(out.contains("swc1") || out.contains("lwc1"), "FP load/store must not pass through:\n$out")
    }

    @Test
    fun mipsFpConvertAndCompareWithMovt() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 cvt.s.w \$f0, \$f0",
            "00001004: 00000000 trunc.w.s \$f0, \$f12",
            "00001008: 00000000 c.olt.s \$f12, \$f14",
            "0000100c: 00000000 movt    \$v0, \$at, \$fcc0",
            "00001010: 00000000 movf    \$v1, \$at, \$fcc0",
            "00001014: 00000000 jr      \$ra",
        ))
        assertTrue(out.contains("\$f0 = (float)\$f0"), "cvt.s.w:\n$out")
        assertTrue(out.contains("\$f0 = (int32_t)\$f12"), "trunc.w.s:\n$out")
        assertTrue(out.contains("fp_cond = \$f12 < \$f14"), "c.olt.s sets fp_cond:\n$out")
        assertTrue(out.contains("if (fp_cond) \$v0 = \$at"), "movt:\n$out")
        assertTrue(out.contains("if (!fp_cond) \$v1 = \$at"), "movf:\n$out")
    }

    @Test
    fun mipsMaddMsubAccumulateHiLo() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 madd    \$a1, \$a0",
            "00001004: 00000000 msub    \$a3, \$a2",
            "00001008: 00000000 jr      \$ra",
        ))
        assertTrue(out.contains("hi:lo = hi:lo + \$a1 * \$a0"), "madd:\n$out")
        assertTrue(out.contains("hi:lo = hi:lo - \$a3 * \$a2"), "msub:\n$out")
    }

    @Test
    fun mipsSetAndTrapComparisons() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 seq     \$v0, \$a0, \$a1",
            "00001004: 00000000 sne     \$v1, \$a0, \$a1",
            "00001008: 00000000 tne     \$a0, \$a1",
            "0000100c: 00000000 tge     \$a0, \$a1",
            "00001010: 00000000 jr      \$ra",
        ))
        assertTrue(out.contains("\$v0 = (\$a0 == \$a1)"), "seq:\n$out")
        assertTrue(out.contains("\$v1 = (\$a0 != \$a1)"), "sne:\n$out")
        assertTrue(out.contains("if (\$a0 != \$a1) __trap()"), "tne:\n$out")
        assertTrue(out.contains("if (\$a0 >= \$a1) __trap()"), "tge:\n$out")
    }

    @Test
    fun pseudoCX86BitScanAndCountOps() {
        val out = NativePseudo.forFunction("f", listOf(
            "f:",
            "00001410: f30fb8442404 popcnt  eax, dword ptr [esp + 4]",
            "00001420: 0fbd442404  bsr     eax, dword ptr [esp + 4]",
            "00001430: f30fbc442404 tzcnt   eax, dword ptr [esp + 4]",
            "00001440: f30fbd442404 lzcnt   eax, dword ptr [esp + 4]",
            "00001450: 0fbc442404  bsf     eax, dword ptr [esp + 4]",
            "00001460: c3          ret",
        ), x86Is32 = true)
        assertTrue(out.contains("eax = popcount(var_s4)"), "popcnt:\n$out")
        assertTrue(out.contains("eax = bsr(var_s4)"), "bsr:\n$out")
        assertTrue(out.contains("eax = ctz(var_s4)"), "tzcnt:\n$out")
        assertTrue(out.contains("eax = clz(var_s4)"), "lzcnt:\n$out")
        assertTrue(out.contains("eax = bsf(var_s4)"), "bsf:\n$out")
        assertFalse(out.contains("popcnt eax"), "popcnt must not pass through raw:\n$out")
    }

    @Test
    fun pseudoCX86AtomicXaddAndDoublePrecisionShifts() {
        val out = NativePseudo.forFunction("f", listOf(
            "f:",
            "00001448: f00fc101    xadd    dword ptr [ecx], eax",
            "00001462: 0fa5c2      shld    edx, eax, cl",
            "00001470: 0fadc2      shrd    edx, eax, cl",
            "00001480: c3          ret",
        ), x86Is32 = true)
        assertTrue(out.contains("eax = __xadd(ecx, eax)"), "xadd:\n$out")
        assertTrue(out.contains("edx = shld(edx, eax, cl)"), "shld:\n$out")
        assertTrue(out.contains("edx = shrd(edx, eax, cl)"), "shrd:\n$out")
        assertFalse(out.contains("xadd dword"), "xadd must not pass through raw:\n$out")
        assertFalse(out.contains("shld edx"), "shld must not pass through raw:\n$out")
    }

    @Test
    fun pseudoCX86IntegerSseBitwiseAndPacked() {
        val out = NativePseudo.forFunction("f", listOf(
            "f:",
            "00001000: 660febc1    por     xmm0, xmm1",
            "00001004: 660fdbc1    pand    xmm0, xmm1",
            "00001008: 660fdfc1    pandn   xmm0, xmm1",
            "0000100c: 660fefc2    pxor    xmm0, xmm2",
            "00001010: 660ffec1    paddd   xmm0, xmm1",
            "00001014: 660ffac1    psubd   xmm0, xmm1",
            "00001018: 660f3840c1  pmulld  xmm0, xmm1",
            "0000101c: 0f50c0      movmskps eax, xmm0",
            "00001020: 660fd7c0    pmovmskb eax, xmm0",
            "00001024: c3          ret",
        ), x86Is32 = true)
        assertTrue(out.contains("xmm0 |= xmm1"), "por:\n$out")
        assertTrue(out.contains("xmm0 &= xmm1"), "pand:\n$out")
        assertTrue(out.contains("xmm0 = ~xmm0 & xmm1"), "pandn:\n$out")
        assertTrue(out.contains("xmm0 ^= xmm2"), "pxor non-self:\n$out")
        assertTrue(out.contains("xmm0 = vadd(xmm0, xmm1)"), "paddd:\n$out")
        assertTrue(out.contains("xmm0 = vsub(xmm0, xmm1)"), "psubd:\n$out")
        assertTrue(out.contains("xmm0 = vmul(xmm0, xmm1)"), "pmulld:\n$out")
        assertTrue(out.contains("eax = movmsk(xmm0)"), "movmskps:\n$out")
        assertTrue(out.contains("eax = pmovmskb(xmm0)"), "pmovmskb:\n$out")
        assertFalse(out.contains("pandn xmm"), "no raw passthrough:\n$out")
    }

    @Test
    fun pseudoCX86X87StackOps() {
        val out = NativePseudo.forFunction("f", listOf(
            "f:",
            "00001000: db00        fild    dword ptr [eax]",
            "00001004: d900        fld     dword ptr [eax]",
            "00001008: d8c1        fadd    st(1)",
            "0000100a: d8ca        fmul    st(2)",
            "0000100c: d8f1        fdiv    st(1)",
            "0000100e: dbf1        fcomi   st(1)",
            "00001010: dbea        fucomi  st(2)",
            "00001012: db18        fistp   dword ptr [eax]",
            "00001016: d918        fstp    dword ptr [eax]",
            "0000101a: c3          ret",
        ), x86Is32 = true)
        assertTrue(out.contains("st0 = *eax"), "fild/fld push:\n$out")
        assertTrue(out.contains("st0 += st(1)"), "fadd implicit st0:\n$out")
        assertTrue(out.contains("st0 *= st(2)"), "fmul implicit st0:\n$out")
        assertTrue(out.contains("st0 /= st(1)"), "fdiv implicit st0:\n$out")
        assertTrue(out.contains("__fcmp(st0, st(1))"), "fcomi:\n$out")
        assertTrue(out.contains("__fcmp(st0, st(2))"), "fucomi:\n$out")
        assertTrue(out.contains("*eax = (long)st0"), "fistp:\n$out")
        assertTrue(out.contains("*eax = st0"), "fstp:\n$out")
        assertFalse(out.contains("fadd st"), "no raw passthrough:\n$out")
    }

    @Test
    fun pseudoCX86RotateCarryAndCpuid() {
        val out = NativePseudo.forFunction("f", listOf(
            "f:",
            "00001000: c1d003      rcl     eax, 3",
            "00001003: d3d8        rcr     eax, cl",
            "00001005: 0f31        rdtsc",
            "00001007: 0fa2        cpuid",
            "00001009: c3          ret",
        ), x86Is32 = true)
        assertTrue(out.contains("eax = rcl(eax, 3)"), "rcl:\n$out")
        assertTrue(out.contains("eax = rcr(eax, cl)"), "rcr:\n$out")
        assertTrue(out.contains("edx:eax = __rdtsc()"), "rdtsc:\n$out")
        assertTrue(out.contains("__cpuid()"), "cpuid:\n$out")
        assertFalse(out.contains("rcl eax"), "no raw passthrough:\n$out")
    }

    @Test
    fun pseudoCMipsLogicalVsArithmeticShift() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 srl     \$v0, \$a0, 0x3",
            "00001004: 00000000 sra     \$v1, \$a1, 0x3",
            "00001008: 00000000 srlv    \$t0, \$a2, \$a3",
            "0000100c: 00000000 jr      \$ra",
            "00001010: 00000000 nop",
        ))
        assertTrue(out.contains("\$v0 = (unsigned)\$a0 >> 0x3"), "srl is a logical (unsigned) shift:\n$out")
        assertTrue(out.contains("\$v1 = \$a1 >> 0x3"), "sra is an arithmetic (signed) shift:\n$out")
        assertTrue(out.contains("\$t0 = (unsigned)\$a2 >> \$a3"), "srlv is a logical (unsigned) shift:\n$out")
    }

    @Test
    fun pseudoCMips64DoublewordArithmeticAndShifts() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 daddu   \$v0, \$a0, \$a1",
            "00001004: 00000000 dsubu   \$v1, \$a0, \$a1",
            "00001008: 00000000 dsll    \$t0, \$a0, 0x5",
            "0000100c: 00000000 dsrl    \$t1, \$a0, 0x5",
            "00001010: 00000000 dsra    \$t2, \$a0, 0x5",
            "00001014: 00000000 dsll32  \$t3, \$a0, 0x8",
            "00001018: 00000000 dsrl32  \$t4, \$a0, 0x8",
            "0000101c: 00000000 jr      \$ra",
            "00001020: 00000000 nop",
        ))
        assertTrue(out.contains("\$v0 = \$a0 + \$a1"), "daddu:\n$out")
        assertTrue(out.contains("\$v1 = \$a0 - \$a1"), "dsubu:\n$out")
        assertTrue(out.contains("\$t0 = \$a0 << 0x5"), "dsll:\n$out")
        assertTrue(out.contains("\$t1 = (uint64_t)\$a0 >> 0x5"), "dsrl is logical:\n$out")
        assertTrue(out.contains("\$t2 = \$a0 >> 0x5"), "dsra is arithmetic:\n$out")
        assertTrue(out.contains("\$t3 = \$a0 << (0x8 + 32)"), "dsll32 adds 32 to shift amount:\n$out")
        assertTrue(out.contains("\$t4 = (uint64_t)\$a0 >> (0x8 + 32)"), "dsrl32 adds 32 to shift amount:\n$out")
    }

    @Test
    fun pseudoCMips64ClzAndByteSwaps() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 dclz    \$v0, \$a0",
            "00001004: 00000000 dsbh    \$v1, \$a0",
            "00001008: 00000000 dshd    \$t0, \$a0",
            "0000100c: 00000000 bitswap \$t1, \$a0",
            "00001010: 00000000 jr      \$ra",
            "00001014: 00000000 nop",
        ))
        assertTrue(out.contains("\$v0 = clz(\$a0)"), "dclz:\n$out")
        assertTrue(out.contains("\$v1 = dsbh(\$a0)"), "dsbh:\n$out")
        assertTrue(out.contains("\$t0 = dshd(\$a0)"), "dshd:\n$out")
        assertTrue(out.contains("\$t1 = rbit(\$a0)"), "bitswap:\n$out")
        assertFalse(out.contains("dclz \$") || out.contains("dsbh \$"), "must not pass through raw:\n$out")
    }

    @Test
    fun pseudoCMipsR6DivModAndSelects() {
        val out = NativePseudo.forFunction("f", listOf(
            "00001000: 00000000 div     \$v0, \$a0, \$a1",
            "00001004: 00000000 modu    \$v1, \$a0, \$a1",
            "00001008: 00000000 mod     \$t0, \$a0, \$a1",
            "0000100c: 00000000 seleqz  \$t1, \$a2, \$a3",
            "00001010: 00000000 selnez  \$t2, \$a2, \$a3",
            "00001014: 00000000 jr      \$ra",
            "00001018: 00000000 nop",
        ))
        assertTrue(out.contains("\$v0 = \$a0 / \$a1"), "r6 div writes quotient to rd:\n$out")
        assertTrue(out.contains("\$v1 = (unsigned)\$a0 % (unsigned)\$a1"), "modu:\n$out")
        assertTrue(out.contains("\$t0 = \$a0 % \$a1"), "mod:\n$out")
        assertTrue(out.contains("\$t1 = (\$a3 == 0) ? \$a2 : 0"), "seleqz:\n$out")
        assertTrue(out.contains("\$t2 = (\$a3 != 0) ? \$a2 : 0"), "selnez:\n$out")
    }

    @Test
    fun pseudoCMipsPreR6DivStillUsesHiLo() {
        val out = NativePseudo.forFunction("sd", listOf(
            "00001000: 00000000 div     \$zero, \$a0, \$a1",
            "00001004: 00000000 mflo    \$v0",
            "00001008: 00000000 jr      \$ra",
            "0000100c: 00000000 nop",
        ))
        assertTrue(out.contains("\$a0 / \$a1"), "pre-r6 div quotient comes from the dividend/divisor:\n$out")
        assertFalse(out.contains("\$zero = \$a0 / \$a1"), "pre-r6 div must not write to the zero placeholder:\n$out")
    }

    @Test
    fun pseudoCTranslatesAvxScalarArith() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 vaddsd  xmm0, xmm0, xmm1",
            "00005008: 00 vsubss  xmm0, xmm0, xmm1",
            "00005010: 00 vmulsd  xmm0, xmm0, xmm1",
            "00005018: 00 vdivss  xmm0, xmm0, xmm1",
            "00005020: 00 ret",
        ), x86Is32 = false)
        assertTrue(out.contains("xmm0 = xmm0 + xmm1"), "vaddsd is 3-operand non-destructive add:\n$out")
        assertTrue(out.contains("xmm0 = xmm0 - xmm1"), "vsubss:\n$out")
        assertTrue(out.contains("xmm0 = xmm0 * xmm1"), "vmulsd:\n$out")
        assertTrue(out.contains("xmm0 = xmm0 / xmm1"), "vdivss:\n$out")
        assertFalse(out.contains("vaddsd") || out.contains("vmulsd") || out.contains("vdivss"),
            "AVX scalar arith must not pass through raw:\n$out")
    }

    @Test
    fun pseudoCTranslatesAvxFma() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 vfmadd213sd xmm0, xmm1, xmm2",
            "00005008: 00 vfmadd132ss xmm0, xmm1, xmm2",
            "00005010: 00 vfmadd231sd xmm0, xmm1, xmm2",
            "00005018: 00 vfnmadd213sd xmm0, xmm1, xmm2",
            "00005020: 00 vfmsub213sd xmm0, xmm1, xmm2",
            "00005028: 00 vfnmsub213sd xmm0, xmm1, xmm2",
            "00005030: 00 ret",
        ), x86Is32 = false)
        assertTrue(out.contains("xmm0 = xmm1 * xmm0 + xmm2"), "vfmadd213: dst = src2*dst + src3:\n$out")
        assertTrue(out.contains("xmm0 = xmm0 * xmm2 + xmm1"), "vfmadd132: dst = dst*src3 + src2:\n$out")
        assertTrue(out.contains("xmm0 = xmm1 * xmm2 + xmm0"), "vfmadd231: dst = src2*src3 + dst:\n$out")
        assertTrue(out.contains("xmm0 = -(xmm1 * xmm0) + xmm2"), "vfnmadd213:\n$out")
        assertTrue(out.contains("xmm0 = xmm1 * xmm0 - xmm2"), "vfmsub213:\n$out")
        assertTrue(out.contains("xmm0 = -(xmm1 * xmm0) - xmm2"), "vfnmsub213:\n$out")
        assertFalse(out.contains("vfmadd") || out.contains("vfnmadd") || out.contains("vfmsub"),
            "FMA must not pass through raw:\n$out")
    }

    @Test
    fun pseudoCTranslatesAvxCvtAndMove() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 vcvtsi2sd xmm0, xmm15, rdi",
            "00005008: 00 vcvtsi2ss xmm0, xmm15, rsi",
            "00005010: 00 vcvtsd2ss xmm0, xmm0, xmm0",
            "00005018: 00 vcvttsd2si rax, xmm0",
            "00005020: 00 vmovsd  xmm1, qword ptr [rdi]",
            "00005028: 00 vmovaps xmm2, xmm1",
            "00005030: 00 ret",
        ), x86Is32 = false)
        assertTrue(out.contains("xmm0 = (double)rdi"), "vcvtsi2sd drops the VEX merge operand:\n$out")
        assertTrue(out.contains("xmm0 = (float)rsi"), "vcvtsi2ss:\n$out")
        assertTrue(out.contains("xmm0 = (float)xmm0"), "vcvtsd2ss:\n$out")
        assertTrue(out.contains("rax = (long)xmm0"), "vcvttsd2si:\n$out")
        assertTrue(out.contains("xmm1 = *rdi"), "vmovsd load:\n$out")
        assertTrue(out.contains("xmm2 = xmm1"), "vmovaps:\n$out")
        assertFalse(out.contains("vcvtsi2sd") || out.contains("vmovsd") || out.contains("vmovaps"),
            "AVX cvt/move must not pass through raw:\n$out")
    }

    @Test
    fun pseudoCTranslatesAvxMinMaxSqrtRoundAndn() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 vmaxsd  xmm0, xmm0, xmm1",
            "00005008: 00 vminsd  xmm0, xmm0, xmm1",
            "00005010: 00 vsqrtsd xmm0, xmm0, xmm0",
            "00005018: 00 vroundsd xmm0, xmm0, xmm0, 0xc",
            "00005020: 00 vandnps xmm0, xmm0, xmm1",
            "00005028: 00 ret",
        ), x86Is32 = false)
        assertTrue(out.contains("xmm0 = fmax(xmm0, xmm1)"), "vmaxsd => fmax:\n$out")
        assertTrue(out.contains("xmm0 = fmin(xmm0, xmm1)"), "vminsd => fmin:\n$out")
        assertTrue(out.contains("xmm0 = sqrt(xmm0)"), "vsqrtsd:\n$out")
        assertTrue(out.contains("xmm0 = round(xmm0)"), "vroundsd drops the rounding-mode imm:\n$out")
        assertTrue(out.contains("xmm0 = ~xmm0 & xmm1"), "vandnps is (~src1)&src2:\n$out")
        assertFalse(out.contains("vmaxsd") || out.contains("vsqrtsd") || out.contains("vandnps"),
            "AVX min/max/sqrt/round/andn must not pass through raw:\n$out")
    }

    @Test
    fun pseudoCTranslatesSseMinMaxRoundAndn() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 maxsd   xmm2, xmm0",
            "00005008: 00 minsd   xmm2, xmm0",
            "00005010: 00 roundsd xmm0, xmm0, 0xc",
            "00005018: 00 andnps  xmm0, xmm1",
            "00005020: 00 ret",
        ), x86Is32 = false)
        assertTrue(out.contains("xmm2 = fmax(xmm2, xmm0)"), "maxsd => fmax:\n$out")
        assertTrue(out.contains("xmm2 = fmin(xmm2, xmm0)"), "minsd => fmin:\n$out")
        assertTrue(out.contains("xmm0 = round(xmm0)"), "roundsd drops the imm:\n$out")
        assertTrue(out.contains("xmm0 = ~xmm0 & xmm1"), "andnps is (~dst)&src:\n$out")
        assertFalse(out.contains("maxsd") || out.contains("minsd") || out.contains("roundsd") || out.contains("andnps"),
            "SSE min/max/round/andn must not pass through raw:\n$out")
    }

    private fun armR8Pseudo(words: List<Long>, thumb: Boolean = false): String {
        assumeTrue(CapstoneDisassembler.available(), "capstone not available")
        val lines = ArrayList<String>()
        lines.add("f:")
        for (w in words) {
            val code = byteArrayOf(
                (w and 0xff).toByte(), ((w shr 8) and 0xff).toByte(),
                ((w shr 16) and 0xff).toByte(), ((w shr 24) and 0xff).toByte(),
            )
            val i = CapstoneDisassembler.disassemble(code, 0x1000, ElfArch.ARM, thumb = thumb).firstOrNull()
            assumeTrue(i != null, "word ${w.toString(16)} did not decode")
            lines.add("%08x: %08x %s %s".format(i!!.address, w, i.mnemonic, i.operands))
        }
        return NativePseudo.forFunction("f", lines)
    }

    @Test
    fun pseudoCArmDspDualAndWideMultiplies() {
        val out = armR8Pseudo(listOf(
            0xe703f213L, 0xe703f253L, 0xe12302a3L, 0xe12302e3L,
            0xe1231283L, 0xe12312c3L, 0xe753f213L, 0xe7531213L,
        ))
        assertTrue(out.contains("r3 = __smuad(r3, r2)"), "smuad:\n$out")
        assertTrue(out.contains("r3 = __smusd(r3, r2)"), "smusd:\n$out")
        assertTrue(out.contains("r3 = ((int64_t)r3 * (int16_t)r2) >> 16"), "smulwb:\n$out")
        assertTrue(out.contains("r3 = ((int64_t)r3 * ((int32_t)r2 >> 16)) >> 16"), "smulwt:\n$out")
        assertTrue(out.contains("r3 = r1 + (((int64_t)r3 * (int16_t)r2) >> 16)"), "smlawb:\n$out")
        assertTrue(out.contains("r3 = r1 + (((int64_t)r3 * ((int32_t)r2 >> 16)) >> 16)"), "smlawt:\n$out")
        assertTrue(out.contains("r3 = ((int64_t)r3 * r2) >> 32"), "smmul:\n$out")
        assertTrue(out.contains("r3 = r1 + (((int64_t)r3 * r2) >> 32)"), "smmla:\n$out")
        assertFalse(Regex("""\b(smuad|smusd|smulw[bt]|smlaw[bt]|smmul|smmla)\b""").containsMatchIn(out), "no raw passthrough:\n$out")
    }

    @Test
    fun pseudoCArmSadSaturateAndPack() {
        val out = armR8Pseudo(listOf(
            0xe783f213L, 0xe7831213L, 0xe6ab3013L, 0xe6ec3013L,
            0xe6ab3f33L, 0xe6ec3f33L, 0xe6833012L, 0xe6833852L, 0xe1a03063L,
        ))
        assertTrue(out.contains("r3 = __usad8(r3, r2)"), "usad8:\n$out")
        assertTrue(out.contains("r3 = r1 + __usad8(r3, r2)"), "usada8:\n$out")
        assertTrue(out.contains("r3 = __ssat(r3, 0xc)"), "ssat:\n$out")
        assertTrue(out.contains("r3 = __usat(r3, 0xc)"), "usat:\n$out")
        assertTrue(out.contains("r3 = __ssat16(r3, 0xc)"), "ssat16:\n$out")
        assertTrue(out.contains("r3 = __usat16(r3, 0xc)"), "usat16:\n$out")
        assertTrue(out.contains("r3 = (r3 & 0xffff) | (r2 & 0xffff0000)"), "pkhbt:\n$out")
        assertTrue(out.contains("r3 = (r3 & 0xffff0000) | ((r2 >> 0x10) & 0xffff)"), "pkhtb:\n$out")
        assertTrue(out.contains("r3 = (r3 >> 1) | (carry << 31)"), "rrx:\n$out")
        assertFalse(Regex("""\b(usad8|usada8|ssat|usat|ssat16|usat16|pkhbt|pkhtb|rrx)\b""").containsMatchIn(out), "no raw passthrough:\n$out")
    }

    @Test
    fun pseudoCArmVfpFusedRoundMinMaxSelect() {
        val out = armR8Pseudo(listOf(
            0xeed77a66L, 0xeed77a26L, 0xeef67ae7L, 0xeef67a67L,
            0xfefb7a67L, 0xfefa7a67L, 0xfef87a67L, 0xfef97a67L,
            0xfec77a87L, 0xfec77ac7L, 0xfe777a87L, 0xfe477a87L,
            0xeef37a67L, 0xeef27a67L,
        ))
        assertTrue(out.contains("s15 = -s15 - s14 * s13"), "vfnma:\n$out")
        assertTrue(out.contains("s15 = -s15 + s14 * s13"), "vfnms:\n$out")
        assertTrue(out.contains("s15 = trunc(s15)"), "vrintz:\n$out")
        assertTrue(out.contains("s15 = rint(s15)"), "vrintr/vrintn:\n$out")
        assertTrue(out.contains("s15 = floor(s15)"), "vrintm:\n$out")
        assertTrue(out.contains("s15 = ceil(s15)"), "vrintp:\n$out")
        assertTrue(out.contains("s15 = round(s15)"), "vrinta:\n$out")
        assertTrue(out.contains("s15 = fmax(s15, s14)"), "vmaxnm:\n$out")
        assertTrue(out.contains("s15 = fmin(s15, s14)"), "vminnm:\n$out")
        assertTrue(out.contains("? s15 : s14"), "vsel:\n$out")
        assertTrue(out.contains("s15 = __f32_to_f16(s15)"), "vcvtb.f16.f32:\n$out")
        assertTrue(out.contains("s15 = __f16_to_f32(s15)"), "vcvtb.f32.f16:\n$out")
        assertFalse(Regex("""\b(vfnma|vfnms|vrint[zrxmpan]|vmaxnm|vminnm|vsel[a-z][a-z]|vcvt[bt])\b""").containsMatchIn(out), "no raw passthrough:\n$out")
    }

    @Test
    fun pseudoCArmUserModeLoadKeepsSubwordCast() {
        val out = armR8Pseudo(listOf(0xe4f33000L, 0xe0f330b0L))
        assertTrue(out.contains("r3 = (uint8_t)*r3"), "ldrbt must keep byte cast:\n$out")
        assertTrue(out.contains("r3 = (uint16_t)*r3"), "ldrht must keep halfword cast:\n$out")
        assertFalse(out.contains("r3 = *r3;"), "must not widen sub-word user-mode load:\n$out")
    }

    @Test
    fun pseudoCDetectsX86FromYmmOnlyBody() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 vaddps  ymm0, ymm0, ymm1",
            "00005008: 00 vmulpd  ymm2, ymm2, ymm3",
            "00005010: 00 ret",
        ), x86Is32 = false)
        assertTrue(out.contains("ymm0 = vadd(ymm0, ymm1)"), "ymm-only AVX body must be detected as x86:\n$out")
        assertTrue(out.contains("ymm2 = vmul(ymm2, ymm3)"), "vmulpd ymm:\n$out")
        assertFalse(out.contains("vaddps") || out.contains("vmulpd"), "ymm-only x86 must not be misdetected as ARM and left raw:\n$out")
    }

    @Test
    fun pseudoCAvxFmaddsubIsNotPlainFma() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 vfmaddsub213ps ymm0, ymm1, ymm2",
            "00005008: 00 vfmaddsub132pd ymm0, ymm1, ymm2",
            "00005010: 00 vfmaddsub231ps ymm0, ymm1, ymm2",
            "00005018: 00 vfmsubadd213ps ymm0, ymm1, ymm2",
            "00005020: 00 vfmsubadd231pd ymm0, ymm1, ymm2",
            "00005028: 00 ret",
        ), x86Is32 = false)
        assertTrue(out.contains("ymm0 = __fmaddsub(ymm1 * ymm0, ymm2)"), "fmaddsub213: alternating, not plain add:\n$out")
        assertTrue(out.contains("ymm0 = __fmaddsub(ymm0 * ymm2, ymm1)"), "fmaddsub132 operand order:\n$out")
        assertTrue(out.contains("ymm0 = __fmaddsub(ymm1 * ymm2, ymm0)"), "fmaddsub231 operand order:\n$out")
        assertTrue(out.contains("ymm0 = __fmsubadd(ymm1 * ymm0, ymm2)"), "fmsubadd213:\n$out")
        assertTrue(out.contains("ymm0 = __fmsubadd(ymm1 * ymm2, ymm0)"), "fmsubadd231:\n$out")
        assertFalse(out.contains("ymm0 = ymm1 * ymm0 + ymm2"), "fmaddsub must not collapse to a plain fmadd:\n$out")
        assertFalse(out.contains("vfmaddsub") || out.contains("vfmsubadd"), "no raw passthrough:\n$out")
    }

    @Test
    fun pseudoCAvxBroadcastBlendPermPtest() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 vbroadcastss ymm0, dword ptr [rdi]",
            "00005008: 00 vpbroadcastd ymm0, xmm0",
            "00005010: 00 vbroadcastsd ymm0, qword ptr [rdi]",
            "00005018: 00 vblendvps ymm0, ymm0, ymm1, ymm2",
            "00005020: 00 vblendps ymm0, ymm0, ymm1, 0x5",
            "00005028: 00 vinsertf128 ymm0, ymm0, xmm1, 0x1",
            "00005030: 00 vextractf128 xmm0, ymm0, 0x1",
            "00005038: 00 vperm2f128 ymm0, ymm0, ymm1, 0x20",
            "00005040: 00 vpermilps ymm0, ymm0, 0x1b",
            "00005048: 00 vmovmskps eax, ymm0",
            "00005050: 00 vptest ymm0, ymm1",
            "00005058: 00 ptest xmm0, xmm1",
            "00005060: 00 ret",
        ), x86Is32 = false)
        assertTrue(out.contains("ymm0 = broadcast(*rdi)"), "vbroadcastss is a broadcast load:\n$out")
        assertTrue(out.contains("ymm0 = broadcast(xmm0)"), "vpbroadcastd broadcasts a register:\n$out")
        assertTrue(out.contains("ymm0 = blendv(ymm0, ymm1, ymm2)"), "vblendvps variable blend:\n$out")
        assertTrue(out.contains("ymm0 = blend(ymm0, ymm1, 0x5)"), "vblendps imm blend:\n$out")
        assertTrue(out.contains("ymm0 = insert128(ymm0, xmm1, 0x1)"), "vinsertf128:\n$out")
        assertTrue(out.contains("xmm0 = extract128(ymm0, 0x1)"), "vextractf128:\n$out")
        assertTrue(out.contains("ymm0 = perm2(ymm0, ymm1, 0x20)"), "vperm2f128:\n$out")
        assertTrue(out.contains("ymm0 = permil(ymm0, 0x1b)"), "vpermilps:\n$out")
        assertTrue(out.contains("eax = movmsk(ymm0)"), "vmovmskps parity with movmskps:\n$out")
        assertTrue(out.contains("__ptest(ymm0, ymm1)"), "vptest:\n$out")
        assertTrue(out.contains("__ptest(xmm0, xmm1)"), "ptest:\n$out")
        assertFalse(Regex("""\b(vbroadcast|vpbroadcast|vblend|vinsertf128|vextractf128|vperm2f128|vpermilps|vmovmskps|vptest|ptest)\b""").containsMatchIn(out),
            "AVX broadcast/blend/perm/ptest must not pass through raw:\n$out")
    }

    @Test
    fun pseudoCArmParallelSimd() {
        val out = armR8Pseudo(listOf(
            0xe6233f12L, 0xe6233f72L, 0xe6133f12L, 0xe6333f12L,
            0xe6733f92L, 0xe6633f92L, 0xe6233f52L, 0xe6233f32L,
        ))
        assertTrue(out.contains("r3 = __qadd16(r3, r2)"), "qadd16:\n$out")
        assertTrue(out.contains("r3 = __qsub16(r3, r2)"), "qsub16:\n$out")
        assertTrue(out.contains("r3 = __sadd16(r3, r2)"), "sadd16:\n$out")
        assertTrue(out.contains("r3 = __shadd16(r3, r2)"), "shadd16:\n$out")
        assertTrue(out.contains("r3 = __uhadd8(r3, r2)"), "uhadd8:\n$out")
        assertTrue(out.contains("r3 = __uqadd8(r3, r2)"), "uqadd8:\n$out")
        assertTrue(out.contains("r3 = __qsax(r3, r2)"), "qsax:\n$out")
        assertTrue(out.contains("r3 = __qasx(r3, r2)"), "qasx:\n$out")
        assertFalse(Regex("""\b(qadd16|qsub16|sadd16|shadd16|uhadd8|uqadd8|qsax|qasx)\b""").containsMatchIn(out), "no raw passthrough:\n$out")
    }

    @Test
    fun pseudoCArmCoprocessor() {
        val out = armR8Pseudo(listOf(0xee110f10L, 0xee010f10L, 0xec510f00L, 0xec410f00L))
        assertTrue(out.contains("r0 = __mrc(p15, 0, c1, c0, 0)"), "mrc:\n$out")
        assertTrue(out.contains("__mcr(p15, 0, r0, c1, c0, 0)"), "mcr:\n$out")
        assertTrue(out.contains("r0, r1 = __mrrc(p15, 0, c0)"), "mrrc:\n$out")
        assertTrue(out.contains("__mcrr(p15, 0, r0, r1, c0)"), "mcrr:\n$out")
        assertFalse(Regex("""(?m)^\s*(mrc|mcr|mrrc|mcrr)\b""").containsMatchIn(out), "no raw passthrough:\n$out")
    }

    @Test
    fun pseudoCArmHintsAndSystem() {
        val out = armR8Pseudo(listOf(
            0xf1010200L, 0xe320f001L, 0xe320f002L, 0xe320f003L, 0xe320f004L, 0xe320f0ffL,
            0xf10c0080L, 0xf8cd0500L, 0xf8930a00L,
        ))
        assertFalse(Regex("""\b(setend|yield|wfe|wfi|sev|dbg|cpsid|cpsie|srsia|rfeia)\b""").containsMatchIn(out), "hints/system must not pass through raw:\n$out")
        assertTrue(out.contains("__srs(sp, 0)"), "srs:\n$out")
        assertTrue(out.contains("__rfe(r3)"), "rfe:\n$out")
    }

    private fun armThumbPseudo(hexWords: List<String>): String {
        assumeTrue(CapstoneDisassembler.available(), "capstone not available")
        val clean = hexWords.joinToString("").replace(" ", "")
        val code = ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        val insns = CapstoneDisassembler.disassemble(code, 0x1000, ElfArch.ARM, thumb = true)
        assumeTrue(insns.isNotEmpty(), "thumb bytes did not decode")
        val lines = ArrayList<String>()
        lines.add("f:")
        for (i in insns) lines.add("%08x: 0000 %s %s".format(i.address, i.mnemonic, i.operands))
        return NativePseudo.forFunction("f", lines)
    }

    @Test
    fun pseudoCArmAcquireReleaseArm() {
        val out = armR8Pseudo(listOf(
            0xe1910c9fL, 0xe1d10c9fL, 0xe1f10c9fL,
            0xe181fc90L, 0xe1c1fc90L, 0xe1e1fc90L,
            0xe1910e9fL, 0xe1d10e9fL, 0xe1f10e9fL,
        ))
        assertTrue(out.contains("r0 = *r1;"), "lda must dereference word:\n$out")
        assertTrue(out.contains("r0 = (uint8_t)*r1;"), "ldab/ldaexb keep byte cast:\n$out")
        assertTrue(out.contains("r0 = (uint16_t)*r1;"), "ldah/ldaexh keep halfword cast:\n$out")
        assertTrue(out.contains("*r1 = r0;"), "stl/stlb/stlh store-release:\n$out")
        assertFalse(Regex("""(?m)^\s*(lda|ldab|ldah|stl|stlb|stlh|ldaex|ldaexb|ldaexh)\b""").containsMatchIn(out),
            "ARMv8 acquire/release must not pass through raw:\n$out")
    }

    @Test
    fun pseudoCArmAcquireReleaseThumb() {
        val out = armThumbPseudo(listOf(
            "d1e8 af0f", "d1e8 8f0f", "d1e8 9f0f",
            "c1e8 af0f", "c1e8 8f0f", "c1e8 9f0f",
            "d1e8 ef0f", "d1e8 cf0f", "d1e8 df0f",
        ))
        assertTrue(out.contains("r0 = *r1;"), "thumb lda must dereference word:\n$out")
        assertTrue(out.contains("r0 = (uint8_t)*r1;"), "thumb ldab/ldaexb keep byte cast:\n$out")
        assertTrue(out.contains("r0 = (uint16_t)*r1;"), "thumb ldah/ldaexh keep halfword cast:\n$out")
        assertTrue(out.contains("*r1 = r0;"), "thumb stl/stlb/stlh store-release:\n$out")
        assertFalse(Regex("""(?m)^\s*(lda|ldab|ldah|stl|stlb|stlh|ldaex|ldaexb|ldaexh)\b""").containsMatchIn(out),
            "thumb ARMv8 acquire/release must not pass through raw:\n$out")
    }

    @Test
    fun pseudoCArmEretIsReturn() {
        val out = armR8Pseudo(listOf(0xe160006eL))
        assertTrue(out.contains("return;"), "eret must be a return, not a wild indirect jump:\n$out")
        assertFalse(out.contains("goto *"), "eret must not emit an empty indirect goto:\n$out")
        assertFalse(Regex("""(?m)^\s*eret\b""").containsMatchIn(out), "eret must not pass through raw:\n$out")
    }

    @Test
    fun pseudoCArmSwapBkptSmcHvc() {
        val out = armR8Pseudo(listOf(
            0xe1020091L, 0xe1420091L, 0xe1200070L, 0xe1400070L, 0xe1600070L,
        ))
        assertTrue(out.contains("r0 = __swp(*r2, r1)"), "swp:\n$out")
        assertTrue(out.contains("r0 = __swpb(*r2, r1)"), "swpb:\n$out")
        assertTrue(out.contains("__break(0)"), "bkpt:\n$out")
        assertTrue(out.contains("__hvc(0)"), "hvc:\n$out")
        assertTrue(out.contains("__smc(0)"), "smc:\n$out")
        assertFalse(Regex("""\b(swp|swpb|bkpt|smc|hvc)\b""").containsMatchIn(out), "no raw passthrough:\n$out")
    }

    @Test
    fun pseudoCX86F16cConvert() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 vcvtph2ps ymm1, xmm0",
            "00005005: 00 vcvtps2ph xmm1, ymm0, 0",
            "0000500c: 00 ret",
        ))
        assertTrue(out.contains("ymm1 = __cvtph2ps(xmm0)"), "vcvtph2ps half->float:\n$out")
        assertTrue(out.contains("xmm1 = __cvtps2ph(ymm0, 0)"), "vcvtps2ph float->half:\n$out")
        assertFalse(Regex("""\bvcvtph2ps\b|\bvcvtps2ph\b""").containsMatchIn(out), "no raw passthrough:\n$out")
    }

    @Test
    fun pseudoCX86Avx512MaskedMerge() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 vaddpd zmm2 {k1}, zmm0, zmm1",
            "00005006: 00 vaddpd zmm3 {k1} {z}, zmm0, zmm1",
            "0000500c: 00 ret",
        ))
        assertTrue(out.contains("zmm2 = __mask_blend(k1, vadd(zmm0, zmm1), zmm2)"), "merge masking keeps dest:\n$out")
        assertTrue(out.contains("zmm3 = __mask_blend(k1, vadd(zmm0, zmm1), 0)"), "zero masking uses 0:\n$out")
        assertFalse(out.contains("{k1}"), "mask decoration must not leak into C:\n$out")
    }

    @Test
    fun pseudoCX86MaskRegisterOps() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 kandw k3, k2, k1",
            "00005004: 00 knotw k2, k1",
            "00005008: 00 korw k3, k2, k1",
            "0000500c: 00 kxorw k3, k2, k1",
            "00005010: 00 kandnw k3, k2, k1",
            "00005014: 00 kmovw eax, k1",
            "00005018: 00 kshiftlw k2, k1, 1",
            "0000501c: 00 kshiftrw k2, k1, 1",
            "00005020: 00 kortestw k2, k1",
            "00005024: 00 kunpckbw k3, k2, k1",
            "00005028: 00 ret",
        ))
        assertTrue(out.contains("k3 = k2 & k1"), "kand:\n$out")
        assertTrue(out.contains("k2 = ~k1"), "knot:\n$out")
        assertTrue(out.contains("k3 = k2 | k1"), "kor:\n$out")
        assertTrue(out.contains("k3 = k2 ^ k1"), "kxor:\n$out")
        assertTrue(out.contains("k3 = ~k2 & k1"), "kandn:\n$out")
        assertTrue(out.contains("eax = k1"), "kmov:\n$out")
        assertTrue(out.contains("k2 = k1 << 1"), "kshiftl:\n$out")
        assertTrue(out.contains("k2 = k1 >> 1"), "kshiftr:\n$out")
        assertTrue(out.contains("__kortest(k2, k1)"), "kortest:\n$out")
        assertTrue(out.contains("k3 = __kunpck(k2, k1)"), "kunpck:\n$out")
        assertFalse(Regex("""\bk(and|andn|not|or|xor|movw|shiftl|shiftr|ortest|unpck)""").containsMatchIn(out), "no raw passthrough:\n$out")
    }

    @Test
    fun pseudoCX86AesAndCarryless() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 aesenc xmm0, xmm1",
            "00005004: 00 aesenclast xmm0, xmm1",
            "00005008: 00 aesdec xmm0, xmm1",
            "0000500c: 00 aesimc xmm0, xmm1",
            "00005010: 00 vaesenc xmm2, xmm0, xmm1",
            "00005014: 00 pclmulqdq xmm0, xmm1, 0x11",
            "00005018: 00 vpclmulqdq xmm2, xmm0, xmm1, 0x11",
            "0000501c: 00 ret",
        ))
        assertTrue(out.contains("xmm0 = __aesenc(xmm0, xmm1)"), "aesenc:\n$out")
        assertTrue(out.contains("xmm0 = __aesenclast(xmm0, xmm1)"), "aesenclast:\n$out")
        assertTrue(out.contains("xmm0 = __aesdec(xmm0, xmm1)"), "aesdec:\n$out")
        assertTrue(out.contains("xmm0 = __aesimc(xmm1)"), "aesimc:\n$out")
        assertTrue(out.contains("xmm2 = __aesenc(xmm0, xmm1)"), "vaesenc 3-operand:\n$out")
        assertTrue(out.contains("xmm0 = __pclmulqdq(xmm0, xmm1, 0x11)"), "pclmulqdq:\n$out")
        assertTrue(out.contains("xmm2 = __pclmulqdq(xmm0, xmm1, 0x11)"), "vpclmulqdq:\n$out")
        assertFalse(Regex("""\b(aesenc|aesdec|aesimc|aesenclast|pclmulqdq)\b""").containsMatchIn(out), "no raw passthrough:\n$out")
    }

    @Test
    fun pseudoCX86ShaIntrinsics() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 sha256rnds2 xmm3, xmm1, xmm0",
            "00005004: 00 sha256msg1 xmm0, xmm1",
            "00005008: 00 sha256msg2 xmm0, xmm1",
            "0000500c: 00 sha1msg1 xmm0, xmm1",
            "00005010: 00 ret",
        ))
        assertTrue(out.contains("xmm3 = __sha256rnds2(xmm3, xmm1, xmm0)"), "sha256rnds2:\n$out")
        assertTrue(out.contains("xmm0 = __sha256msg1(xmm0, xmm1)"), "sha256msg1:\n$out")
        assertTrue(out.contains("xmm0 = __sha256msg2(xmm0, xmm1)"), "sha256msg2:\n$out")
        assertTrue(out.contains("xmm0 = __sha1msg1(xmm0, xmm1)"), "sha1msg1:\n$out")
        assertFalse(Regex("""\bsha(256|1)""").containsMatchIn(out), "no raw passthrough:\n$out")
    }

    @Test
    fun pseudoCX86Avx512MathHelpers() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 vpternlogd zmm0, zmm1, zmm2, 0xca",
            "00005007: 00 vpconflictd zmm1, zmm0",
            "0000500b: 00 vplzcntd zmm1, zmm0",
            "0000500f: 00 vpopcntd zmm1, zmm0",
            "00005013: 00 vscalefpd zmm2, zmm0, zmm1",
            "00005017: 00 vgetexppd zmm1, zmm0",
            "0000501b: 00 vrndscalepd zmm1, zmm0, 0",
            "0000501f: 00 vfixupimmpd zmm0, zmm1, zmm2, 0",
            "00005023: 00 vrcp14pd zmm1, zmm0",
            "00005027: 00 vgf2p8affineqb zmm2, zmm0, zmm1, 0",
            "0000502b: 00 vgf2p8mulb zmm2, zmm0, zmm1",
            "0000502f: 00 ret",
        ))
        assertTrue(out.contains("zmm0 = __vpternlog(zmm0, zmm1, zmm2, 0xca)"), "vpternlog:\n$out")
        assertTrue(out.contains("zmm1 = __vpconflict(zmm0)"), "vpconflict:\n$out")
        assertTrue(out.contains("zmm1 = __vplzcnt(zmm0)"), "vplzcnt:\n$out")
        assertTrue(out.contains("zmm1 = __vpopcnt(zmm0)"), "vpopcnt:\n$out")
        assertTrue(out.contains("zmm2 = __vscalef(zmm0, zmm1)"), "vscalef:\n$out")
        assertTrue(out.contains("zmm1 = __vgetexp(zmm0)"), "vgetexp:\n$out")
        assertTrue(out.contains("zmm1 = __vrndscale(zmm0, 0)"), "vrndscale:\n$out")
        assertTrue(out.contains("zmm0 = __vfixupimm(zmm0, zmm1, zmm2, 0)"), "vfixupimm:\n$out")
        assertTrue(out.contains("zmm1 = __vrcp14(zmm0)"), "vrcp14:\n$out")
        assertTrue(out.contains("zmm2 = __gf2p8affineqb(zmm0, zmm1, 0)"), "gf2p8affine:\n$out")
        assertTrue(out.contains("zmm2 = __gf2p8mulb(zmm0, zmm1)"), "gf2p8mul:\n$out")
        assertFalse(Regex("""\bvp(ternlog|conflict|lzcnt|popcnt)|\bvscalef|\bvgetexp|\bvrndscale|\bvfixupimm|\bvrcp14|\bvgf2p8""").containsMatchIn(out), "no raw passthrough:\n$out")
    }

    @Test
    fun pseudoCX86Avx512CompressGatherMovExtend() {
        val out = NativePseudo.forFunction("f", listOf(
            "00005000: 00 vpcompressd zmm1 {k1}, zmm0",
            "00005006: 00 vpexpandd zmm1 {k1}, zmm0",
            "0000500c: 00 vgatherdps ymm1, ymmword ptr [rdi + ymm0*4], ymm2",
            "00005012: 00 vpmovzxbd ymm1, xmm0",
            "00005017: 00 vpmovsxbd ymm1, xmm0",
            "0000501c: 00 vptestmd k1, zmm0, zmm1",
            "00005022: 00 vmovdqa64 zmm1, zmm0",
            "00005028: 00 bzhi rcx, rbx, rax",
            "0000502c: 00 ret",
        ))
        assertTrue(out.contains("zmm1 = __mask_blend(k1, __vpcompress(zmm0), zmm1)"), "masked vpcompress:\n$out")
        assertTrue(out.contains("zmm1 = __mask_blend(k1, __vpexpand(zmm0), zmm1)"), "masked vpexpand:\n$out")
        assertTrue(out.contains("ymm1 = __vgather("), "vgatherdps:\n$out")
        assertTrue(out.contains("ymm1 = __vpmovzx(xmm0)"), "vpmovzx:\n$out")
        assertTrue(out.contains("ymm1 = __vpmovsx(xmm0)"), "vpmovsx:\n$out")
        assertTrue(out.contains("k1 = __vptestm(zmm0, zmm1)"), "vptestm into mask:\n$out")
        assertTrue(out.contains("zmm1 = zmm0"), "vmovdqa64 is a move:\n$out")
        assertTrue(out.contains("rcx = rbx & ((1 << (rax & 0xff)) - 1)"), "bzhi:\n$out")
        assertFalse(Regex("""\bvp(compressd|expandd|movzxbd|movsxbd|testmd)|\bvgatherdps|\bvmovdqa64|\bbzhi""").containsMatchIn(out), "no raw passthrough:\n$out")
    }
}
