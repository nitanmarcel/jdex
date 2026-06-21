package io.github.nitanmarcel.jdex.disasm

import com.sun.jna.NativeLong
import com.sun.jna.Structure
import com.sun.jna.ptr.LongByReference
import com.sun.jna.ptr.PointerByReference

object CapstoneDisassembler : Disassembler {
    override val id = "capstone"
    override val displayName = "Capstone"

    private const val MODE_BIG_ENDIAN = 1 shl 31
    private const val OPT_SYNTAX = 1
    private const val OPT_SYNTAX_INTEL = 1

    private fun archMode(arch: ElfArch, thumb: Boolean): Pair<Int, Int>? = when (arch) {
        ElfArch.ARM -> 0 to (if (thumb) 1 shl 4 else 0)
        ElfArch.ARM64 -> 1 to 0
        ElfArch.X86 -> 3 to (1 shl 2)
        ElfArch.X86_64 -> 3 to (1 shl 3)
        ElfArch.MIPS -> 2 to (1 shl 2)
        ElfArch.MIPS64 -> 2 to (1 shl 3)
        ElfArch.UNKNOWN -> null
    }

    override fun supports(arch: ElfArch) = archMode(arch, false) != null

    override fun available(): Boolean = runCatching { CapstoneLib.INSTANCE }.isSuccess

    override fun disassemble(code: ByteArray, baseAddr: Long, arch: ElfArch, thumb: Boolean, littleEndian: Boolean): List<Insn> {
        val (csArch, baseMode) = archMode(arch, thumb) ?: return emptyList()
        val mode = if (littleEndian) baseMode else baseMode or MODE_BIG_ENDIAN
        val lib = CapstoneLib.INSTANCE
        val handle = LongByReference()
        if (lib.cs_open(csArch, mode, handle) != 0) return emptyList()
        try {
            if (arch == ElfArch.X86 || arch == ElfArch.X86_64) lib.cs_option(handle.value, OPT_SYNTAX, NativeLong(OPT_SYNTAX_INTEL.toLong()))
            val ref = PointerByReference()
            val count = lib.cs_disasm(handle.value, code, NativeLong(code.size.toLong()), baseAddr, NativeLong(0), ref).toLong()
            if (count <= 0) return emptyList()
            try {
                val first = Structure.newInstance(CsInsn::class.java, ref.value).apply { read() }
                val array = first.toArray(count.toInt())
                val out = ArrayList<Insn>(count.toInt())
                for (entry in array) {
                    val insn = entry as CsInsn
                    val len = insn.size.toInt() and 0xFFFF
                    out.add(Insn(insn.address, len, insn.bytes.copyOf(len.coerceAtMost(insn.bytes.size)), cstr(insn.mnemonic), cstr(insn.opStr)))
                }
                return out
            } finally {
                lib.cs_free(ref.value, NativeLong(count))
            }
        } finally {
            lib.cs_close(handle)
        }
    }

    private fun cstr(b: ByteArray): String {
        var n = 0
        while (n < b.size && b[n].toInt() != 0) n++
        return String(b, 0, n, Charsets.US_ASCII)
    }
}
