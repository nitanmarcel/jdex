package io.github.nitanmarcel.jdex.disasm

class Insn(
    val address: Long,
    val size: Int,
    val bytes: ByteArray,
    val mnemonic: String,
    val operands: String,
)

interface Disassembler {
    val id: String
    val displayName: String
    fun supports(arch: ElfArch): Boolean
    fun available(): Boolean = true
    fun disassemble(code: ByteArray, baseAddr: Long, arch: ElfArch, thumb: Boolean = false, littleEndian: Boolean = true): List<Insn>
}

object Disassemblers {
    val all: List<Disassembler> = listOf(CapstoneDisassembler)

    fun forId(id: String): Disassembler? = all.firstOrNull { it.id == id }

    fun available(arch: ElfArch): List<Disassembler> = all.filter { it.supports(arch) }
}
