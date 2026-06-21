package io.github.nitanmarcel.jdex.disasm

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Pointer
import com.sun.jna.Structure
import com.sun.jna.ptr.LongByReference
import com.sun.jna.ptr.PointerByReference

internal interface CapstoneLib : Library {
    fun cs_open(arch: Int, mode: Int, handle: LongByReference): Int
    fun cs_option(handle: Long, type: Int, value: NativeLong): Int
    fun cs_disasm(handle: Long, code: ByteArray, codeSize: NativeLong, address: Long, count: NativeLong, insn: PointerByReference): NativeLong
    fun cs_free(insn: Pointer, count: NativeLong)
    fun cs_close(handle: LongByReference): Int

    companion object {
        val INSTANCE: CapstoneLib by lazy { Native.load("capstone", CapstoneLib::class.java) }
    }
}

@Structure.FieldOrder("id", "address", "size", "bytes", "mnemonic", "opStr", "detail")
internal open class CsInsn : Structure {
    @JvmField var id: Int = 0
    @JvmField var address: Long = 0
    @JvmField var size: Short = 0
    @JvmField var bytes: ByteArray = ByteArray(24)
    @JvmField var mnemonic: ByteArray = ByteArray(32)
    @JvmField var opStr: ByteArray = ByteArray(160)
    @JvmField var detail: Pointer? = null

    constructor() : super()
    constructor(p: Pointer) : super(p)
}
