package io.github.nitanmarcel.jdex.project

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest

class DexPatch private constructor(
    private val sourceLen: Int,
    private val runs: List<Run>?,
    private val full: ByteArray?,
) {
    private class Run(val offset: Int, val bytes: ByteArray)

    fun apply(source: ByteArray): ByteArray {
        if (full != null) return full.copyOf()
        if (source.size != sourceLen) return source.copyOf()
        val out = source.copyOf()
        runs?.forEach { System.arraycopy(it.bytes, 0, out, it.offset, it.bytes.size) }
        return out
    }

    fun serialize(): ByteArray {
        val bos = ByteArrayOutputStream()
        DataOutputStream(bos).use { out ->
            if (full != null) {
                out.writeByte(1); out.writeInt(full.size); out.write(full)
            } else {
                out.writeByte(0); out.writeInt(sourceLen); out.writeInt(runs!!.size)
                runs.forEach { out.writeInt(it.offset); out.writeInt(it.bytes.size); out.write(it.bytes) }
            }
        }
        return bos.toByteArray()
    }

    companion object {
        fun sha256(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

        fun between(source: ByteArray, target: ByteArray): DexPatch {
            if (source.size != target.size) return DexPatch(source.size, null, target.copyOf())
            val runs = ArrayList<Run>()
            var i = 0
            while (i < source.size) {
                if (source[i] != target[i]) {
                    val start = i
                    while (i < source.size && source[i] != target[i]) i++
                    runs.add(Run(start, target.copyOfRange(start, i)))
                } else {
                    i++
                }
            }
            return DexPatch(source.size, runs, null)
        }

        fun deserialize(data: ByteArray): DexPatch =
            DataInputStream(ByteArrayInputStream(data)).use { input ->
                when (input.readByte().toInt()) {
                    1 -> {
                        val bytes = ByteArray(input.readInt()); input.readFully(bytes)
                        DexPatch(0, null, bytes)
                    }
                    else -> {
                        val sourceLen = input.readInt()
                        val runs = (0 until input.readInt()).map {
                            val offset = input.readInt()
                            val bytes = ByteArray(input.readInt()); input.readFully(bytes)
                            Run(offset, bytes)
                        }
                        DexPatch(sourceLen, runs, null)
                    }
                }
            }
    }
}
