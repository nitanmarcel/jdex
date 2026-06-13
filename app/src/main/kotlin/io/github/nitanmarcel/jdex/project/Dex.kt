package io.github.nitanmarcel.jdex.project

import java.security.MessageDigest
import java.util.zip.Adler32

object Dex {

    private const val HEADER_SIZE = 0x70
    private const val ENDIAN_TAG = 0x12345678
    private val MAGIC = byteArrayOf(0x64, 0x65, 0x78, 0x0A)
    private val VERSIONS = setOf("035", "037", "038", "039")

    fun isDex(bytes: ByteArray): Boolean =
        bytes.size >= 8 && MAGIC.indices.all { bytes[it] == MAGIC[it] }

    fun parseBroken(bytes: ByteArray): Boolean {
        if (bytes.size < HEADER_SIZE) return true
        if (!validVersion(bytes)) return true
        if (readInt(bytes, 0x24) != HEADER_SIZE) return true
        if (readInt(bytes, 0x28) != ENDIAN_TAG) return true
        return false
    }

    fun validate(bytes: ByteArray): List<String> {
        if (bytes.size < HEADER_SIZE) return listOf("Too small to be a DEX (${bytes.size} bytes, need ≥ $HEADER_SIZE)")
        val problems = mutableListOf<String>()
        when {
            !MAGIC.indices.all { bytes[it] == MAGIC[it] } -> problems += "Bad magic"
            !validVersion(bytes) -> problems += "Unknown DEX version \"${version(bytes)}\""
        }
        if (readInt(bytes, 0x24) != HEADER_SIZE) problems += "Wrong header_size (0x%x)".format(readInt(bytes, 0x24))
        if (readInt(bytes, 0x28) != ENDIAN_TAG) problems += "Wrong endian_tag (0x%08x)".format(readInt(bytes, 0x28))
        if (readInt(bytes, 0x20) != bytes.size) problems += "Wrong file_size (header 0x%x, actual 0x%x)".format(readInt(bytes, 0x20), bytes.size)
        if (readInt(bytes, 0x08) != adler32(bytes)) problems += "Bad checksum"
        if (!sha1(bytes).contentEquals(bytes.copyOfRange(0x0C, 0x20))) problems += "Bad signature"
        return problems
    }

    fun repair(input: ByteArray): ByteArray {
        require(input.size >= HEADER_SIZE) { "Too small to be a DEX (${input.size} bytes)" }
        val bytes = input.copyOf()
        System.arraycopy(MAGIC, 0, bytes, 0, 4)
        if (!validVersion(bytes)) {
            bytes[4] = '0'.code.toByte(); bytes[5] = '3'.code.toByte(); bytes[6] = '5'.code.toByte()
        }
        bytes[7] = 0
        writeInt(bytes, 0x20, bytes.size)
        writeInt(bytes, 0x24, HEADER_SIZE)
        writeInt(bytes, 0x28, ENDIAN_TAG)
        System.arraycopy(sha1(bytes), 0, bytes, 0x0C, 20)
        writeInt(bytes, 0x08, adler32(bytes))
        return bytes
    }

    private fun validVersion(bytes: ByteArray): Boolean =
        MAGIC.indices.all { bytes[it] == MAGIC[it] } && version(bytes) in VERSIONS && bytes[7] == 0.toByte()

    private fun version(bytes: ByteArray): String = String(bytes, 4, 3, Charsets.US_ASCII)

    private fun adler32(bytes: ByteArray): Int {
        val checksum = Adler32()
        checksum.update(bytes, 0x0C, bytes.size - 0x0C)
        return checksum.value.toInt()
    }

    private fun sha1(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-1").digest(bytes.copyOfRange(0x20, bytes.size))

    private fun readInt(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8) or
            ((bytes[offset + 2].toInt() and 0xff) shl 16) or ((bytes[offset + 3].toInt() and 0xff) shl 24)

    private fun writeInt(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value and 0xff).toByte()
        bytes[offset + 1] = ((value ushr 8) and 0xff).toByte()
        bytes[offset + 2] = ((value ushr 16) and 0xff).toByte()
        bytes[offset + 3] = ((value ushr 24) and 0xff).toByte()
    }
}
