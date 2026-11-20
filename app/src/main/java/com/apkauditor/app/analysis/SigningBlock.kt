package com.apkauditor.app.analysis

import java.io.File
import java.io.RandomAccessFile

/**
 * Detecta el bloque de firma APK (esquemas v2/v3) buscando su firma mágica
 * justo antes del directorio central del ZIP. Sin él, el APK solo trae
 * firma v1 (JAR). Nunca lanza: ante cualquier anomalía devuelve false.
 */
object SigningBlock {

    const val MAGIC = "APK Sig Block 42"
    private const val EOCD_SIG = 0x06054B50
    private const val MAGIC_LEN = 16

    fun hasSigningBlock(apk: File): Boolean {
        return try {
            check(apk)
        } catch (e: Exception) {
            false
        }
    }

    private fun check(apk: File): Boolean {
        val len = apk.length()
        if (len < 22 + 32) return false
        RandomAccessFile(apk, "r").use { f ->
            // EOCD: buscar hacia atrás desde el final (comentario ≤ 64KB).
            val tail = minOf(len, 65557L + 22).toInt()
            val buf = ByteArray(tail)
            f.seek(len - tail)
            f.readFully(buf)
            var eocd = -1
            var i = buf.size - 22
            while (i >= 0) {
                if (le32(buf, i) == EOCD_SIG) {
                    // El comentario puede traer la firma: validar su largo.
                    val commentLen = le16(buf, i + 20)
                    if ((len - tail) + i + 22 + commentLen == len) {
                        eocd = i
                        break
                    }
                }
                i--
            }
            if (eocd < 0) return false
            val cdOff = le32(buf, eocd + 16).toLong() and 0xFFFFFFFFL
            if (cdOff < 32 || cdOff > len) return false
            // [size2:8][magia:16] justo antes del directorio central.
            val probe = ByteArray(8 + MAGIC_LEN)
            f.seek(cdOff - probe.size)
            f.readFully(probe)
            val magic = String(probe, 8, MAGIC_LEN, Charsets.US_ASCII)
            if (magic != MAGIC) return false
            val size2 = le64(probe, 0)
            return size2 >= 32 && size2 <= len
        }
    }

    private fun le16(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or (((b[off + 1].toInt() and 0xFF)) shl 8)

    private fun le32(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or
            (((b[off + 1].toInt() and 0xFF)) shl 8) or
            (((b[off + 2].toInt() and 0xFF)) shl 16) or
            (((b[off + 3].toInt() and 0xFF)) shl 24)

    private fun le64(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 8) {
            v = v or ((b[off + i].toLong() and 0xFF) shl (i * 8))
        }
        return v
    }
}
