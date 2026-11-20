package com.apkauditor.app.analysis

/**
 * Lee la tabla de strings real de un classes.dex (string_ids + string_data_item)
 * en vez de barrer bytes en bruto. Así cada string llega exacta, sin pegarse
 * con sus vecinas, y los detectores no generan falsos positivos por
 * concatenación (p. ej. "http://" + "https://" + "loadUrl"...).
 *
 * Devuelve null si el dex no se puede parsear (formato inesperado, truncado
 * o demasiado grande): el llamador debe usar el barrido en bruto como respaldo.
 * Kotlin puro, sin Android: unit-testeable en JVM.
 */
object DexParser {

    const val MAX_STRINGS = 300_000
    const val MAX_STRING_BYTES = 32 * 1024
    const val MAX_TOTAL_CHARS = 40_000_000

    private const val HEADER_SIZE = 0x70
    private const val OFF_STRING_IDS_SIZE = 0x38
    private const val OFF_STRING_IDS_OFF = 0x3C
    private const val OFF_ENDIAN_TAG = 0x28
    private const val ENDIAN_LE = 0x12345678

    fun readStrings(dex: ByteArray): List<String>? {
        if (dex.size < HEADER_SIZE) return null
        if (dex[0] != 'd'.code.toByte() || dex[1] != 'e'.code.toByte() ||
            dex[2] != 'x'.code.toByte() || dex[3] != '\n'.code.toByte() ||
            dex[7] != 0.toByte()
        ) return null
        if (readU32(dex, OFF_ENDIAN_TAG) != ENDIAN_LE) return null
        val count = readU32(dex, OFF_STRING_IDS_SIZE)
        if (count < 0 || count > MAX_STRINGS) return null
        val tableOff = readU32(dex, OFF_STRING_IDS_OFF)
        if (tableOff < 0 || tableOff > dex.size - count * 4) return null

        val out = ArrayList<String>(minOf(count, 4096))
        var totalChars = 0
        for (i in 0 until count) {
            val itemOff = readU32(dex, tableOff + i * 4)
            if (itemOff < 0 || itemOff >= dex.size) return null
            val s = readMutf8(dex, itemOff) ?: return null
            totalChars += s.length
            if (totalChars > MAX_TOTAL_CHARS) return null
            out.add(s)
        }
        return out
    }

    private fun readU32(b: ByteArray, off: Int): Int {
        if (off < 0 || off > b.size - 4) return -1
        return (b[off].toInt() and 0xFF) or
            ((b[off + 1].toInt() and 0xFF) shl 8) or
            ((b[off + 2].toInt() and 0xFF) shl 16) or
            ((b[off + 3].toInt() and 0xFF) shl 24)
    }

    /** Lee un uleb128; devuelve Pair(valor, siguienteOffset) o null. */
    private fun readUleb128(b: ByteArray, off: Int): Pair<Int, Int>? {
        var result = 0
        var shift = 0
        var pos = off
        repeat(5) {
            if (pos >= b.size) return null
            val v = b[pos++].toInt() and 0xFF
            result = result or ((v and 0x7F) shl shift)
            if ((v and 0x80) == 0) return result to pos
            shift += 7
        }
        return null
    }

    /**
     * Decodifica un string_data_item (MUTF-8: NUL como 0xC0 0x80,
     * secuencias de 1-3 bytes). Trunca a [MAX_STRING_BYTES] sin fallar:
     * cada string tiene su propio offset, así que truncar no pierde el resto.
     */
    private fun readMutf8(b: ByteArray, off: Int): String? {
        val (_, pos) = readUleb128(b, off) ?: return null
        val sb = StringBuilder()
        var p = pos
        val end = minOf(b.size, pos + MAX_STRING_BYTES)
        while (p < end) {
            val a = b[p++].toInt() and 0xFF
            when {
                a == 0x00 -> return sb.toString()
                a < 0x80 -> sb.append(a.toChar())
                (a and 0xE0) == 0xC0 -> {
                    if (p >= end) return sb.toString()
                    val c = b[p++].toInt() and 0xFF
                    if (c == 0x80 && a == 0xC0) sb.append('\u0000')
                    else sb.append((((a and 0x1F) shl 6) or (c and 0x3F)).toChar())
                }
                (a and 0xF0) == 0xE0 -> {
                    if (p + 1 >= end) return sb.toString()
                    val c = b[p++].toInt() and 0xFF
                    val d = b[p++].toInt() and 0xFF
                    sb.append(
                        (((a and 0x0F) shl 12) or ((c and 0x3F) shl 6) or (d and 0x3F)).toChar()
                    )
                }
                else -> sb.append('�')
            }
        }
        return sb.toString()
    }
}
