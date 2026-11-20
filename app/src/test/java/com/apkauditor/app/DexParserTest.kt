package com.apkauditor.app

import com.apkauditor.app.analysis.DexParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DexParserTest {

    /** Arma un dex mínimo: cabecera + tabla string_ids + items. */
    private fun buildDex(items: List<ByteArray>): ByteArray {
        val header = ByteArray(0x70)
        "dex\n035\u0000".toByteArray(Charsets.ISO_8859_1).copyInto(header)
        putU32(header, 0x28, 0x12345678) // endian_tag
        putU32(header, 0x38, items.size) // string_ids_size
        putU32(header, 0x3C, 0x70) // string_ids_off
        val table = ByteArray(items.size * 4)
        val blobs = mutableListOf<ByteArray>()
        var off = 0x70 + items.size * 4
        items.forEachIndexed { i, body ->
            putU32(table, i * 4, off)
            val item = byteArrayOf(body.size.toByte()) + body + byteArrayOf(0)
            blobs.add(item)
            off += item.size
        }
        return header + table + blobs.fold(ByteArray(0)) { acc, b -> acc + b }
    }

    private fun putU32(b: ByteArray, off: Int, v: Int) {
        b[off] = (v and 0xFF).toByte()
        b[off + 1] = ((v shr 8) and 0xFF).toByte()
        b[off + 2] = ((v shr 16) and 0xFF).toByte()
        b[off + 3] = ((v shr 24) and 0xFF).toByte()
    }

    @Test
    fun lee_tabla_de_strings() {
        val dex = buildDex(
            listOf("hola", "http://a.bc/x", "").map { it.toByteArray(Charsets.UTF_8) }
        )
        assertEquals(listOf("hola", "http://a.bc/x", ""), DexParser.readStrings(dex))
    }

    @Test
    fun decodifica_mututf8() {
        val cafe = byteArrayOf(
            'c'.code.toByte(), 'a'.code.toByte(), 'f'.code.toByte(),
            0xC3.toByte(), 0xA9.toByte()
        )
        val euro = byteArrayOf(0xE2.toByte(), 0x82.toByte(), 0xAC.toByte())
        val nul = byteArrayOf('a'.code.toByte(), 0xC0.toByte(), 0x80.toByte(), 'b'.code.toByte())
        val dex = buildDex(listOf(cafe, euro, nul))
        assertEquals(listOf("caf\u00e9", "\u20ac", "a\u0000b"), DexParser.readStrings(dex))
    }

    @Test
    fun magia_invalida_devuelve_null() {
        assertNull(DexParser.readStrings(ByteArray(256)))
        assertNull(DexParser.readStrings("no-es-dex".toByteArray()))
    }

    @Test
    fun truncado_devuelve_null() {
        val dex = buildDex(listOf("hola".toByteArray()))
        assertNull(DexParser.readStrings(dex.copyOf(0x70 + 2)))
    }

    @Test
    fun demasiados_strings_devuelve_null() {
        val header = ByteArray(0x70)
        "dex\n035\u0000".toByteArray(Charsets.ISO_8859_1).copyInto(header)
        putU32(header, 0x28, 0x12345678)
        putU32(header, 0x38, DexParser.MAX_STRINGS + 1)
        putU32(header, 0x3C, 0x70)
        assertNull(DexParser.readStrings(header))
    }
}
