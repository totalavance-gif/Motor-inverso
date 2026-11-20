package com.apkauditor.app

import com.apkauditor.app.analysis.DexParser
import com.apkauditor.app.analysis.DexRefs
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DexRefsTest {

    private data class Tables(
        val strings: List<String>,
        val types: List<Int>,
        val methods: List<Triple<Int, Int, Int>>, // classIdx, protoIdx, nameIdx
        val classes: List<Int> // classIdx (a type_ids)
    )

    private fun buildDex(t: Tables): ByteArray {
        val header = ByteArray(0x70)
        "dex\n035\u0000".toByteArray(Charsets.ISO_8859_1).copyInto(header)
        putU32(header, 0x28, 0x12345678)
        val out = header.toMutableList()
        // string_ids
        val strTab = out.size
        putU32(header, 0x38, t.strings.size)
        putU32(header, 0x3C, strTab)
        repeat(t.strings.size) { out.addAll(listOf(0, 0, 0, 0)) }
        val strOffs = t.strings.map { s ->
            val off = out.size
            val body = s.toByteArray(Charsets.UTF_8)
            out.add(body.size.toByte())
            out.addAll(body.toList())
            out.add(0)
            off
        }
        strOffs.forEachIndexed { i, o -> writeU32(out, strTab + i * 4, o) }
        // type_ids
        val typeTab = out.size
        putU32(header, 0x40, t.types.size)
        putU32(header, 0x44, typeTab)
        t.types.forEach { writeU32grow(out, it) }
        // method_ids
        val methTab = out.size
        putU32(header, 0x58, t.methods.size)
        putU32(header, 0x5C, methTab)
        t.methods.forEach { (c, p, n) ->
            out.add((c and 0xFF).toByte())
            out.add(((c shr 8) and 0xFF).toByte())
            out.add((p and 0xFF).toByte())
            out.add(((p shr 8) and 0xFF).toByte())
            writeU32grow(out, n)
        }
        // class_defs
        val defTab = out.size
        putU32(header, 0x60, t.classes.size)
        putU32(header, 0x64, defTab)
        t.classes.forEach {
            writeU32grow(out, it)
            repeat(7) { writeU32grow(out, 0) }
        }
        val bytes = out.toByteArray()
        header.copyInto(bytes)
        return bytes
    }

    private fun putU32(b: ByteArray, off: Int, v: Int) {
        b[off] = (v and 0xFF).toByte()
        b[off + 1] = ((v shr 8) and 0xFF).toByte()
        b[off + 2] = ((v shr 16) and 0xFF).toByte()
        b[off + 3] = ((v shr 24) and 0xFF).toByte()
    }

    private fun writeU32grow(out: MutableList<Byte>, v: Int) {
        out.add((v and 0xFF).toByte())
        out.add(((v shr 8) and 0xFF).toByte())
        out.add(((v shr 16) and 0xFF).toByte())
        out.add(((v shr 24) and 0xFF).toByte())
    }

    private fun writeU32(out: MutableList<Byte>, off: Int, v: Int) {
        out[off] = (v and 0xFF).toByte()
        out[off + 1] = ((v shr 8) and 0xFF).toByte()
        out[off + 2] = ((v shr 16) and 0xFF).toByte()
        out[off + 3] = ((v shr 24) and 0xFF).toByte()
    }

    private fun sample() = Tables(
        strings = listOf("Ljava/lang/Runtime;", "exec", "Lcom/app/Main;", "onCreate"),
        types = listOf(0, 2),
        methods = listOf(Triple(0, 0, 1), Triple(1, 0, 3)),
        classes = listOf(1)
    )

    @Test
    fun metodos_y_clases_exactos() {
        val dex = buildDex(sample())
        val strings = DexParser.readStrings(dex)!!
        val methods = DexRefs.readMethods(dex, strings)!!
        assertEquals(2, methods.size)
        assertTrue(methods.contains(DexRefs.MethodRef("Ljava/lang/Runtime;", "exec")))
        val hits = DexRefs.matchExact(methods)
        assertEquals(1, hits["Ejecución de comandos (Runtime.exec)"])
        assertEquals(listOf("Lcom/app/Main;"), DexRefs.readClasses(dex, strings))
        assertEquals(0, DexRefs.obfuscationPct(listOf("Lcom/app/Main;")))
    }

    @Test
    fun ofuscacion_mide_nombres_cortos() {
        assertEquals(
            66,
            DexRefs.obfuscationPct(listOf("La/b/c;", "Ld/e/fg;", "Lcom/app/MainActivity;"))
        )
        assertEquals(-1, DexRefs.obfuscationPct(emptyList()))
    }

    @Test
    fun tablas_rotas_devuelven_null() {
        val dex = buildDex(sample())
        // method_ids_size gigante
        putU32(dex, 0x58, DexRefs.MAX_IDS + 1)
        val strings = DexParser.readStrings(dex)!!
        assertNull(DexRefs.readMethods(dex, strings))
    }
}
