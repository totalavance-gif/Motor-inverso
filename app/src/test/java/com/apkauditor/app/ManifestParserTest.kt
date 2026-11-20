package com.apkauditor.app

import com.apkauditor.app.analysis.ManifestParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class ManifestParserTest {

    @Test
    fun manifest_real_detecta_launcher() {
        val bytes = javaClass.getResourceAsStream("/launcher-manifest.xml")!!.readBytes()
        assertEquals(
            setOf("com.nexos.youtubeblocker.MainActivity"),
            ManifestParser.launcherActivities(bytes, "com.nexos.youtubeblocker")
        )
    }

    @Test
    fun basura_y_truncado_dan_vacio() {
        assertTrue(ManifestParser.launcherActivities(ByteArray(0), "com.ejemplo").isEmpty())
        assertTrue(
            ManifestParser.launcherActivities("hola".toByteArray(), "com.ejemplo").isEmpty()
        )
        val bytes = javaClass.getResourceAsStream("/launcher-manifest.xml")!!.readBytes()
        assertTrue(
            ManifestParser.launcherActivities(bytes.copyOf(100), "com.nexos.youtubeblocker")
                .isEmpty()
        )
    }

    @Test
    fun forma_resid_estandar_con_nombres_relativos() {
        // Estilo aapt2: atributos por resid + pool UTF-8. Dos activities:
        // .Main con filtro MAIN/LAUNCHER y .Other sin filtro.
        val pool = listOf(
            "activity", "name", ".Main", "intent-filter", "action",
            "android.intent.action.MAIN", "category",
            "android.intent.category.LAUNCHER", ".Other", "service"
        )
        val axml = buildAxml(pool) { w, ix ->
            startElement(w, ix("activity"), listOf(nameAttr(ix(".Main"))))
            startElement(w, ix("intent-filter"), emptyList())
            startElement(w, ix("action"), listOf(nameAttr(ix("android.intent.action.MAIN"))))
            endElement(w, ix("action"))
            startElement(w, ix("category"), listOf(nameAttr(ix("android.intent.category.LAUNCHER"))))
            endElement(w, ix("category"))
            endElement(w, ix("intent-filter"))
            endElement(w, ix("activity"))
            startElement(w, ix("service"), listOf(nameAttr(ix(".Other"))))
            endElement(w, ix("service"))
            startElement(w, ix("activity"), listOf(nameAttr(ix(".Other"))))
            endElement(w, ix("activity"))
        }
        assertEquals(
            setOf("com.ejemplo.Main"),
            ManifestParser.launcherActivities(axml, "com.ejemplo")
        )
    }

    // ---- Mini constructor de AXML ----

    private data class Attr(val nameResid: Int, val valueIx: Int)

    private fun nameAttr(valueIx: Int) = Attr(ManifestParser.ATTR_NAME_RESID, valueIx)

    private fun buildAxml(pool: List<String>, body: (ByteArrayOutputStream, (String) -> Int) -> Unit): ByteArray {
        val ix = { s: String -> pool.indexOf(s) }
        val chunks = ByteArrayOutputStream()
        body(chunks, ix)
        val out = ByteArrayOutputStream()
        putU16(out, 0x0003)
        putU16(out, 8)
        val poolBytes = buildPool(pool)
        putU32(out, 8 + poolBytes.size + chunks.size())
        out.write(poolBytes)
        out.write(chunks.toByteArray())
        return out.toByteArray()
    }

    private fun buildPool(pool: List<String>): ByteArray {
        val data = ByteArrayOutputStream()
        val offsets = pool.map { s ->
            val off = data.size()
            val bytes = s.toByteArray(Charsets.UTF_8)
            putVarLen(data, s.length)
            putVarLen(data, bytes.size)
            data.write(bytes)
            data.write(0)
            off
        }
        val out = ByteArrayOutputStream()
        putU16(out, 0x0001)
        putU16(out, 28)
        putU32(out, 28 + pool.size * 4 + data.size())
        putU32(out, pool.size)
        putU32(out, 0)
        putU32(out, 0x100) // UTF-8
        putU32(out, 28 + pool.size * 4)
        putU32(out, 0)
        offsets.forEach { putU32(out, it) }
        out.write(data.toByteArray())
        return out.toByteArray()
    }

    private fun startElement(w: ByteArrayOutputStream, nameIx: Int, attrs: List<Attr>) {
        putU16(w, 0x0102)
        putU16(w, 16)
        putU32(w, 36 + attrs.size * 20)
        putU32(w, 0)
        putU32(w, 0xFFFFFFFF.toInt())
        putU32(w, 0xFFFFFFFF.toInt())
        putU32(w, nameIx)
        putU16(w, 36)
        putU16(w, 20)
        putU16(w, attrs.size)
        putU16(w, 0xFFFF)
        putU16(w, 0xFFFF)
        putU16(w, 0xFFFF)
        attrs.forEach {
            putU32(w, 0x01010000)
            putU32(w, it.nameResid)
            putU32(w, 0xFFFFFFFF.toInt())
            putU32(w, 8 or (3 shl 24))
            putU32(w, it.valueIx)
        }
    }

    private fun endElement(w: ByteArrayOutputStream, nameIx: Int) {
        putU16(w, 0x0103)
        putU16(w, 16)
        putU32(w, 24)
        putU32(w, 0)
        putU32(w, 0xFFFFFFFF.toInt())
        putU32(w, 0xFFFFFFFF.toInt())
        putU32(w, nameIx)
    }

    private fun putU16(w: ByteArrayOutputStream, v: Int) {
        w.write(v and 0xFF)
        w.write((v shr 8) and 0xFF)
    }

    private fun putU32(w: ByteArrayOutputStream, v: Int) {
        w.write(v and 0xFF)
        w.write((v shr 8) and 0xFF)
        w.write((v shr 16) and 0xFF)
        w.write((v shr 24) and 0xFF)
    }

    private fun putVarLen(w: ByteArrayOutputStream, v: Int) {
        if (v < 0x80) w.write(v)
        else {
            w.write(0x80 or ((v shr 8) and 0x7F))
            w.write(v and 0xFF)
        }
    }
}
