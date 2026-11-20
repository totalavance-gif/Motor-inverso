package com.apkauditor.app

import com.apkauditor.app.analysis.ManifestParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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

    @Test
    fun fixture_flags() {
        val bytes = javaClass.getResourceAsStream("/launcher-manifest.xml")!!.readBytes()
        val f = ManifestParser.readAppFlags(bytes)
        assertEquals(true, f.debuggable)
        assertEquals(false, f.allowBackup)
        assertEquals(false, f.usesCleartextTraffic)
        assertNull(f.legacyStorage)
    }

    @Test
    fun fixture_filtros() {
        val bytes = javaClass.getResourceAsStream("/launcher-manifest.xml")!!.readBytes()
        val fs = ManifestParser.readIntentFilters(bytes, "com.nexos.youtubeblocker")
        assertEquals(1, fs.size)
        assertEquals("com.nexos.youtubeblocker.MainActivity", fs[0].component)
        assertEquals(listOf("android.intent.action.MAIN"), fs[0].actions)
        assertEquals(listOf("android.intent.category.LAUNCHER"), fs[0].categories)
        assertTrue(fs[0].schemes.isEmpty())
    }

    @Test
    fun sintetico_flags_y_filtros() {
        val pool = listOf(
            "application", "debuggable", "allowBackup", "receiver", ".Boot",
            "intent-filter", "action", "android.intent.action.BOOT_COMPLETED",
            "data", "scheme", "myapp"
        )
        val axml = buildAxml(pool) { w, ix ->
            startElement(
                w, ix("application"),
                listOf(
                    boolAttr(ManifestParser.ATTR_DEBUGGABLE_RESID, 1),
                    boolAttr(ManifestParser.ATTR_ALLOWBACKUP_RESID, 0)
                )
            )
            endElement(w, ix("application"))
            startElement(w, ix("receiver"), listOf(nameAttr(ix(".Boot"))))
            startElement(w, ix("intent-filter"), emptyList())
            startElement(
                w, ix("action"),
                listOf(nameAttr(ix("android.intent.action.BOOT_COMPLETED")))
            )
            endElement(w, ix("action"))
            startElement(
                w, ix("data"),
                listOf(Attr(ManifestParser.ATTR_SCHEME_RESID, 3, ix("myapp")))
            )
            endElement(w, ix("data"))
            endElement(w, ix("intent-filter"))
            endElement(w, ix("receiver"))
        }
        val f = ManifestParser.readAppFlags(axml)
        assertEquals(true, f.debuggable)
        assertEquals(false, f.allowBackup)
        assertNull(f.usesCleartextTraffic)
        assertEquals(
            listOf(
                ManifestParser.FilterInfo(
                    "com.ejemplo.Boot",
                    listOf("android.intent.action.BOOT_COMPLETED"),
                    emptyList(), listOf("myapp")
                )
            ),
            ManifestParser.readIntentFilters(axml, "com.ejemplo")
        )
    }

    // ---- Mini constructor de AXML ----

    private data class Attr(val nameResid: Int, val dataType: Int, val data: Int)

    private fun nameAttr(valueIx: Int) = Attr(ManifestParser.ATTR_NAME_RESID, 3, valueIx)

    private fun boolAttr(resid: Int, v: Int) = Attr(resid, 0x12, v)

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
            putU32(w, 8 or (it.dataType shl 24))
            putU32(w, it.data)
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
