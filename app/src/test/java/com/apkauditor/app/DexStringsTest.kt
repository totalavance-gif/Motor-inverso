package com.apkauditor.app

import com.apkauditor.app.analysis.DexStrings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DexStringsTest {

    @Test
    fun detecta_http_apis_y_trackers() {
        val blob = (
            "xxxxhttp://api.ejemplo.com/datos yyyy" +
                "Ldalvik/system/DexClassLoader;zzzz" +
                "Lcom/facebook/appevents/AppEventsLogger;" +
                "https://seguro.ejemplo.com/" +
                "ip 192.168.1.50 fin"
            ).toByteArray(Charsets.ISO_8859_1)
        val r = DexStrings.scan(blob.inputStream())
        assertEquals(listOf("http://api.ejemplo.com/datos"), r.httpUrls)
        assertEquals(1, r.httpsCount)
        assertEquals(listOf("192.168.1.50"), r.ips)
        assertTrue(r.apis.keys.any { it.contains("DexClassLoader") })
        assertEquals(listOf("Meta App Events"), r.trackers)
    }

    @Test
    fun vacio_no_falla() {
        val r = DexStrings.scan(ByteArray(0).inputStream())
        assertTrue(r.httpUrls.isEmpty())
        assertEquals(0, r.bytesScanned)
    }
}
