package com.apkauditor.app

import com.apkauditor.app.analysis.DexRefs
import com.apkauditor.app.analysis.DexStrings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
        assertEquals(listOf("192.168.1.50"), r.ips.map { it.ip })
        assertTrue(r.apis.keys.any { it.contains("DexClassLoader") })
        assertEquals(listOf("Meta App Events"), r.trackers)
    }

    @Test
    fun vacio_no_falla() {
        val r = DexStrings.scan(ByteArray(0).inputStream())
        assertTrue(r.httpUrls.isEmpty())
        assertEquals(0, r.bytesScanned)
    }

    @Test
    fun rechaza_url_falsa_pegada_con_nulos() {
        // Falso positivo real visto en un reporte: strings vecinas del dex
        // pegadas por el regex ("http://" + NUL + "https://" + ... + "loadUrl").
        val blob = byteArrayOf(
            *"http://".toByteArray(),
            0x00, 0x08,
            *"https://".toByteArray(),
            0x00, 0x07,
            *"loadUrl".toByteArray(),
            0x00, 0x04,
            *"name".toByteArray()
        )
        val r = DexStrings.scan(blob.inputStream())
        assertTrue(r.httpUrls.isEmpty())
    }

    @Test
    fun url_sin_host_valido_se_rechaza() {
        val blob = (
            "http:// nota suelta " +
                "http://sinhost/aqui " +
                "ok http://localhost:8080/app fin"
            ).toByteArray(Charsets.ISO_8859_1)
        val r = DexStrings.scan(blob.inputStream())
        assertEquals(listOf("http://localhost:8080/app"), r.httpUrls)
    }

    @Test
    fun no_cuenta_doble_en_traslape() {
        // Marca justo en la zona de traslape entre bloques (bloque = 256 KB).
        val marca = "https://a.bc/ Ljava/lang/Runtime;->exec "
        val relleno = "x".repeat(256 * 1024 - 100)
        val blob = (relleno + marca + "cola".repeat(2000)).toByteArray(Charsets.ISO_8859_1)
        val r = DexStrings.scan(blob.inputStream())
        assertEquals(1, r.httpsCount)
        assertEquals(1, r.apis.values.sum())
    }

    @Test
    fun detecta_secretos_sin_guardar_valores() {
        val google = "AIza" + "A".repeat(35)
        val blob = (
            "k1=$google " +
                "k2=AKIAIOSFODNN7EXAMPLE " +
                "api_key = \"supersecreto123\" " +
                "-----BEGIN RSA PRIVATE KEY-----"
            ).toByteArray(Charsets.ISO_8859_1)
        val r = DexStrings.scan(blob.inputStream())
        assertEquals(1, r.secrets["Clave de API de Google"])
        assertEquals(1, r.secrets["Clave de acceso de AWS"])
        assertEquals(1, r.secrets["Posible clave en claro"])
        assertEquals(1, r.secrets["Llave privada"])
        // El valor jamás queda en el resultado (ni en muestras ni en toString).
        assertFalse(r.toString().contains("supersecreto123"))
        assertFalse(r.toString().contains("AKIAIOSFODNN7EXAMPLE"))
    }

    @Test
    fun detecta_senales_de_entorno() {
        val blob = "a /system/xbin/su b com.topjohnwu.magisk c"
            .toByteArray(Charsets.ISO_8859_1)
        val r = DexStrings.scan(blob.inputStream())
        assertTrue(r.envSignals.contains("ruta su"))
        assertTrue(r.envSignals.contains("Magisk"))
    }

    @Test
    fun ip_trae_contexto() {
        val blob = "version=1.2.3.4;fin".toByteArray(Charsets.ISO_8859_1)
        val r = DexStrings.scan(blob.inputStream())
        assertEquals(1, r.ips.size)
        assertEquals("1.2.3.4", r.ips[0].ip)
        assertTrue(r.ips[0].context.contains("version="))
    }

    @Test
    fun puente_js_no_resta_score() {
        val apis = mapOf(
            "Puente JavaScript en WebView (addJavascriptInterface)" to 5,
            "Ejecución de comandos (Runtime.exec)" to 1
        )
        assertEquals(1, DexStrings.scoredApiCount(apis))
        assertEquals(0, DexStrings.scoredApiCount(mapOf(apis.keys.first() to 5)))
    }

    @Test
    fun scanStrings_no_pega_vecinas() {
        val r = DexStrings.scanStrings(listOf("http://", "loadUrl", "name"))
        assertTrue(r.httpUrls.isEmpty())
        assertTrue(r.exactStrings)

        val ok = DexStrings.scanStrings(listOf("nada", "http://api.ejemplo.com/x"))
        assertEquals(listOf("http://api.ejemplo.com/x"), ok.httpUrls)
    }

    @Test
    fun jwt_y_bearer_sin_guardar_valores() {
        val jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0." +
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        val blob = "tok=$jwt auth=Bearer abcdefghijklmnopqrstuvwx fin"
            .toByteArray(Charsets.ISO_8859_1)
        val r = DexStrings.scan(blob.inputStream())
        assertEquals(1, r.secrets["Token JWT"])
        assertEquals(1, r.secrets["Token Bearer"])
        assertFalse(r.toString().contains("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"))
    }

    @Test
    fun blob_base64_con_url_se_reporta_y_ruido_no() {
        val withUrl = java.util.Base64.getEncoder().encodeToString(
            "http://oculto.ejemplo.com/ruta-secreta-con-relleno-0123456789".toByteArray()
        )
        assertTrue(withUrl.length >= 80)
        val r = DexStrings.scanStrings(listOf("x", withUrl))
        assertEquals(1, r.blobs["Blob base64 con URL"])

        val noise = DexStrings.scanStrings(listOf("A".repeat(100)))
        assertTrue(noise.blobs.isEmpty())
    }

    @Test
    fun cripto_tokens_sin_falsos() {
        val r = DexStrings.scanStrings(
            listOf("usa DES y MD5, evita AES/ECB; description sin nada")
        )
        assertEquals(1, r.crypto["DES"])
        assertEquals(1, r.crypto["MD5"])
        assertEquals(1, r.crypto["AES/ECB"])

        val clean = DexStrings.scanStrings(listOf("description", "SHAPE-1"))
        assertTrue(clean.crypto.isEmpty())
    }

    @Test
    fun shell_comandos() {
        val r = DexStrings.scanStrings(
            listOf("run pm install /sdcard/x.apk y getprop ro.build fin")
        )
        assertEquals(1, r.shellCmds["pm install"])
        assertEquals(1, r.shellCmds["getprop"])
        val clean = DexStrings.scanStrings(listOf("getproperty"))
        assertTrue(clean.shellCmds.isEmpty())
    }

    @Test
    fun tracker_exige_limite_de_paquete() {
        val no = DexStrings.scanStrings(listOf("zzzLcom/flurryyy"), emptyList())
        assertTrue(no.trackers.isEmpty())
        val yes = DexStrings.scanStrings(listOf("Lcom/flurry/A;"), emptyList())
        assertEquals(listOf("Flurry"), yes.trackers)
    }

    @Test
    fun https_guarda_muestras() {
        val r = DexStrings.scanStrings(listOf("ir a https://seguro.ejemplo.com/a ya"))
        assertEquals(1, r.httpsCount)
        assertEquals(listOf("https://seguro.ejemplo.com/a"), r.httpsUrls)
    }

    @Test
    fun apis_exactas_ignoran_substrings() {
        val r = DexStrings.scanStrings(
            listOf("Ljava/lang/Runtime;->exec"),
            listOf(DexRefs.MethodRef("Ljava/lang/Runtime;", "exec"))
        )
        assertEquals(1, r.apis["Ejecución de comandos (Runtime.exec)"])

        // substring sin referencia exacta: no cuenta
        val none = DexStrings.scanStrings(listOf("Ljava/lang/Runtime;->exec"), emptyList())
        assertTrue(none.apis.isEmpty())
        assertEquals(0, DexStrings.scoredApiCount(none.apis))
    }

    @Test
    fun userinfo_pasa_para_marcarse() {
        val r = DexStrings.scanStrings(listOf("ir a http://admin@huesped.com/ ya"))
        assertEquals(listOf("http://admin@huesped.com/"), r.httpUrls)
    }
}
