package com.apkauditor.app.analysis

import java.io.InputStream

/**
 * Escaneo de strings en bruto sobre classes.dex (ingeniería inversa ligera).
 * Lee por bloques con traslape para no cargar dex grandes en memoria.
 * Todo es heurístico: un hallazgo indica presencia, no necesariamente malicia.
 */
object DexStrings {

    data class Result(
        val httpUrls: List<String>,
        val httpsCount: Int,
        val ips: List<String>,
        val apis: Map<String, Int>, // etiqueta -> ocurrencias
        val trackers: List<String>, // SDKs detectados
        val bytesScanned: Long,
        val truncated: Boolean
    )

    private const val CHUNK = 256 * 1024
    private const val OVERLAP = 4096
    const val MAX_BYTES: Long = 200L * 1024 * 1024
    private const val MAX_SAMPLES = 100

    private val httpRe = Regex("http://[^\\s\"'<>\\\\]+")
    private val httpsRe = Regex("https://[^\\s\"'<>\\\\]+")
    private val ipRe = Regex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")

    /** APIs sensibles buscadas tal cual aparecen en el dex. */
    val sensitiveApis = mapOf(
        "Ldalvik/system/DexClassLoader;" to "Carga dinámica de código (DexClassLoader)",
        "Ljava/lang/Runtime;->exec" to "Ejecución de comandos (Runtime.exec)",
        "Ljava/lang/reflect/Method;->invoke" to "Llamadas por reflexión (Method.invoke)",
        "Landroid/webkit/WebView;->addJavascriptInterface"
            to "Puente JavaScript en WebView (addJavascriptInterface)",
        "Ljavax/crypto/Cipher;" to "Cifrado (javax.crypto)",
        "Landroid/app/admin/DevicePolicyManager;" to "API de administrador del dispositivo"
    )

    /** Prefijos de paquetes de SDKs de analítica, ads o rastreo. */
    val trackerPrefixes = mapOf(
        "Lcom/google/firebase/analytics" to "Firebase Analytics",
        "Lcom/google/android/gms/analytics" to "Google Analytics",
        "Lcom/facebook/appevents" to "Meta App Events",
        "Lcom/flurry" to "Flurry",
        "Lcom/applovin" to "AppLovin",
        "Lcom/unity3d/ads" to "Unity Ads",
        "Lcom/mopub" to "MoPub",
        "Lcom/inmobi" to "InMobi",
        "Lcom/chartboost" to "Chartboost",
        "Lcom/crashlytics" to "Crashlytics",
        "Lcom/amplitude" to "Amplitude",
        "Lcom/mixpanel" to "Mixpanel",
        "Lcom/appsflyer" to "AppsFlyer",
        "Lcom/adjust" to "Adjust",
        "Lcom/kochava" to "Kochava",
        "Lcom/ironsource" to "ironSource",
        "Lcom/startapp" to "StartApp",
        "Lcom/airpush" to "Airpush",
        "Lio/branch" to "Branch",
        "Lcom/bugsnag" to "Bugsnag",
        "Lcom/newrelic" to "New Relic",
        "Lcom/uxcam" to "UXCam",
        "Lcom/yandex/metrica" to "Yandex Metrica"
    )

    fun scan(input: InputStream, onBytes: (Long) -> Unit = {}): Result {
        val httpUrls = linkedSetOf<String>()
        var httpsCount = 0
        val ips = linkedSetOf<String>()
        val apis = mutableMapOf<String, Int>()
        val trackers = linkedSetOf<String>()
        var scanned = 0L
        var truncated = false
        val buf = ByteArray(CHUNK)
        var carry = ""

        while (true) {
            val read = input.read(buf)
            if (read <= 0) break
            scanned += read
            onBytes(scanned)
            if (scanned > MAX_BYTES) {
                truncated = true
                break
            }
            val text = carry + String(buf, 0, read, Charsets.ISO_8859_1)

            httpRe.findAll(text).forEach {
                if (httpUrls.size < MAX_SAMPLES) httpUrls.add(trimUrl(it.value))
            }
            httpsCount += httpsRe.findAll(text).count()
            ipRe.findAll(text).forEach {
                if (ips.size < MAX_SAMPLES && validIp(it.value)) ips.add(it.value)
            }
            for ((needle, label) in sensitiveApis) {
                val n = countOccurrences(text, needle)
                if (n > 0) apis[label] = (apis[label] ?: 0) + n
            }
            for ((prefix, label) in trackerPrefixes) {
                if (text.contains(prefix)) trackers.add(label)
            }
            carry = text.takeLast(OVERLAP)
        }
        return Result(
            httpUrls = httpUrls.toList(),
            httpsCount = httpsCount,
            ips = ips.toList(),
            apis = apis,
            trackers = trackers.toList(),
            bytesScanned = scanned,
            truncated = truncated
        )
    }

    private fun trimUrl(url: String): String {
        val clean = url.take(200)
        return if (clean.length > 120) clean.take(117) + "..." else clean
    }

    private fun validIp(ip: String): Boolean {
        val parts = ip.split(".")
        if (parts.size != 4) return false
        return parts.all { (it.toIntOrNull() ?: 256) in 0..255 }
    }

    private fun countOccurrences(text: String, needle: String): Int {
        var count = 0
        var idx = text.indexOf(needle)
        while (idx >= 0) {
            count++
            idx = text.indexOf(needle, idx + needle.length)
        }
        return count
    }
}
