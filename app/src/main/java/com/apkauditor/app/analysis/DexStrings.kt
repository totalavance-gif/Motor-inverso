package com.apkauditor.app.analysis

import java.io.InputStream

/**
 * Escaneo de strings sobre classes.dex (ingeniería inversa ligera).
 *
 * Dos modos: [scanStrings] sobre la tabla de strings exacta (ver [DexParser],
 * preferido: cada string llega separada) y [scan] en bruto por bloques con
 * traslape para dex que no se pudieron parsear o muy grandes.
 * Todo es heurístico: un hallazgo indica presencia, no necesariamente malicia.
 * Kotlin puro, sin Android: unit-testeable en JVM.
 */
object DexStrings {

    /** Una IP literal con el texto que la rodea (para distinguirla de versiones). */
    data class IpHit(val ip: String, val context: String)

    data class Result(
        val httpUrls: List<String>,
        val httpsCount: Int,
        val ips: List<IpHit>,
        val apis: Map<String, Int>, // etiqueta -> ocurrencias
        val trackers: List<String>, // SDKs detectados
        val secrets: Map<String, Int>, // tipo de secreto -> ocurrencias (nunca el valor)
        val envSignals: List<String>, // menciones a root/análisis (posible detección de entorno)
        val bytesScanned: Long,
        val truncated: Boolean,
        val exactStrings: Boolean // true si vino de la tabla de strings exacta
    )

    private const val CHUNK = 256 * 1024
    private const val OVERLAP = 4096
    const val MAX_BYTES: Long = 200L * 1024 * 1024
    private const val MAX_SAMPLES = 100
    private const val CONTEXT = 24

    // Los bytes de control (NUL separa strings en el dex) nunca son parte de una URL:
    // sin esto el regex pega strings vecinas y crea URLs falsas.
    private val httpRe = Regex("http://[^\\s\"'<>\\\\\\x00-\\x1F\\x7F]+")
    private val httpsRe = Regex("https://[^\\s\"'<>\\\\\\x00-\\x1F\\x7F]+")
    private val ipRe = Regex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")

    /** Patrones de secretos hardcodeados. Solo se cuenta el tipo: el valor jamás se guarda. */
    private val secretRes = listOf(
        "Clave de API de Google" to Regex("AIza[0-9A-Za-z_\\-]{35}"),
        "Clave de acceso de AWS" to Regex("AKIA[0-9A-Z]{16}"),
        "Token de GitHub" to Regex("ghp_[0-9A-Za-z]{20,}|github_pat_[0-9A-Za-z_]{20,}"),
        "Token de Slack" to Regex("xox[baprs]-[0-9A-Za-z\\-]+"),
        "Llave privada" to Regex("-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "Posible clave en claro" to
            Regex("(?i)(?:api[_-]?key|api[_-]?secret|secret[_-]?key|password|passwd)\\s*[:=]\\s*['\"][^'\"\\s]{8,}['\"]")
    )

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

    /** Detecciones informativas que NO restan score (uso legítimo muy común). */
    val infoOnlyApis = setOf(
        "Puente JavaScript en WebView (addJavascriptInterface)"
    )

    /** APIs con peso en el score (excluye las informativas). */
    fun scoredApiCount(apis: Map<String, Int>): Int =
        apis.keys.count { it !in infoOnlyApis }

    /** Menciones a herramientas de root/análisis: el APK podría detectar el entorno. */
    val envNeedles = mapOf(
        "/system/bin/su" to "ruta su",
        "/system/xbin/su" to "ruta su",
        "/sbin/su" to "ruta su",
        "Superuser.apk" to "Superuser.apk",
        "com.topjohnwu.magisk" to "Magisk",
        "de.robv.android.xposed" to "Xposed",
        "frida-server" to "Frida",
        "frida-agent" to "Frida",
        "libfrida" to "Frida"
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

    private class Acc {
        val httpUrls = linkedSetOf<String>()
        var httpsCount = 0
        val ips = linkedMapOf<String, String>() // ip -> contexto
        val apis = mutableMapOf<String, Int>()
        val trackers = linkedSetOf<String>()
        val secrets = mutableMapOf<String, Int>()
        val envSignals = linkedSetOf<String>()
    }

    /** Barrido en bruto por bloques (respaldo cuando el dex no se pudo parsear). */
    fun scan(input: InputStream, onBytes: (Long) -> Unit = {}): Result {
        val acc = Acc()
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
            detect(text, fromIndex = carry.length, acc)
            carry = text.takeLast(OVERLAP)
        }
        return build(acc, scanned, truncated, exactStrings = false)
    }

    /** Escaneo sobre strings exactas (sin traslape: cada string ya viene separada). */
    fun scanStrings(strings: List<String>): Result {
        val acc = Acc()
        // "\n" nunca forma parte de un match: une sin pegar detecciones.
        val text = strings.joinToString("\n")
        detect(text, fromIndex = 0, acc)
        return build(acc, text.length.toLong(), truncated = false, exactStrings = true)
    }

    /**
     * Aplica todos los detectores a [text]. Los conteos solo toman matches que
     * empiezan en [fromIndex] o después (lo anterior ya se contó en el bloque
     * previo); los sets buscan todo el texto para no perder matches cortados
     * por el borde (los duplicados se eliminan solos).
     */
    private fun detect(text: String, fromIndex: Int, acc: Acc) {
        httpRe.findAll(text).forEach {
            if (validHttpUrl(it.value) && acc.httpUrls.size < MAX_SAMPLES) {
                acc.httpUrls.add(trimUrl(it.value))
            }
        }
        httpsRe.findAll(text).forEach {
            if (it.range.first >= fromIndex) acc.httpsCount++
        }
        ipRe.findAll(text).forEach {
            if (validIp(it.value) && acc.ips.size < MAX_SAMPLES) {
                acc.ips.putIfAbsent(it.value, contextAround(text, it.range))
            }
        }
        for ((needle, label) in sensitiveApis) {
            val n = countOccurrences(text, needle, fromIndex)
            if (n > 0) acc.apis[label] = (acc.apis[label] ?: 0) + n
        }
        for ((prefix, label) in trackerPrefixes) {
            if (text.contains(prefix)) acc.trackers.add(label)
        }
        for ((label, re) in secretRes) {
            val n = re.findAll(text).count { it.range.first >= fromIndex }
            if (n > 0) acc.secrets[label] = (acc.secrets[label] ?: 0) + n
        }
        for ((needle, label) in envNeedles) {
            if (text.contains(needle)) acc.envSignals.add(label)
        }
    }

    private fun build(acc: Acc, scanned: Long, truncated: Boolean, exactStrings: Boolean) =
        Result(
            httpUrls = acc.httpUrls.toList(),
            httpsCount = acc.httpsCount,
            ips = acc.ips.map { IpHit(it.key, it.value) },
            apis = acc.apis,
            trackers = acc.trackers.toList(),
            secrets = acc.secrets,
            envSignals = acc.envSignals.toList(),
            bytesScanned = scanned,
            truncated = truncated,
            exactStrings = exactStrings
        )

    /** Exige host con aspecto real (con punto o localhost): rechaza basura pegada. */
    internal fun validHttpUrl(url: String): Boolean {
        val rest = url.removePrefix("http://")
        if (rest.isEmpty() || rest.length > 500) return false
        val host = rest.substringBefore('/')
            .substringBefore('?').substringBefore('#').substringBefore(':')
        if (host.isEmpty() || host.length > 253) return false
        if (host.equals("localhost", ignoreCase = true)) return true
        if (!host.contains('.')) return false
        return host.all { it.isLetterOrDigit() || it == '.' || it == '-' || it == '_' }
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

    private fun contextAround(text: String, range: IntRange): String {
        val s = (range.first - CONTEXT).coerceAtLeast(0)
        val e = (range.last + CONTEXT + 1).coerceAtMost(text.length)
        return text.substring(s, e)
            .map { if (it in '\u0020'..'\u007E') it else '·' }
            .joinToString("")
    }

    private fun countOccurrences(text: String, needle: String, fromIndex: Int): Int {
        var count = 0
        var idx = text.indexOf(needle, fromIndex.coerceAtMost(text.length))
        while (idx >= 0) {
            count++
            idx = text.indexOf(needle, idx + needle.length)
        }
        return count
    }
}
