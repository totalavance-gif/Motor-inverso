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
        val nsUrls: List<String>, // http que son namespaces/identificadores, no tráfico
        val httpsCount: Int,
        val httpsUrls: List<String>, // muestras validadas (para dominios)
        val ips: List<IpHit>,
        val apis: Map<String, Int>, // etiqueta -> ocurrencias (exactas si hubo method_ids)
        val trackers: List<String>, // SDKs detectados
        val secrets: Map<String, Int>, // tipo de secreto -> ocurrencias (nunca el valor)
        val envSignals: List<String>, // menciones a root/análisis (posible detección de entorno)
        val crypto: Map<String, Int>, // algoritmo débil -> ocurrencias
        val shellCmds: Map<String, Int>, // comando de shell -> ocurrencias
        val blobs: Map<String, Int>, // blob base64 con contenido -> ocurrencias
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
        "Token JWT" to Regex("eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}"),
        "Token Bearer" to Regex("(?i)Bearer\\s+[A-Za-z0-9\\-._~+/]{20,}={0,2}"),
        "Posible clave en claro" to
            Regex("(?i)(?:api[_-]?key|api[_-]?secret|secret[_-]?key|password|passwd)\\s*[:=]\\s*['\"][^'\"\\s]{8,}['\"]")
    )

    /** Candidatos a blob base64 largo (luego se decodifica y valida). */
    private val blobRe = Regex("[A-Za-z0-9+/]{80,}={0,2}")
    private const val MAX_BLOB_DECODE = 20
    private const val MAX_BLOB_LEN = 8192

    /** Algoritmos débiles como token completo (\\b evita "DES" en "description"). */
    private val cryptoRes = listOf(
        "DES" to Regex("(?i)\\bDESede\\b|\\bTripleDES\\b|\\bDES\\b"),
        "RC4" to Regex("(?i)\\bRC4\\b"),
        "MD5" to Regex("(?i)\\bMD5\\b"),
        "SHA-1" to Regex("(?i)\\bSHA-?1\\b"),
        "AES/ECB" to Regex("(?i)AES/ECB|/ECB/")
    )

    /** Comandos de shell literales (llevan espacios/rutas: pocas falsas). */
    private val shellNeedles = listOf(
        "/system/bin/sh", "sh -c", "su -c", "mount -o remount",
        "am start", "pm install", "pm uninstall",
        "getprop ", "setprop ", "logcat -d", "chmod 777"
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
        "Lcom/yandex/metrica" to "Yandex Metrica",
        "Lcom/onesignal" to "OneSignal",
        "Lcom/segment/analytics" to "Segment",
        "Lio/sentry" to "Sentry",
        "Lcom/huawei/hms/analytics" to "Huawei Analytics",
        "Lcom/bytedance/sdk/openadsdk" to "Pangle (ByteDance)",
        "Lcom/tapjoy" to "Tapjoy",
        "Lcom/vungle" to "Vungle",
        "Lcom/adcolony" to "AdColony",
        "Lcom/fyber" to "Fyber",
        "Lcom/supersonicads" to "Supersonic"
    )

    private class Acc {
        val httpUrls = linkedSetOf<String>()
        val nsUrls = linkedSetOf<String>()
        var httpsCount = 0
        val httpsUrls = linkedSetOf<String>()
        val ips = linkedMapOf<String, String>() // ip -> contexto
        val apis = mutableMapOf<String, Int>()
        val trackers = linkedSetOf<String>()
        val secrets = mutableMapOf<String, Int>()
        val envSignals = linkedSetOf<String>()
        val crypto = mutableMapOf<String, Int>()
        val shellCmds = mutableMapOf<String, Int>()
        val blobs = mutableMapOf<String, Int>()
        val seenBlobHeads = mutableSetOf<String>()
        var blobAttempts = 0
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

    /**
     * Escaneo sobre strings exactas (sin traslape: cada string ya viene separada).
     * Con [methods] (method_ids), las APIs son referencias exactas y los
     * trackers exigen límite de paquete; sin ellos, substring como respaldo.
     */
    fun scanStrings(strings: List<String>, methods: List<DexRefs.MethodRef>? = null): Result {
        val acc = Acc()
        // "\n" nunca forma parte de un match: une sin pegar detecciones.
        val text = strings.joinToString("\n")
        detect(text, fromIndex = 0, acc, exactTrackers = methods != null)
        if (methods != null) {
            acc.apis.clear()
            acc.apis.putAll(DexRefs.matchExact(methods))
            matchTrackersExact(strings, acc)
        }
        return build(acc, text.length.toLong(), truncated = false, exactStrings = true)
    }

    /** Trackers contra strings exactas: el prefijo debe ser inicio + límite. */
    private fun matchTrackersExact(strings: List<String>, acc: Acc) {
        for (s in strings) {
            for ((prefix, label) in trackerPrefixes) {
                if (s.startsWith(prefix) &&
                    (s.length == prefix.length || s[prefix.length] == '/' || s[prefix.length] == ';')
                ) {
                    acc.trackers.add(label)
                }
            }
        }
    }

    /**
     * Aplica todos los detectores a [text]. Los conteos solo toman matches que
     * empiezan en [fromIndex] o después (lo anterior ya se contó en el bloque
     * previo); los sets buscan todo el texto para no perder matches cortados
     * por el borde (los duplicados se eliminan solos).
     */
    private fun detect(text: String, fromIndex: Int, acc: Acc, exactTrackers: Boolean = false) {
        httpRe.findAll(text).forEach {
            val clean = stripTrailingPunct(it.value)
            if (!validHttpUrl(clean)) return@forEach
            if (looksLikeNamespace(clean)) {
                if (acc.nsUrls.size < MAX_SAMPLES) acc.nsUrls.add(trimUrl(clean))
            } else if (acc.httpUrls.size < MAX_SAMPLES) {
                acc.httpUrls.add(trimUrl(clean))
            }
        }
        httpsRe.findAll(text).forEach {
            if (it.range.first >= fromIndex) {
                acc.httpsCount++
                val clean = stripTrailingPunct(it.value)
                if (validHost(clean.substringAfter("://")) && acc.httpsUrls.size < MAX_SAMPLES) {
                    acc.httpsUrls.add(trimUrl(clean))
                }
            }
        }
        ipRe.findAll(text).forEach {
            if (validIp(it.value, text, it.range) && acc.ips.size < MAX_SAMPLES) {
                acc.ips.putIfAbsent(it.value, contextAround(text, it.range))
            }
        }
        for ((needle, label) in sensitiveApis) {
            val n = countOccurrences(text, needle, fromIndex)
            if (n > 0) acc.apis[label] = (acc.apis[label] ?: 0) + n
        }
        if (!exactTrackers) {
            for ((prefix, label) in trackerPrefixes) {
                if (text.contains(prefix)) acc.trackers.add(label)
            }
        }
        for ((label, re) in secretRes) {
            val n = re.findAll(text).count { it.range.first >= fromIndex }
            if (n > 0) acc.secrets[label] = (acc.secrets[label] ?: 0) + n
        }
        for ((needle, label) in envNeedles) {
            if (text.contains(needle)) acc.envSignals.add(label)
        }
        for ((label, re) in cryptoRes) {
            val n = re.findAll(text).count { it.range.first >= fromIndex }
            if (n > 0) acc.crypto[label] = (acc.crypto[label] ?: 0) + n
        }
        for (needle in shellNeedles) {
            val n = countOccurrences(text, needle, fromIndex)
            if (n > 0) acc.shellCmds[needle.trim()] = (acc.shellCmds[needle.trim()] ?: 0) + n
        }
        blobRe.findAll(text).forEach {
            if (it.range.first >= fromIndex) inspectBlob(it.value, acc)
        }
    }

    /** Decodifica un candidato base64: solo cuenta si trae URL o binario. */
    private fun inspectBlob(run: String, acc: Acc) {
        if (acc.blobAttempts >= MAX_BLOB_DECODE || run.length > MAX_BLOB_LEN) return
        acc.blobAttempts++
        val clean = run.trimEnd('=')
        if (clean.length < 80 || clean.length % 4 == 1) return
        val decoded = try {
            java.util.Base64.getDecoder().decode(padBase64(clean))
        } catch (e: Exception) {
            return
        }
        if (decoded.size < 16) return
        val head = decoded.take(32).toByteArray().toString(Charsets.ISO_8859_1)
        if (!acc.seenBlobHeads.add(head)) return // mismo blob cortado por el borde
        val asText = decoded.toString(Charsets.ISO_8859_1)
        val label = when {
            "http://" in asText || "https://" in asText -> "Blob base64 con URL"
            isBinaryMagic(decoded) -> "Blob base64 con binario"
            else -> return
        }
        acc.blobs[label] = (acc.blobs[label] ?: 0) + 1
    }

    private fun padBase64(s: String): String = s + "=".repeat((4 - s.length % 4) % 4)

    private fun isBinaryMagic(b: ByteArray): Boolean {
        if (b.size < 4) return false
        if (b[0] == 0x7F.toByte() && b[1] == 'E'.code.toByte()) return true // ELF
        if (b[0] == 'P'.code.toByte() && b[1] == 'K'.code.toByte()) return true // ZIP/APK
        if (b[0] == 'M'.code.toByte() && b[1] == 'Z'.code.toByte()) return true // EXE/DLL
        if (b[0] == '%'.code.toByte() && b[1] == 'P'.code.toByte()) return true // PDF
        if (b.size >= 8 && b[0] == 'd'.code.toByte() && b[3] == '\n'.code.toByte()) {
            val magic = b.take(8).toByteArray().toString(Charsets.US_ASCII)
            if (magic.startsWith("dex\n")) return true
        }
        return false
    }

    private fun build(acc: Acc, scanned: Long, truncated: Boolean, exactStrings: Boolean) =
        Result(
            httpUrls = acc.httpUrls.toList(),
            nsUrls = acc.nsUrls.toList(),
            httpsCount = acc.httpsCount,
            httpsUrls = acc.httpsUrls.toList(),
            ips = acc.ips.map { IpHit(it.key, it.value) },
            apis = acc.apis,
            trackers = acc.trackers.toList(),
            secrets = acc.secrets,
            envSignals = acc.envSignals.toList(),
            crypto = acc.crypto,
            shellCmds = acc.shellCmds,
            blobs = acc.blobs,
            bytesScanned = scanned,
            truncated = truncated,
            exactStrings = exactStrings
        )

    /** Exige host con aspecto real (con punto o localhost): rechaza basura pegada. */
    internal fun validHttpUrl(url: String): Boolean {
        val rest = url.removePrefix("http://")
        if (rest.isEmpty() || rest.length > 500) return false
        return validHost(rest)
    }

    internal fun validHost(rest: String): Boolean {
        val auth = rest.substringBefore('/').substringBefore('?').substringBefore('#')
        // Quita usuario/clave primero: Domains lo marca como sospechoso.
        val noUser = auth.substringAfterLast('@')
        val host = if (noUser.startsWith("[")) {
            noUser.substringBefore(']') + "]" // IPv6 literal
        } else {
            noUser.substringBefore(':')
        }
        if (host.isEmpty() || host.length > 253) return false
        if (host.startsWith("[") && host.endsWith("]")) return true
        if (host.equals("localhost", ignoreCase = true)) return true
        if (!host.contains('.')) return false
        return host.all { it.isLetterOrDigit() || it == '.' || it == '-' || it == '_' }
    }

    private fun trimUrl(url: String): String {
        val clean = url.take(200)
        return if (clean.length > 120) clean.take(117) + "..." else clean
    }

    /** Quita puntuación final de prosa ("mira https://a.bc/x."). */
    internal fun stripTrailingPunct(url: String): String =
        url.dropLastWhile { it in ".,;:!?)]}\"" }

    /** Hosts de organismos de estándares: sus URLs son identificadores, no tráfico. */
    private val nsExactHosts = setOf(
        "w3.org", "xml.org", "oasis-open.org", "dashif.org", "aomedia.org",
        "schemas.microsoft.com", "schemas.android.com", "schemas.xmlsoap.org",
        "schemas.openxmlformats.org", "ns.adobe.com", "xmlpull.org", "xml.org"
    )

    internal fun looksLikeNamespace(url: String): Boolean {
        val host = urlHost(url).lowercase()
        if (host.isEmpty()) return false
        if (host in nsExactHosts || host.endsWith(".w3.org")) return true
        if ("schemas." in host || host.startsWith("ns.")) return true
        return false
    }

    internal fun urlHost(url: String): String {
        val auth = url.substringAfter("://", "")
            .substringBefore('/').substringBefore('?').substringBefore('#')
        val noUser = auth.substringAfterLast('@')
        return if (noUser.startsWith("[")) {
            noUser.substringBefore(']') + "]"
        } else {
            noUser.substringBefore(':')
        }
    }

    /** Versiones (Chrome/124.0.0.0, Tizen 4.0.0.2) y OIDs (1.3.6.1...) no son IPs. */
    private val versionPrefixRe =
        Regex("(?i)\\b(chrome|chromium|version|safari|firefox|tizen|android|ios|edge|opera|mozilla|applewebkit|gecko|build|crios|fxios|edg|samsungbrowser|ucbrowser|miuibrowser)[/: ][^\\s]{0,4}$|\\bv=[\"']?$")

    private fun validIp(ip: String, text: String, range: IntRange): Boolean {
        val parts = ip.split(".")
        if (parts.size != 4) return false
        if (!parts.all { (it.toIntOrNull() ?: 256) in 0..255 }) return false
        // N.0.0.0 es dirección de red (o versión Chrome), nunca un host.
        if (parts[1] == "0" && parts[2] == "0" && parts[3] == "0") return false
        // Parte de una corrida punteada más larga (OID, versión extendida).
        val before = text.getOrNull(range.first - 1)
        val after = text.getOrNull(range.last + 1)
        if (before != null && (before.isDigit() || before == '.')) return false
        if (after != null && (after.isDigit() || after == '.')) return false
        // Chrome/124.0.0.0 sí; http://1.2.3.4/ no (ahí es host).
        if (before == '/') {
            val prev = range.first - 2
            val isScheme = prev >= 1 && text[prev] == '/' && text[prev - 1] == ':'
            if (!isScheme) return false
        }
        // Tizen 4.0.0.2, Version 1.2.3.4
        val behind = text.substring(maxOf(0, range.first - 20), range.first)
        if (versionPrefixRe.containsMatchIn(behind)) return false
        return true
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
