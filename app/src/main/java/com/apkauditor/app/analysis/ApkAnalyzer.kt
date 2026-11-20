package com.apkauditor.app.analysis

import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import com.apkauditor.app.model.AuditReport
import com.apkauditor.app.model.CertInfo
import com.apkauditor.app.model.ComponentInfo
import com.apkauditor.app.model.DexFinding
import com.apkauditor.app.model.Finding
import com.apkauditor.app.model.PermCategory
import com.apkauditor.app.model.ZipZone
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.ZipFile

/** Error de análisis con mensaje listo para mostrar al usuario. */
class ApkAnalysisException(message: String) : Exception(message)

/**
 * Analiza un APK copiado en almacenamiento privado. Todo es solo lectura:
 * nunca instala, ejecuta ni modifica el APK.
 */
object ApkAnalyzer {

    const val MAX_APK_BYTES = 500L * 1024 * 1024

    /** Dex más grande que esto se barre en bruto en vez de parsearse exacto. */
    private const val MAX_EXACT_DEX_BYTES = 64L * 1024 * 1024

    fun analyze(
        pm: PackageManager,
        apk: File,
        onProgress: (Float, String) -> Unit = { _, _ -> }
    ): AuditReport {
        if (!apk.isFile) throw ApkAnalysisException("No se encontró el archivo temporal.")
        if (apk.length() > MAX_APK_BYTES) {
            throw ApkAnalysisException("El APK supera el límite de 500 MB.")
        }
        onProgress(0.05f, "Leyendo manifest...")
        val info = readArchiveInfo(pm, apk)
        onProgress(0.3f, "Inventariando archivos...")
        val zip = readZip(apk)
        onProgress(0.55f, "Verificando firma...")
        val certs = readCerts(info)
        onProgress(0.6f, "Leyendo manifest...")
        val manifestBytes = readManifestBytes(apk)
        onProgress(0.65f, "Escaneando código...")
        val dex = scanDex(apk, zip.dexNames, info.packageName, manifestBytes) { done, total ->
            val f = if (total > 0) done.toFloat() / total else 0f
            onProgress(0.65f + 0.3f * f, "Escaneando código...")
        }
        onProgress(0.97f, "Calculando score...")
        return buildReport(apk, info, zip, certs, dex)
    }

    private data class ArchiveData(
        val packageName: String,
        val versionName: String,
        val versionCode: Long,
        val minSdk: Int,
        val targetSdk: Int,
        val debuggable: Boolean,
        val permissions: List<String>,
        val components: List<ComponentInfo>,
        val signatures: List<Signature>,
        val multipleSigners: Boolean
    )

    @Suppress("DEPRECATION")
    private fun readArchiveInfo(pm: PackageManager, apk: File): ArchiveData {
        val flags = PackageManager.GET_ACTIVITIES or
            PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or
            PackageManager.GET_PROVIDERS or
            PackageManager.GET_PERMISSIONS or
            PackageManager.GET_SIGNING_CERTIFICATES
        val info = try {
            pm.getPackageArchiveInfo(apk.absolutePath, flags)
        } catch (e: Exception) {
            throw ApkAnalysisException("No se pudo leer el APK (¿archivo corrupto?).")
        } ?: throw ApkAnalysisException("El archivo no es un APK válido.")

        val app = info.applicationInfo
        // Launcher desde el manifest binario (PackageManager no expone intent-filters).
        val launchers = readManifestLaunchers(apk, info.packageName ?: "")
        val components = mutableListOf<ComponentInfo>()
        info.activities?.forEach {
            components.add(ComponentInfo("Activity", it.name, it.exported, it.name in launchers))
        }
        info.services?.forEach {
            components.add(ComponentInfo("Service", it.name, it.exported))
        }
        info.receivers?.forEach {
            components.add(ComponentInfo("Receiver", it.name, it.exported))
        }
        info.providers?.forEach {
            // Los providers no exponen exported de forma fiable: se marcan según autoridad.
            components.add(ComponentInfo("Provider", it.name + " (${it.authority})", it.exported))
        }

        val signatures: List<Signature>
        val multiple: Boolean
        if (Build.VERSION.SDK_INT >= 28) {
            val signing = info.signingInfo
            signatures = signing?.apkContentsSigners?.toList().orEmpty()
            multiple = signing?.hasMultipleSigners() == true
        } else {
            signatures = info.signatures?.toList().orEmpty()
            multiple = signatures.size > 1
        }

        return ArchiveData(
            packageName = info.packageName ?: "(desconocido)",
            versionName = info.versionName ?: "(sin versión)",
            versionCode = if (Build.VERSION.SDK_INT >= 28) {
                info.longVersionCode
            } else {
                info.versionCode.toLong()
            },
            minSdk = app?.minSdkVersion ?: 0,
            targetSdk = app?.targetSdkVersion ?: 0,
            debuggable = app != null &&
                (app.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0,
            permissions = info.requestedPermissions?.toList().orEmpty(),
            components = components,
            signatures = signatures,
            multipleSigners = multiple
        )
    }

    /** Lee el manifest binario del ZIP y extrae activities lanzadoras. */
    private fun readManifestLaunchers(apk: File, packageName: String): Set<String> {
        if (packageName.isEmpty()) return emptySet()
        val bytes = readManifestBytes(apk) ?: return emptySet()
        return ManifestParser.launcherActivities(bytes, packageName)
    }

    private fun readManifestBytes(apk: File): ByteArray? {
        return try {
            ZipFile(apk).use { zip ->
                val entry = zip.getEntry("AndroidManifest.xml") ?: return null
                if (entry.size < 0 || entry.size > 8L * 1024 * 1024) return null
                zip.getInputStream(entry).use { it.readBytes() }
            }
        } catch (e: Exception) {
            null
        }
    }

    private data class ZipData(
        val zones: List<ZipZone>,
        val dexNames: List<String>,
        val dexCount: Int,
        val hasV1: Boolean,
        val hasV2: Boolean,
        val abis: Set<String>,
        val droppers: List<String>
    )

    private fun readZip(apk: File): ZipData {
        val zones = linkedMapOf<String, Pair<Int, Long>>()
        val dexNames = mutableListOf<String>()
        val entryNames = mutableListOf<String>()
        var hasV1 = false
        try {
            ZipFile(apk).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val e = entries.nextElement()
                    if (e.isDirectory) continue
                    val name = e.name
                    entryNames.add(name)
                    val zone = when {
                        name == "AndroidManifest.xml" -> "Manifest"
                        name == "resources.arsc" -> "Recursos"
                        name.startsWith("classes") && name.endsWith(".dex") -> "Código DEX"
                        name.startsWith("lib/") -> "Nativas lib/"
                        name.startsWith("res/") -> "Recursos res/"
                        name.startsWith("assets/") -> "Assets"
                        name.startsWith("META-INF/") -> "Firma META-INF/"
                        name.startsWith("kotlin/") -> "Kotlin"
                        else -> "Otros"
                    }
                    if (zone == "Código DEX") dexNames.add(name)
                    if (name.startsWith("META-INF/") &&
                        (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC"))
                    ) hasV1 = true
                    val size = if (e.size >= 0) e.size else 0L
                    val (n, b) = zones[zone] ?: (0 to 0L)
                    zones[zone] = (n + 1) to (b + size)
                }
            }
        } catch (e: Exception) {
            throw ApkAnalysisException("El archivo no es un ZIP/APK válido.")
        }
        if (!zones.containsKey("Manifest")) {
            throw ApkAnalysisException("El APK no contiene AndroidManifest.xml.")
        }
        dexNames.sort()
        return ZipData(
            zones = zones.map { ZipZone(it.key, it.value.first, it.value.second) },
            dexNames = dexNames,
            dexCount = dexNames.size,
            hasV1 = hasV1,
            hasV2 = SigningBlock.hasSigningBlock(apk),
            abis = ApkContent.abisOf(entryNames),
            droppers = ApkContent.dropperFiles(entryNames)
        )
    }

    private fun readCerts(info: ArchiveData): List<CertInfo> {
        val factory = try {
            CertificateFactory.getInstance("X.509")
        } catch (e: Exception) {
            return emptyList()
        }
        val fmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)
        val now = System.currentTimeMillis()
        return info.signatures.mapNotNull { sig ->
            try {
                val cert = factory.generateCertificate(
                    sig.toByteArray().inputStream()
                ) as X509Certificate
                val expired = cert.notAfter.time < now
                val soon = !expired && cert.notAfter.time - now < 365L * 24 * 3600 * 1000
                val digest = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
                CertInfo(
                    subject = cert.subjectX500Principal.name,
                    issuer = cert.issuerX500Principal.name,
                    algorithm = cert.sigAlgName ?: "?",
                    sha256 = digest.joinToString("") { "%02X".format(it) },
                    notBefore = fmt.format(Date(cert.notBefore.time)),
                    notAfter = fmt.format(Date(cert.notAfter.time)),
                    expired = expired,
                    expiresSoon = soon
                )
            } catch (e: Exception) {
                null
            }
        }
    }

    private data class DexData(
        val findings: List<DexFinding>,
        val truncated: Boolean,
        val exactAll: Boolean,
        val httpCount: Int,
        val apiCount: Int,
        val trackerCount: Int,
        val crypto: Map<String, Int>,
        val shellCmds: Map<String, Int>,
        val blobs: Map<String, Int>,
        val domains: Domains.Result,
        val classCount: Int,
        val obfuscationPct: Int,
        val filters: List<ManifestParser.FilterInfo>,
        val appFlags: ManifestParser.AppFlags
    )

    private fun scanDex(
        apk: File,
        dexNames: List<String>,
        packageName: String,
        manifestBytes: ByteArray?,
        onBytes: (Long, Long) -> Unit
    ): DexData {
        val totalDex = try {
            ZipFile(apk).use { zip ->
                dexNames.sumOf { zip.getEntry(it)?.size?.coerceAtLeast(0) ?: 0L }
            }
        } catch (e: Exception) {
            0L
        }
        var done = 0L
        val http = linkedSetOf<String>()
        var https = 0
        val httpsUrls = linkedSetOf<String>()
        val ips = linkedMapOf<String, String>()
        val apis = mutableMapOf<String, Int>()
        val trackers = linkedSetOf<String>()
        val secrets = mutableMapOf<String, Int>()
        val envSignals = linkedSetOf<String>()
        val crypto = mutableMapOf<String, Int>()
        val shellCmds = mutableMapOf<String, Int>()
        val blobs = mutableMapOf<String, Int>()
        val classes = linkedSetOf<String>()
        var truncated = false
        var exactAll = true
        try {
            ZipFile(apk).use { zip ->
                for (name in dexNames) {
                    val entry = zip.getEntry(name) ?: continue
                    val size = entry.size.coerceAtLeast(0)
                    // Ruta exacta: parsear la tabla de strings. Si falla o el dex
                    // es muy grande, respaldo al barrido en bruto por bloques.
                    val bytes = if (size in 1..MAX_EXACT_DEX_BYTES) {
                        runCatching {
                            zip.getInputStream(entry).use { it.readBytes() }
                        }.getOrNull()
                    } else null
                    val strings = bytes?.let { DexParser.readStrings(it) }
                    val r = if (strings != null && bytes != null) {
                        onBytes(done + size, totalDex)
                        val methods = DexRefs.readMethods(bytes, strings)
                        if (methods == null) exactAll = false
                        DexRefs.readClasses(bytes, strings)?.let { classes.addAll(it) }
                        DexStrings.scanStrings(strings, methods)
                    } else {
                        exactAll = false
                        zip.getInputStream(entry).use { input ->
                            DexStrings.scan(input) { scanned ->
                                onBytes(done + scanned, totalDex)
                            }
                        }
                    }
                    http.addAll(r.httpUrls)
                    https += r.httpsCount
                    httpsUrls.addAll(r.httpsUrls)
                    r.ips.forEach { ips.putIfAbsent(it.ip, it.context) }
                    r.apis.forEach { (k, v) -> apis[k] = (apis[k] ?: 0) + v }
                    trackers.addAll(r.trackers)
                    r.secrets.forEach { (k, v) -> secrets[k] = (secrets[k] ?: 0) + v }
                    envSignals.addAll(r.envSignals)
                    r.crypto.forEach { (k, v) -> crypto[k] = (crypto[k] ?: 0) + v }
                    r.shellCmds.forEach { (k, v) -> shellCmds[k] = (shellCmds[k] ?: 0) + v }
                    r.blobs.forEach { (k, v) -> blobs[k] = (blobs[k] ?: 0) + v }
                    truncated = truncated || r.truncated
                    done += size
                }
            }
        } catch (e: Exception) {
            // Si un dex no se puede leer, se sigue con un aviso.
        }
        val domains = Domains.analyze((http + httpsUrls).toList())
        val obfuscation = DexRefs.obfuscationPct(classes.toList())
        val filters = manifestBytes?.let {
            ManifestParser.readIntentFilters(it, packageName)
        } ?: emptyList()
        val appFlags = manifestBytes?.let { ManifestParser.readAppFlags(it) }
            ?: ManifestParser.AppFlags(null, null, null, null)

        val list = mutableListOf<DexFinding>()
        if (http.isNotEmpty()) {
            list.add(DexFinding("URL_HTTP", "URLs http:// sin cifrar", http.take(25), http.size))
        }
        if (https > 0) {
            list.add(DexFinding("URLS_HTTPS", "Referencias https://", httpsUrls.take(25), https))
        }
        if (domains.domains.isNotEmpty()) {
            val samples = (domains.domains.take(15) + domains.suspicious.take(10)).distinct()
            list.add(DexFinding("DOMAIN", "Dominios únicos", samples.take(25), domains.domains.size))
        }
        if (ips.isNotEmpty()) {
            val samples = ips.map { (ip, ctx) -> "$ip ‹…$ctx…›" }
            list.add(DexFinding("IP", "Direcciones IP literales", samples.take(25), ips.size))
        }
        apis.forEach { (label, n) ->
            list.add(DexFinding("API", label, emptyList(), n))
        }
        if (classes.isNotEmpty()) {
            val label = if (obfuscation >= 0) {
                "Clases: ${classes.size} (ofuscación $obfuscation%)"
            } else {
                "Clases: ${classes.size}"
            }
            list.add(DexFinding("CLASS", label, classes.take(10).toList(), classes.size))
        }
        if (trackers.isNotEmpty()) {
            list.add(DexFinding("TRACKER", "SDKs de analítica/ads", trackers.take(25), trackers.size))
        }
        secrets.forEach { (label, n) ->
            // Sin muestras: el valor de un secreto jamás se copia al reporte.
            list.add(DexFinding("SECRET", label, emptyList(), n))
        }
        blobs.forEach { (label, n) ->
            list.add(DexFinding("BLOB", label, emptyList(), n))
        }
        crypto.forEach { (label, n) ->
            list.add(DexFinding("CRYPTO", "Cripto débil: $label", emptyList(), n))
        }
        shellCmds.forEach { (label, n) ->
            list.add(DexFinding("CMD", "Comando de shell: $label", emptyList(), n))
        }
        if (envSignals.isNotEmpty()) {
            list.add(
                DexFinding(
                    "ENV", "Menciones a root/análisis (posible detección de entorno)",
                    envSignals.take(25), envSignals.size
                )
            )
        }
        return DexData(
            findings = list,
            truncated = truncated,
            exactAll = exactAll,
            httpCount = http.size,
            apiCount = DexStrings.scoredApiCount(apis),
            trackerCount = trackers.size,
            crypto = crypto,
            shellCmds = shellCmds,
            blobs = blobs,
            domains = domains,
            classCount = classes.size,
            obfuscationPct = obfuscation,
            filters = filters,
            appFlags = appFlags
        )
    }

    private fun buildReport(
        apk: File,
        info: ArchiveData,
        zip: ZipData,
        certs: List<CertInfo>,
        dex: DexData
    ): AuditReport {
        val perms = info.permissions.map { PermissionData.classify(it) }
        val dangerous = perms.count { it.category == PermCategory.PELIGROSO }
        val special = perms.count { it.category == PermCategory.ESPECIAL }
        val exported = Scoring.exportedNonLauncher(info.components)
        val certProblem = certs.any { it.expired || it.expiresSoon }
        val signed = certs.isNotEmpty()

        val scored = Scoring.score(
            ScoreInput(
                dangerousCount = dangerous,
                specialCount = special,
                exportedCount = exported,
                debuggable = info.debuggable,
                targetSdk = info.targetSdk,
                httpUrls = dex.httpCount,
                sensitiveApis = dex.apiCount,
                trackerCount = dex.trackerCount,
                certProblem = certProblem,
                signed = signed
            )
        )

        val findings = mutableListOf<Finding>()
        if (!signed) {
            findings.add(
                Finding("RIESGO", "APK sin firma detectable",
                    "No se encontró certificado. Un APK sin firmar no se puede instalar en Android normal.")
            )
        }
        certs.filter { it.expired }.forEach {
            findings.add(Finding("RIESGO", "Certificado vencido", "Venció el ${it.notAfter}."))
        }
        certs.filter { !it.expired && it.expiresSoon }.forEach {
            findings.add(
                Finding("AVISO", "Certificado por vencer", "Vence el ${it.notAfter}.")
            )
        }
        if (info.debuggable) {
            findings.add(
                Finding("RIESGO", "APK debuggable",
                    "Es una compilación de desarrollo: expone logs y permite depuración.")
            )
        }
        if (dangerous > 0) {
            findings.add(
                Finding("AVISO", "Permisos peligrosos: $dangerous",
                    "Revisa si la app realmente necesita cada uno (ubicación, cámara, SMS...).")
            )
        }
        if (special > 0) {
            findings.add(
                Finding("AVISO", "Permisos especiales: $special",
                    "Son accesos sensibles que Android concede aparte. Verifica que sean su función.")
            )
        }
        if (info.targetSdk > 0 && Scoring.TARGET_BASELINE - info.targetSdk >= 2) {
            findings.add(
                Finding("AVISO", "targetSdk desactualizado (${info.targetSdk})",
                    "La referencia actual es SDK ${Scoring.TARGET_BASELINE} (lo que exige Play). " +
                        "Un target viejo evita protecciones nuevas de Android.")
            )
        }
        if (exported > 0) {
            findings.add(
                Finding("INFO", "Componentes exportados: $exported (sin contar el launcher)",
                    "Otras apps pueden llamarlos. Revisa si cada uno necesita estar expuesto.")
            )
        }
        if (dex.httpCount > 0) {
            findings.add(
                Finding("AVISO", "Tráfico sin cifrar en el código",
                    "Se hallaron ${dex.httpCount} URL(s) http:// en el dex. Usa https://.")
            )
        }
        if (dex.apiCount > 0) {
            findings.add(
                Finding("INFO", "APIs sensibles en el código",
                    "DexClassLoader, exec, reflexión... son legítimas pero revisa su uso.")
            )
        }
        if (dex.trackerCount > 0) {
            findings.add(
                Finding("INFO", "SDKs de rastreo: ${dex.trackerCount}",
                    "Analítica o publicidad detectada por nombre de paquete (indicio, no certeza).")
            )
        }
        val secretTotal = dex.findings.filter { it.kind == "SECRET" }.sumOf { it.count }
        if (secretTotal > 0) {
            findings.add(
                Finding("AVISO", "Posibles secretos en el código: $secretTotal",
                    "Claves o tokens con aspecto real dentro del dex. Cualquiera que abra el APK los lee.")
            )
        }
        if (dex.findings.any { it.kind == "ENV" }) {
            findings.add(
                Finding("INFO", "El código menciona root/análisis",
                    "El APK podría detectar root, emulador o instrumentación antes de correr.")
            )
        }
        if (!dex.exactAll) {
            findings.add(
                Finding("INFO", "Escaneo aproximado en algún dex",
                    "Un dex no se pudo parsear exacto y se barrió en bruto: esos conteos son aproximados.")
            )
        }
        if (zip.hasV1 && zip.hasV2) {
            findings.add(
                Finding("INFO", "Firma v1+v2/v3",
                    "Firma JAR más bloque de firma moderno. Esquema completo.")
            )
        } else if (zip.hasV1) {
            if (info.minSdk in 1..25) {
                findings.add(
                    Finding("AVISO", "Solo firma v1 (Janus)",
                        "Sin bloque v2/v3 y minSdk ${info.minSdk}: instalable en Android < 8.1, " +
                            "vulnerable a Janus (CVE-2017-13156).")
                )
            } else {
                findings.add(
                    Finding("INFO", "Solo firma v1",
                        "Tiene firma JAR (META-INF) pero no bloque v2/v3.")
                )
            }
        } else if (zip.hasV2 && info.minSdk in 1..23) {
            findings.add(
                Finding("AVISO", "Sin firma v1",
                    "Solo trae bloque v2/v3: no instala en Android < 7.0 (minSdk ${info.minSdk}).")
            )
        }
        if (zip.abis.isNotEmpty()) {
            findings.add(
                Finding("INFO", "ABIs nativas: ${zip.abis.sorted().joinToString()}",
                    if (ApkContent.missing64Bit(zip.abis)) {
                        "Solo 32-bit: Play exige 64-bit desde 2019."
                    } else {
                        "Incluye 64-bit."
                    })
            )
            if (ApkContent.missing64Bit(zip.abis)) {
                findings.add(
                    Finding("AVISO", "Nativas sin 64-bit",
                        "Play exige arm64-v8a desde 2019; este APK no lo trae.")
                )
            }
        }
        if (zip.droppers.isNotEmpty()) {
            findings.add(
                Finding("AVISO", "Archivos plantados: ${zip.droppers.size}",
                    "Ejecutables escondidos entre recursos: " +
                        zip.droppers.take(5).joinToString() + ".")
            )
        }
        if (dex.crypto.isNotEmpty()) {
            findings.add(
                Finding("AVISO", "Cripto débil en el código",
                    "Algoritmos rotos o débiles mencionados: " +
                        dex.crypto.keys.joinToString() + ".")
            )
        }
        if (dex.shellCmds.isNotEmpty()) {
            findings.add(
                Finding("INFO", "Comandos de shell en el código",
                    dex.shellCmds.keys.take(5).joinToString() + ". Revisa su uso.")
            )
        }
        if (dex.blobs.isNotEmpty()) {
            findings.add(
                Finding("INFO", "Blobs base64 con contenido",
                    dex.blobs.entries.joinToString { "${it.key} (×${it.value})" } + ".")
            )
        }
        if (dex.domains.suspicious.isNotEmpty()) {
            findings.add(
                Finding("AVISO", "Hosts sospechosos: ${dex.domains.suspicious.size}",
                    dex.domains.suspicious.take(3).joinToString("; ") + ".")
            )
        }
        if (dex.obfuscationPct >= 70 && dex.classCount > 10) {
            findings.add(
                Finding("INFO", "Código ofuscado (${dex.obfuscationPct}%)",
                    "La mayoría de clases tiene nombre corto (R8/ProGuard). " +
                        "El análisis de strings sigue valiendo; las clases no se leen.")
            )
        }
        val schemes = dex.filters.flatMap { it.schemes }.distinct()
        if (schemes.isNotEmpty()) {
            findings.add(
                Finding("INFO", "Deep links/schemes: ${schemes.size}",
                    schemes.take(10).joinToString() + ".")
            )
        }
        dex.filters.forEach { f ->
            f.actions.intersect(ManifestParser.DANGEROUS_ACTIONS).forEach { a ->
                findings.add(
                    Finding("AVISO", "Filtro sensible: ${a.substringAfterLast('.')}",
                        "${f.component} escucha $a.")
                )
            }
        }
        if (dex.appFlags.allowBackup == true) {
            findings.add(
                Finding("AVISO", "allowBackup=true",
                    "Los datos se pueden extraer con adb backup en equipos viejos.")
            )
        }
        if (dex.appFlags.usesCleartextTraffic == true) {
            findings.add(
                Finding("AVISO", "usesCleartextTraffic=true",
                    "La app permite tráfico http:// sin cifrar por manifiesto.")
            )
        }
        if (dex.appFlags.legacyStorage == true) {
            findings.add(
                Finding("AVISO", "requestLegacyExternalStorage=true",
                    "Usa almacenamiento externo amplio (obsoleto desde Android 11).")
            )
        }
        if (dex.truncated) {
            findings.add(
                Finding("INFO", "Escaneo de código parcial",
                    "El dex supera el límite y solo se escaneó el inicio.")
            )
        }
        if (findings.isEmpty()) {
            findings.add(Finding("INFO", "Sin hallazgos", "El APK pasa todas las revisiones."))
        }

        return AuditReport(
            fileName = apk.name,
            sizeBytes = apk.length(),
            dateMillis = System.currentTimeMillis(),
            packageName = info.packageName,
            versionName = info.versionName,
            versionCode = info.versionCode,
            minSdk = info.minSdk,
            targetSdk = info.targetSdk,
            debuggable = info.debuggable,
            permissions = perms,
            components = info.components.sortedWith(
                compareBy({ it.type }, { it.name })
            ),
            zipZones = zip.zones,
            dexCount = zip.dexCount,
            certs = certs,
            hasMultipleSigners = info.multipleSigners,
            dexFindings = dex.findings,
            findings = findings,
            score = scored.total,
            scoreNotes = scored.notes,
            scoreBase = scored.base,
            scoreHeuristic = scored.heuristic
        )
    }
}
