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

    fun analyze(
        pm: PackageManager,
        apk: File,
        currentSdk: Int = Build.VERSION.SDK_INT,
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
        onProgress(0.65f, "Escaneando código...")
        val dex = scanDex(apk, zip.dexNames) { done, total ->
            val f = if (total > 0) done.toFloat() / total else 0f
            onProgress(0.65f + 0.3f * f, "Escaneando código...")
        }
        onProgress(0.97f, "Calculando score...")
        return buildReport(apk, info, zip, certs, dex, currentSdk)
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
        val components = mutableListOf<ComponentInfo>()
        info.activities?.forEach {
            components.add(ComponentInfo("Activity", it.name, it.exported))
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

    private data class ZipData(
        val zones: List<ZipZone>,
        val dexNames: List<String>,
        val dexCount: Int,
        val hasV1: Boolean
    )

    private fun readZip(apk: File): ZipData {
        val zones = linkedMapOf<String, Pair<Int, Long>>()
        val dexNames = mutableListOf<String>()
        var hasV1 = false
        try {
            ZipFile(apk).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val e = entries.nextElement()
                    if (e.isDirectory) continue
                    val name = e.name
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
            hasV1 = hasV1
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
        val httpCount: Int,
        val apiCount: Int,
        val trackerCount: Int
    )

    private fun scanDex(
        apk: File,
        dexNames: List<String>,
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
        val ips = linkedSetOf<String>()
        val apis = mutableMapOf<String, Int>()
        val trackers = linkedSetOf<String>()
        var truncated = false
        try {
            ZipFile(apk).use { zip ->
                for (name in dexNames) {
                    val entry = zip.getEntry(name) ?: continue
                    zip.getInputStream(entry).use { input ->
                        val r = DexStrings.scan(input) { scanned ->
                            onBytes(done + scanned, totalDex)
                        }
                        http.addAll(r.httpUrls)
                        https += r.httpsCount
                        ips.addAll(r.ips)
                        r.apis.forEach { (k, v) -> apis[k] = (apis[k] ?: 0) + v }
                        trackers.addAll(r.trackers)
                        truncated = truncated || r.truncated
                    }
                    done += entry.size.coerceAtLeast(0)
                }
            }
        } catch (e: Exception) {
            // Si un dex no se puede leer, se sigue con un aviso.
        }
        val list = mutableListOf<DexFinding>()
        if (http.isNotEmpty()) {
            list.add(DexFinding("URL_HTTP", "URLs http:// sin cifrar", http.take(25), http.size))
        }
        if (https > 0) {
            list.add(DexFinding("URLS_HTTPS", "Referencias https://", emptyList(), https))
        }
        if (ips.isNotEmpty()) {
            list.add(DexFinding("IP", "Direcciones IP literales", ips.take(25), ips.size))
        }
        apis.forEach { (label, n) ->
            list.add(DexFinding("API", label, emptyList(), n))
        }
        if (trackers.isNotEmpty()) {
            list.add(DexFinding("TRACKER", "SDKs de analítica/ads", trackers.take(25), trackers.size))
        }
        return DexData(list, truncated, http.size, apis.size, trackers.size)
    }

    private fun buildReport(
        apk: File,
        info: ArchiveData,
        zip: ZipData,
        certs: List<CertInfo>,
        dex: DexData,
        currentSdk: Int
    ): AuditReport {
        val perms = info.permissions.map { PermissionData.classify(it) }
        val dangerous = perms.count { it.category == PermCategory.PELIGROSO }
        val special = perms.count { it.category == PermCategory.ESPECIAL }
        val exported = info.components.count { it.exported }
        val certProblem = certs.any { it.expired || it.expiresSoon }
        val signed = certs.isNotEmpty()

        val (score, notes) = Scoring.score(
            ScoreInput(
                dangerousCount = dangerous,
                specialCount = special,
                exportedCount = exported,
                debuggable = info.debuggable,
                targetSdk = info.targetSdk,
                currentSdk = currentSdk,
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
        if (info.targetSdk > 0 && currentSdk - info.targetSdk >= 2) {
            findings.add(
                Finding("AVISO", "targetSdk desactualizado (${info.targetSdk})",
                    "Tu equipo usa SDK $currentSdk. Un target viejo evita protecciones nuevas de Android.")
            )
        }
        if (exported > 0) {
            findings.add(
                Finding("INFO", "Componentes exportados: $exported",
                    "Otras apps pueden llamarlos. Es normal en launchers, revisa el resto.")
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
        if (zip.hasV1) {
            findings.add(
                Finding("INFO", "Firma v1 presente",
                    "Tiene firma JAR (META-INF). Los APKs modernos suelen sumar v2/v3.")
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
            score = score,
            scoreNotes = notes
        )
    }
}
