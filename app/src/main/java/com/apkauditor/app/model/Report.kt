package com.apkauditor.app.model

/** Categoría de un permiso Android. */
enum class PermCategory { NORMAL, PELIGROSO, ESPECIAL, FIRMA, DESCONOCIDO }

/** Un permiso solicitado por el APK. */
data class PermInfo(
    val name: String,
    val category: PermCategory,
    val explanation: String
)

/** Un componente declarado (activity, service, receiver, provider). */
data class ComponentInfo(
    val type: String, // "Activity", "Service", "Receiver", "Provider"
    val name: String,
    val exported: Boolean,
    val isLauncher: Boolean = false
)

/** Resumen de una zona del ZIP del APK. */
data class ZipZone(
    val name: String,
    val files: Int,
    val bytes: Long
)

/** Certificado de firma. */
data class CertInfo(
    val subject: String,
    val issuer: String,
    val algorithm: String,
    val sha256: String,
    val notBefore: String,
    val notAfter: String,
    val expired: Boolean,
    val expiresSoon: Boolean // vence en menos de 1 año
)

/** Hallazgo de ingeniería inversa sobre el dex. */
data class DexFinding(
    val kind: String, // "URL_HTTP", "URLS_HTTPS", "DOMAIN", "IP", "API", "CLASS",
    // "TRACKER", "SECRET", "BLOB", "CRYPTO", "CMD", "ENV"
    val label: String,
    val samples: List<String>,
    val count: Int
)

/** Un riesgo o recomendación con severidad. */
data class Finding(
    val severity: String, // "INFO", "AVISO", "RIESGO"
    val title: String,
    val detail: String
)

/** Reporte completo de una auditoría. */
data class AuditReport(
    val fileName: String,
    val sizeBytes: Long,
    val dateMillis: Long,
    val packageName: String,
    val versionName: String,
    val versionCode: Long,
    val minSdk: Int,
    val targetSdk: Int,
    val debuggable: Boolean,
    val permissions: List<PermInfo>,
    val components: List<ComponentInfo>,
    val zipZones: List<ZipZone>,
    val dexCount: Int,
    val certs: List<CertInfo>,
    val hasMultipleSigners: Boolean,
    val dexFindings: List<DexFinding>,
    val findings: List<Finding>,
    val score: Int,
    val scoreNotes: List<String>,
    val scoreBase: Int = 100,
    val scoreHeuristic: Int = 0
)
