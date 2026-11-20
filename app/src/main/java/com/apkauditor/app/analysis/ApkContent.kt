package com.apkauditor.app.analysis

/**
 * Señales del contenido del ZIP: ABIs nativas y archivos plantados
 * (posibles droppers). Opera sobre nombres de entradas. Kotlin puro.
 */
object ApkContent {

    /** ABIs: segundo segmento de las entradas bajo lib. */
    fun abisOf(entries: List<String>): Set<String> =
        entries.mapNotNull {
            if (it.startsWith("lib/")) it.removePrefix("lib/").substringBefore('/').ifEmpty { null }
            else null
        }.toSet()

    /** Hay nativas pero ninguna de 64 bits (Play exige 64-bit desde 2019). */
    fun missing64Bit(abis: Set<String>): Boolean =
        abis.isNotEmpty() && "arm64-v8a" !in abis && "x86_64" !in abis

    private val payloadExt = setOf(".apk", ".dex", ".jar", ".so", ".odex", ".vdex", ".oat")
    private val classesDex = Regex("classes\\d*\\.dex")

    /**
     * Archivos con pinta de plantados: ejecutables escondidos en assets/res
     * o dex fuera de classesN.dex.
     */
    fun dropperFiles(entries: List<String>): List<String> =
        entries.filter { e ->
            if (e.endsWith("/")) return@filter false
            val lower = e.lowercase()
            val ext = lower.substringAfterLast('.', "")
            val inPayloadDir = lower.startsWith("assets/") ||
                lower.startsWith("res/raw/") || lower.startsWith("res/")
            when {
                // Dex en raíz que no es classes.dex: sospechoso.
                lower.endsWith(".dex") && !lower.contains("/") && !classesDex.matches(lower) -> true
                // Ejecutable escondido entre recursos.
                inPayloadDir && ".$ext" in payloadExt -> true
                else -> false
            }
        }.distinct().take(25)
}
