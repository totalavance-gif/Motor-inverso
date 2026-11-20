package com.apkauditor.app.analysis

/**
 * Dominios únicos extraídos de las URLs + marcas de hosts sospechosos.
 * Opera sobre URLs ya validadas. Kotlin puro: unit-testeable en JVM.
 */
object Domains {

    data class Result(
        val domains: List<String>,
        val suspicious: List<String> // "host — motivo"
    )

    private val riskyTlds = setOf("top", "xyz", "tk", "ml", "ga", "cf", "gq", "onion", "su", "biz")

    fun analyze(urls: List<String>): Result {
        val domains = linkedSetOf<String>()
        val suspicious = linkedSetOf<String>()
        for (url in urls) {
            val host = hostOf(url) ?: continue
            domains.add(host.lowercase())
            flag(url, host)?.let { suspicious.add("$host — $it") }
        }
        return Result(domains.toList(), suspicious.toList())
    }

    private fun hostOf(url: String): String? {
        val rest = url.substringAfter("://", "")
        if (rest.isEmpty()) return null
        val authority = rest.substringBefore('/').substringBefore('?').substringBefore('#')
        val noUser = authority.substringAfterLast('@')
        val host = if (noUser.startsWith("[")) {
            noUser.substringBefore(']') + "]" // IPv6 literal
        } else {
            noUser.substringBefore(':')
        }
        return host.ifEmpty { null }
    }

    private fun portOf(url: String): Int? {
        val rest = url.substringAfter("://", "")
        val authority = rest.substringBefore('/').substringBefore('?').substringBefore('#')
        val noUser = authority.substringAfterLast('@')
        if (noUser.startsWith("[")) {
            return noUser.substringAfter("]:", "").toIntOrNull()
        }
        val parts = noUser.split(":")
        if (parts.size != 2) return null
        return parts[1].toIntOrNull()
    }

    private fun flag(url: String, host: String): String? {
        val lower = host.lowercase()
        if (isIpLiteral(lower)) return "host es IP literal"
        val authority = url.substringAfter("://", "").substringBefore('/')
        if ("@" in authority) return "trae usuario/clave en la URL"
        val port = portOf(url)
        val default = if (url.startsWith("https://", ignoreCase = true)) 443 else 80
        if (port != null && port != default) return "puerto no estándar ($port)"
        if (lower.startsWith("xn--") || ".xn--" in lower) return "dominio con punycode"
        val tld = lower.substringAfterLast('.', "")
        if (tld in riskyTlds) return "TLD de riesgo (.$tld)"
        return null
    }

    private fun isIpLiteral(host: String): Boolean {
        if (host.startsWith("[") && host.endsWith("]")) return true
        if (':' in host) return true // IPv6 sin corchetes
        val parts = host.split(".")
        return parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 }
    }
}
