package com.apkauditor.app.analysis

/**
 * Referencias exactas del dex (method_ids, type_ids, class_defs) en vez de
 * substrings: una coincidencia aquí es una llamada real al método, no una
 * palabra suelta en un string. Devuelve null si no se puede parsear.
 * Kotlin puro, sin Android: unit-testeable en JVM.
 */
object DexRefs {

    data class MethodRef(val className: String, val name: String)

    const val MAX_IDS = 1_000_000
    const val MAX_CLASSES = 200_000

    // method_ids -> etiqueta. "*" = cualquier método de esa clase.
    private val exactTable: Map<String, Map<String, String>> = mapOf(
        "Ldalvik/system/DexClassLoader;" to mapOf(
            "<init>" to "Carga dinámica de código (DexClassLoader)",
            "loadClass" to "Carga dinámica de código (DexClassLoader)"
        ),
        "Ldalvik/system/PathClassLoader;" to mapOf(
            "<init>" to "Carga dinámica de código (PathClassLoader)"
        ),
        "Ljava/lang/Runtime;" to mapOf(
            "exec" to "Ejecución de comandos (Runtime.exec)"
        ),
        "Ljava/lang/reflect/Method;" to mapOf(
            "invoke" to "Llamadas por reflexión (Method.invoke)"
        ),
        "Ljava/lang/Class;" to mapOf(
            "forName" to "Reflexión (Class.forName)",
            "getMethod" to "Reflexión (Class.getMethod)",
            "getDeclaredMethod" to "Reflexión (Class.getDeclaredMethod)",
            "getDeclaredField" to "Reflexión (Class.getDeclaredField)"
        ),
        "Landroid/os/Debug;" to mapOf(
            "isDebuggerConnected" to "Detección de depurador (Debug.isDebuggerConnected)"
        ),
        "Ljavax/crypto/Cipher;" to mapOf(
            "getInstance" to "Cifrado (Cipher.getInstance)"
        ),
        "Ljava/security/MessageDigest;" to mapOf(
            "getInstance" to "Hash (MessageDigest.getInstance)"
        ),
        "Ljavax/crypto/spec/SecretKeySpec;" to mapOf(
            "<init>" to "Clave en código (SecretKeySpec)"
        ),
        "Ljavax/crypto/spec/IvParameterSpec;" to mapOf(
            "<init>" to "IV en código (IvParameterSpec)"
        ),
        "Ljava/util/Random;" to mapOf(
            "<init>" to "RNG débil (java.util.Random)",
            "nextBytes" to "RNG débil (java.util.Random)",
            "nextInt" to "RNG débil (java.util.Random)"
        ),
        "Landroid/app/admin/DevicePolicyManager;" to mapOf(
            "*" to "API de administrador del dispositivo"
        ),
        "Landroid/webkit/WebView;" to mapOf(
            "addJavascriptInterface" to
                "Puente JavaScript en WebView (addJavascriptInterface)"
        )
    )

    /** Métodos referenciados (clase + nombre), resueltos vía type_ids. */
    fun readMethods(dex: ByteArray, strings: List<String>): List<MethodRef>? {
        if (dex.size < 0x70) return null
        val typeSize = u32(dex, 0x40)
        val typeOff = u32(dex, 0x44)
        val methodSize = u32(dex, 0x58)
        val methodOff = u32(dex, 0x5C)
        if (!validRange(typeSize, typeOff, 4, dex.size, MAX_IDS)) return null
        if (!validRange(methodSize, methodOff, 8, dex.size, MAX_IDS)) return null
        val out = ArrayList<MethodRef>(minOf(methodSize, 4096))
        repeat(methodSize) { i ->
            val base = methodOff + i * 8
            val classIdx = u16(dex, base)
            val nameIdx = u32(dex, base + 4)
            if (classIdx < 0 || classIdx >= typeSize) return null
            val typeIdx = u32(dex, typeOff + classIdx * 4)
            val cls = strings.getOrNull(typeIdx) ?: return null
            val name = strings.getOrNull(nameIdx) ?: return null
            out.add(MethodRef(cls, name))
        }
        return out
    }

    /** Clases DEFINIDAS en el dex (no solo referenciadas). */
    fun readClasses(dex: ByteArray, strings: List<String>): List<String>? {
        if (dex.size < 0x70) return null
        val typeSize = u32(dex, 0x40)
        val typeOff = u32(dex, 0x44)
        val defSize = u32(dex, 0x60)
        val defOff = u32(dex, 0x64)
        if (!validRange(typeSize, typeOff, 4, dex.size, MAX_IDS)) return null
        if (!validRange(defSize, defOff, 32, dex.size, MAX_CLASSES)) return null
        val out = ArrayList<String>(minOf(defSize, 4096))
        repeat(defSize) { i ->
            val classIdx = u32(dex, defOff + i * 32)
            if (classIdx < 0 || classIdx >= typeSize) return null
            out.add(strings.getOrNull(u32(dex, typeOff + classIdx * 4)) ?: return null)
        }
        return out
    }

    /** Etiquetas sensibles halladas en referencias exactas. */
    fun matchExact(methods: List<MethodRef>): Map<String, Int> {
        val out = mutableMapOf<String, Int>()
        for (m in methods) {
            val byName = exactTable[m.className] ?: continue
            val label = byName[m.name] ?: byName["*"] ?: continue
            out[label] = (out[label] ?: 0) + 1
        }
        return out
    }

    /**
     * % de clases con nombre simple de ≤2 chars (a.a.a;): indicio de
     * ofuscación (R8/ProGuard). -1 si no hay clases.
     */
    fun obfuscationPct(classes: List<String>): Int {
        if (classes.isEmpty()) return -1
        val short = classes.count { simpleName(it).length <= 2 }
        return (short * 100) / classes.size
    }

    private fun simpleName(cls: String): String {
        val noPrefix = if (cls.startsWith("L")) cls.drop(1) else cls
        val noSuffix = noPrefix.removeSuffix(";")
        return noSuffix.substringAfterLast('/').substringAfterLast('.')
    }

    private fun validRange(size: Int, off: Int, entry: Int, fileSize: Int, max: Int): Boolean {
        if (size < 0 || size > max || off < 0) return false
        return off <= fileSize - size * entry
    }

    private fun u16(m: ByteArray, off: Int): Int {
        if (off < 0 || off + 2 > m.size) return -1
        return (m[off].toInt() and 0xFF) or ((m[off + 1].toInt() and 0xFF) shl 8)
    }

    private fun u32(m: ByteArray, off: Int): Int {
        if (off < 0 || off + 4 > m.size) return -1
        return (m[off].toInt() and 0xFF) or
            (((m[off + 1].toInt() and 0xFF)) shl 8) or
            (((m[off + 2].toInt() and 0xFF)) shl 16) or
            (((m[off + 3].toInt() and 0xFF)) shl 24)
    }
}
