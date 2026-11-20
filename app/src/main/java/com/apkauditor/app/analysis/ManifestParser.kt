package com.apkauditor.app.analysis

/**
 * Lee el AndroidManifest.xml binario (AXML) directo del APK, sin PackageManager
 * (la API pública no expone intent-filters). Extrae las activities lanzadoras
 * (action MAIN + category LAUNCHER) para no castigarlas como "exportadas".
 *
 * Tolera las dos variantes vistas en la práctica: atributos con resid estándar
 * (aapt/aapt2) y con índice al pool de strings (AIDE). Ante cualquier formato
 * inesperado devuelve lo recolectado (o vacío), nunca lanza.
 * Kotlin puro, sin Android: unit-testeable en JVM.
 */
object ManifestParser {

    const val ACTION_MAIN = "android.intent.action.MAIN"
    const val CATEGORY_LAUNCHER = "android.intent.category.LAUNCHER"

    /** Resid del atributo android:name. */
    const val ATTR_NAME_RESID = 0x01010003

    private const val TYPE_STRING = 3
    private const val MAX_MANIFEST_BYTES = 8 * 1024 * 1024
    private const val MAX_POOL_STRINGS = 100_000
    private const val MAX_STRING_BYTES = 64 * 1024

    fun launcherActivities(manifest: ByteArray, packageName: String): Set<String> {
        if (manifest.size < 8 || manifest.size > MAX_MANIFEST_BYTES) return emptySet()
        if (u16(manifest, 0) != 0x0003) return emptySet()
        return try {
            parse(manifest, packageName)
        } catch (e: Exception) {
            emptySet()
        }
    }

    private fun parse(m: ByteArray, pkg: String): Set<String> {
        val found = linkedSetOf<String>()
        var pool: List<String>? = null
        var off = 8
        // Pila de elementos + estado del activity en curso.
        val stack = ArrayDeque<String>()
        var currentActivity: String? = null
        var inFilter = false
        var hasMain = false
        var hasLauncher = false

        while (off + 8 <= m.size) {
            val type = u16(m, off)
            val size = u32(m, off + 4)
            if (size < 8 || size > m.size - off) break
            when (type) {
                0x0001 -> pool = readPool(m, off, size)
                0x0102 -> {
                    val p = pool ?: emptyList()
                    val name = stringAt(p, u32(m, off + 20))
                    stack.addLast(name)
                    when (name) {
                        "activity", "activity-alias" -> {
                            currentActivity = componentName(m, off, size, p)?.let {
                                resolve(it, pkg)
                            }
                            hasMain = false
                            hasLauncher = false
                        }
                        "intent-filter" -> {
                            if (currentActivity != null) inFilter = true
                        }
                        "action" -> {
                            if (inFilter && attrValue(m, off, size, p) == ACTION_MAIN) {
                                hasMain = true
                            }
                        }
                        "category" -> {
                            if (inFilter && attrValue(m, off, size, p) == CATEGORY_LAUNCHER) {
                                hasLauncher = true
                            }
                        }
                    }
                }
                0x0103 -> {
                    val name = if (stack.isNotEmpty()) stack.removeLast() else ""
                    if (name == "intent-filter") inFilter = false
                    if ((name == "activity" || name == "activity-alias")) {
                        if (hasMain && hasLauncher && currentActivity != null) {
                            found.add(currentActivity!!)
                        }
                        currentActivity = null
                        inFilter = false
                    }
                }
            }
            off += size
        }
        return found
    }

    /** Nombre del componente del atributo android:name del elemento. */
    private fun componentName(m: ByteArray, off: Int, size: Int, pool: List<String>): String? =
        attrValue(m, off, size, pool)

    /** Valor del atributo android:name (resid estándar o índice "name"). */
    private fun attrValue(m: ByteArray, off: Int, size: Int, pool: List<String>): String? {
        val count = u16(m, off + 28)
        if (count < 0 || count > 256) return null
        var a = off + 36
        val end = off + size
        repeat(count) {
            if (a + 20 > end || a + 20 > m.size) return null
            val nm = u32(m, a + 4)
            val dataType = (u32(m, a + 12) ushr 24) and 0xFF
            val data = u32(m, a + 16)
            if (isNameAttr(nm, pool) && data >= 0 && data < pool.size &&
                (dataType == TYPE_STRING || dataType == 0)
            ) {
                return pool[data]
            }
            a += 20
        }
        return null
    }

    private fun isNameAttr(nm: Int, pool: List<String>): Boolean =
        nm == ATTR_NAME_RESID || (nm >= 0 && nm < pool.size && pool[nm] == "name")

    private fun resolve(name: String, pkg: String): String = when {
        name.startsWith(".") -> pkg + name
        name.contains(".") -> name
        else -> "$pkg.$name"
    }

    private fun stringAt(pool: List<String>, ix: Int): String =
        if (ix >= 0 && ix < pool.size) pool[ix] else ""

    private fun readPool(m: ByteArray, off: Int, size: Int): List<String>? {
        if (off + 28 > m.size) return null
        val count = u32(m, off + 8)
        if (count < 0 || count > MAX_POOL_STRINGS) return null
        val flags = u32(m, off + 16)
        val dataStart = off + u32(m, off + 20)
        if (dataStart < 0 || dataStart > m.size) return null
        val utf8 = (flags and 0x100) != 0
        val out = ArrayList<String>(minOf(count, 1024))
        repeat(count) { i ->
            val entry = off + 28 + i * 4
            if (entry + 4 > m.size) return null
            val so = dataStart + u32(m, entry)
            if (so < 0 || so >= m.size) return null
            out.add(if (utf8) readUtf8(m, so) else readUtf16(m, so))
        }
        return out
    }

    private fun readUtf8(m: ByteArray, pos: Int): String {
        var p = pos
        if (p >= m.size) return ""
        // Dos longitudes (chars y bytes), de 1-2 bytes cada una.
        p = skipVarLen(m, p)
        if (p >= m.size) return ""
        val (byteLen, after) = varLen(m, p)
        p = after
        val len = byteLen.coerceAtMost(MAX_STRING_BYTES).coerceAtMost((m.size - p).coerceAtLeast(0))
        return try {
            String(m, p, len, Charsets.UTF_8)
        } catch (e: Exception) {
            ""
        }
    }

    private fun readUtf16(m: ByteArray, pos: Int): String {
        var p = pos
        if (p + 2 > m.size) return ""
        var len = u16(m, p)
        p += 2
        if ((len and 0x8000) != 0) {
            if (p + 2 > m.size) return ""
            len = ((len and 0x7FFF) shl 16) or u16(m, p)
            p += 2
        }
        val bytes = (len * 2).coerceAtMost(MAX_STRING_BYTES).coerceAtMost((m.size - p).coerceAtLeast(0))
        return try {
            String(m, p, bytes, Charsets.UTF_16LE)
        } catch (e: Exception) {
            ""
        }
    }

    private fun varLen(m: ByteArray, p: Int): Pair<Int, Int> {
        if (p >= m.size) return 0 to p
        val b0 = m[p].toInt() and 0xFF
        return if ((b0 and 0x80) == 0) {
            b0 to (p + 1)
        } else {
            if (p + 1 >= m.size) return 0 to (p + 1)
            val b1 = m[p + 1].toInt() and 0xFF
            (((b0 and 0x7F) shl 8) or b1) to (p + 2)
        }
    }

    private fun skipVarLen(m: ByteArray, p: Int): Int = varLen(m, p).second

    private fun u16(m: ByteArray, off: Int): Int {
        if (off < 0 || off + 2 > m.size) return 0
        return (m[off].toInt() and 0xFF) or ((m[off + 1].toInt() and 0xFF) shl 8)
    }

    private fun u32(m: ByteArray, off: Int): Int {
        if (off < 0 || off + 4 > m.size) return 0
        return (m[off].toInt() and 0xFF) or
            (((m[off + 1].toInt() and 0xFF)) shl 8) or
            (((m[off + 2].toInt() and 0xFF)) shl 16) or
            (((m[off + 3].toInt() and 0xFF)) shl 24)
    }
}
