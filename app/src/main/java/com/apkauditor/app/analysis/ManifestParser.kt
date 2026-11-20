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
    const val ATTR_SCHEME_RESID = 0x01010027
    const val ATTR_DEBUGGABLE_RESID = 0x0101000F
    const val ATTR_ALLOWBACKUP_RESID = 0x01010280
    const val ATTR_CLEARTEXT_RESID = 0x010104EC
    const val ATTR_LEGACYSTORAGE_RESID = 0x01010603

    /** Acciones de broadcast sensibles (arranque, SMS, llamadas, admin). */
    val DANGEROUS_ACTIONS = setOf(
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.SMS_RECEIVED",
        "android.intent.action.WAP_PUSH_RECEIVED",
        "android.intent.action.NEW_OUTGOING_CALL",
        "android.app.action.DEVICE_ADMIN_ENABLED"
    )

    /** Un intent-filter con su componente dueño. */
    data class FilterInfo(
        val component: String,
        val actions: List<String>,
        val categories: List<String>,
        val schemes: List<String>
    )

    /** Flags del elemento application (null = no declarado). */
    data class AppFlags(
        val debuggable: Boolean?,
        val allowBackup: Boolean?,
        val usesCleartextTraffic: Boolean?,
        val legacyStorage: Boolean?
    )

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

    private data class Attr(val ns: Int, val name: Int, val dataType: Int, val data: Int)

    private fun parse(m: ByteArray, pkg: String): Set<String> {
        val found = linkedSetOf<String>()
        var currentActivity: String? = null
        var inFilter = false
        var hasMain = false
        var hasLauncher = false
        walk(m) { start, name, attrs, pool ->
            if (start) {
                when (name) {
                    "activity", "activity-alias" -> {
                        currentActivity = stringAttr(attrs, pool, ATTR_NAME_RESID, "name")
                            ?.let { resolve(it, pkg) }
                        hasMain = false
                        hasLauncher = false
                    }
                    "intent-filter" -> {
                        if (currentActivity != null) inFilter = true
                    }
                    "action" -> {
                        if (inFilter &&
                            stringAttr(attrs, pool, ATTR_NAME_RESID, "name") == ACTION_MAIN
                        ) hasMain = true
                    }
                    "category" -> {
                        if (inFilter &&
                            stringAttr(attrs, pool, ATTR_NAME_RESID, "name") == CATEGORY_LAUNCHER
                        ) hasLauncher = true
                    }
                }
            } else {
                if (name == "intent-filter") inFilter = false
                if (name == "activity" || name == "activity-alias") {
                    if (hasMain && hasLauncher && currentActivity != null) {
                        found.add(currentActivity!!)
                    }
                    currentActivity = null
                    inFilter = false
                }
            }
        }
        return found
    }

    /** Todos los intent-filters con componente, acciones, categorías y schemes. */
    fun readIntentFilters(manifest: ByteArray, packageName: String): List<FilterInfo> {
        if (manifest.size < 8 || manifest.size > MAX_MANIFEST_BYTES) return emptyList()
        if (u16(manifest, 0) != 0x0003) return emptyList()
        return try {
            val out = mutableListOf<FilterInfo>()
            var current: String? = null
            var actions = mutableListOf<String>()
            var categories = mutableListOf<String>()
            var schemes = mutableListOf<String>()
            var inFilter = false
            walk(manifest) { start, name, attrs, pool ->
                if (start) {
                    when (name) {
                        "activity", "activity-alias", "service", "receiver", "provider" -> {
                            current = stringAttr(attrs, pool, ATTR_NAME_RESID, "name")
                                ?.let { resolve(it, packageName) }
                        }
                        "intent-filter" -> {
                            if (current != null) {
                                inFilter = true
                                actions = mutableListOf()
                                categories = mutableListOf()
                                schemes = mutableListOf()
                            }
                        }
                        "action" -> {
                            if (inFilter) stringAttr(attrs, pool, ATTR_NAME_RESID, "name")
                                ?.let { actions.add(it) }
                        }
                        "category" -> {
                            if (inFilter) stringAttr(attrs, pool, ATTR_NAME_RESID, "name")
                                ?.let { categories.add(it) }
                        }
                        "data" -> {
                            if (inFilter) stringAttr(attrs, pool, ATTR_SCHEME_RESID, "scheme")
                                ?.let { schemes.add(it) }
                        }
                    }
                } else {
                    if (name == "intent-filter" && inFilter && current != null) {
                        out.add(FilterInfo(current!!, actions.toList(), categories.toList(), schemes.toList()))
                        inFilter = false
                    }
                    if (name in COMPONENTS) current = null
                }
            }
            out
        } catch (e: Exception) {
            emptyList()
        }
    }

    /** Flags del elemento application (null = no declarado). */
    fun readAppFlags(manifest: ByteArray): AppFlags {
        if (manifest.size < 8 || manifest.size > MAX_MANIFEST_BYTES) {
            return AppFlags(null, null, null, null)
        }
        if (u16(manifest, 0) != 0x0003) return AppFlags(null, null, null, null)
        return try {
            var flags = AppFlags(null, null, null, null)
            walk(manifest) { start, name, attrs, pool ->
                if (start && name == "application") {
                    flags = AppFlags(
                        boolAttr(attrs, pool, ATTR_DEBUGGABLE_RESID, "debuggable"),
                        boolAttr(attrs, pool, ATTR_ALLOWBACKUP_RESID, "allowBackup"),
                        boolAttr(attrs, pool, ATTR_CLEARTEXT_RESID, "usesCleartextTraffic"),
                        boolAttr(attrs, pool, ATTR_LEGACYSTORAGE_RESID, "requestLegacyExternalStorage")
                    )
                }
            }
            flags
        } catch (e: Exception) {
            AppFlags(null, null, null, null)
        }
    }

    private val COMPONENTS = setOf("activity", "activity-alias", "service", "receiver", "provider")

    /**
     * Camina los elementos del AXML. Por cada START/END entrega nombre,
     * atributos crudos y pool de strings.
     */
    private fun walk(
        m: ByteArray,
        fn: (start: Boolean, name: String, attrs: List<Attr>, pool: List<String>) -> Unit
    ) {
        var pool: List<String>? = null
        var off = 8
        while (off + 8 <= m.size) {
            val type = u16(m, off)
            val size = u32(m, off + 4)
            if (size < 8 || size > m.size - off) break
            when (type) {
                0x0001 -> pool = readPool(m, off, size)
                0x0102 -> {
                    val p = pool ?: emptyList()
                    fn(true, stringAt(p, u32(m, off + 20)), readAttrs(m, off, size), p)
                }
                0x0103 -> {
                    val p = pool ?: emptyList()
                    fn(false, stringAt(p, u32(m, off + 20)), emptyList(), p)
                }
            }
            off += size
        }
    }

    private fun readAttrs(m: ByteArray, off: Int, size: Int): List<Attr> {
        val count = u16(m, off + 28)
        if (count < 0 || count > 256) return emptyList()
        val out = ArrayList<Attr>(count)
        var a = off + 36
        val end = minOf(off + size, m.size)
        repeat(count) {
            if (a + 20 > end) return out
            out.add(
                Attr(
                    u32(m, a), u32(m, a + 4),
                    (u32(m, a + 12) ushr 24) and 0xFF, u32(m, a + 16)
                )
            )
            a += 20
        }
        return out
    }

    /** Valor string de un atributo (resid estándar o nombre en el pool). */
    private fun stringAttr(
        attrs: List<Attr>, pool: List<String>, resid: Int, altName: String
    ): String? {
        val a = attrs.firstOrNull { matches(it.name, pool, resid, altName) } ?: return null
        if (a.data < 0 || a.data >= pool.size) return null
        return if (a.dataType == TYPE_STRING || a.dataType == 0) pool[a.data] else null
    }

    /** Valor booleano de un atributo (null = no declarado o no booleano). */
    private fun boolAttr(
        attrs: List<Attr>, pool: List<String>, resid: Int, altName: String
    ): Boolean? {
        val a = attrs.firstOrNull { matches(it.name, pool, resid, altName) } ?: return null
        // 0x10-0x12 = enteros/bool tipados; 0 = entero sin tipo (AIDE).
        if (a.dataType in 0x10..0x12) return a.data != 0
        if (a.dataType == 0 && a.data in 0..1) return a.data != 0
        if (a.dataType == 0 && a.data == -1) return true // AIDE escribe -1 como true
        return null
    }

    private fun matches(nm: Int, pool: List<String>, resid: Int, altName: String): Boolean =
        nm == resid || (nm >= 0 && nm < pool.size && pool[nm] == altName)

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
