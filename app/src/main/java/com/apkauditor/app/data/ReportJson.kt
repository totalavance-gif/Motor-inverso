package com.apkauditor.app.data

import com.apkauditor.app.model.AuditReport
import com.apkauditor.app.model.CertInfo
import com.apkauditor.app.model.ComponentInfo
import com.apkauditor.app.model.DexFinding
import com.apkauditor.app.model.Finding
import com.apkauditor.app.model.PermCategory
import com.apkauditor.app.model.PermInfo
import com.apkauditor.app.model.ZipZone
import org.json.JSONArray
import org.json.JSONObject

/** Serializa el reporte con org.json (incluido en Android, sin dependencias). */
object ReportJson {

    fun toJson(r: AuditReport): String {
        val o = JSONObject()
        o.put("fileName", r.fileName)
        o.put("sizeBytes", r.sizeBytes)
        o.put("dateMillis", r.dateMillis)
        o.put("packageName", r.packageName)
        o.put("versionName", r.versionName)
        o.put("versionCode", r.versionCode)
        o.put("minSdk", r.minSdk)
        o.put("targetSdk", r.targetSdk)
        o.put("debuggable", r.debuggable)
        o.put("dexCount", r.dexCount)
        o.put("hasMultipleSigners", r.hasMultipleSigners)
        o.put("score", r.score)
        o.put("scoreBase", r.scoreBase)
        o.put("scoreHeuristic", r.scoreHeuristic)
        o.put("permissions", JSONArray().apply {
            r.permissions.forEach {
                put(JSONObject().put("name", it.name)
                    .put("category", it.category.name)
                    .put("explanation", it.explanation))
            }
        })
        o.put("components", JSONArray().apply {
            r.components.forEach {
                put(JSONObject().put("type", it.type)
                    .put("name", it.name)
                    .put("exported", it.exported)
                    .put("isLauncher", it.isLauncher))
            }
        })
        o.put("zipZones", JSONArray().apply {
            r.zipZones.forEach {
                put(JSONObject().put("name", it.name)
                    .put("files", it.files)
                    .put("bytes", it.bytes))
            }
        })
        o.put("certs", JSONArray().apply {
            r.certs.forEach {
                put(JSONObject().put("subject", it.subject)
                    .put("issuer", it.issuer)
                    .put("algorithm", it.algorithm)
                    .put("sha256", it.sha256)
                    .put("notBefore", it.notBefore)
                    .put("notAfter", it.notAfter)
                    .put("expired", it.expired)
                    .put("expiresSoon", it.expiresSoon))
            }
        })
        o.put("dexFindings", JSONArray().apply {
            r.dexFindings.forEach {
                put(JSONObject().put("kind", it.kind)
                    .put("label", it.label)
                    .put("count", it.count)
                    .put("samples", JSONArray(it.samples)))
            }
        })
        o.put("findings", JSONArray().apply {
            r.findings.forEach {
                put(JSONObject().put("severity", it.severity)
                    .put("title", it.title)
                    .put("detail", it.detail))
            }
        })
        o.put("scoreNotes", JSONArray(r.scoreNotes))
        return o.toString()
    }

    fun fromJson(json: String): AuditReport {
        val o = JSONObject(json)
        fun joArray(key: String): List<JSONObject> {
            val a = o.optJSONArray(key) ?: JSONArray()
            return (0 until a.length()).map { a.getJSONObject(it) }
        }
        return AuditReport(
            fileName = o.optString("fileName"),
            sizeBytes = o.optLong("sizeBytes"),
            dateMillis = o.optLong("dateMillis"),
            packageName = o.optString("packageName"),
            versionName = o.optString("versionName"),
            versionCode = o.optLong("versionCode"),
            minSdk = o.optInt("minSdk"),
            targetSdk = o.optInt("targetSdk"),
            debuggable = o.optBoolean("debuggable"),
            permissions = joArray("permissions").map {
                PermInfo(
                    it.optString("name"),
                    runCatching { PermCategory.valueOf(it.optString("category")) }
                        .getOrDefault(PermCategory.DESCONOCIDO),
                    it.optString("explanation")
                )
            },
            components = joArray("components").map {
                ComponentInfo(
                    it.optString("type"), it.optString("name"),
                    it.optBoolean("exported"), it.optBoolean("isLauncher")
                )
            },
            zipZones = joArray("zipZones").map {
                ZipZone(it.optString("name"), it.optInt("files"), it.optLong("bytes"))
            },
            dexCount = o.optInt("dexCount"),
            certs = joArray("certs").map {
                CertInfo(
                    it.optString("subject"), it.optString("issuer"),
                    it.optString("algorithm"), it.optString("sha256"),
                    it.optString("notBefore"), it.optString("notAfter"),
                    it.optBoolean("expired"), it.optBoolean("expiresSoon")
                )
            },
            hasMultipleSigners = o.optBoolean("hasMultipleSigners"),
            dexFindings = joArray("dexFindings").map {
                val samples = it.optJSONArray("samples") ?: JSONArray()
                DexFinding(
                    it.optString("kind"), it.optString("label"),
                    (0 until samples.length()).map { i -> samples.optString(i) },
                    it.optInt("count")
                )
            },
            findings = joArray("findings").map {
                Finding(it.optString("severity"), it.optString("title"), it.optString("detail"))
            },
            score = o.optInt("score"),
            scoreNotes = (o.optJSONArray("scoreNotes") ?: JSONArray()).let { a ->
                (0 until a.length()).map { i -> a.optString(i) }
            },
            scoreBase = o.optInt("scoreBase", o.optInt("score")),
            scoreHeuristic = o.optInt("scoreHeuristic")
        )
    }
}
