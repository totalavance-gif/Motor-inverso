package com.apkauditor.app.data

import android.graphics.Paint
import android.graphics.pdf.PdfDocument
import com.apkauditor.app.analysis.Format
import com.apkauditor.app.model.AuditReport
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Exporta el reporte a Markdown (texto) y PDF (con PdfDocument del sistema). */
object ReportExporter {

    private val dateFmt = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)

    fun toMarkdown(r: AuditReport): String {
        val sb = StringBuilder()
        sb.appendLine("# Auditoría APK: ${r.fileName}")
        sb.appendLine()
        sb.appendLine("- Paquete: `${r.packageName}`")
        sb.appendLine("- Versión: ${r.versionName} (${r.versionCode})")
        sb.appendLine("- Tamaño: ${Format.humanSize(r.sizeBytes)}")
        sb.appendLine("- Fecha: ${dateFmt.format(Date(r.dateMillis))}")
        sb.appendLine("- minSdk: ${sdkOrUnknown(r.minSdk)} · targetSdk: ${sdkOrUnknown(r.targetSdk)}")
        sb.appendLine("- Debuggable: ${if (r.debuggable) "sí" else "no"}")
        val breakdown = if (r.scoreHeuristic > 0) {
            " (base ${r.scoreBase}, heurístico -${r.scoreHeuristic})"
        } else ""
        sb.appendLine("- **Score: ${r.score}/100**$breakdown")
        sb.appendLine()
        sb.appendLine("## Score")
        r.scoreNotes.forEach { sb.appendLine("- $it") }
        sb.appendLine()
        sb.appendLine("## Riesgos y recomendaciones")
        r.findings.forEach { sb.appendLine("- **[${it.severity}] ${it.title}**: ${it.detail}") }
        sb.appendLine()
        sb.appendLine("## Permisos (${r.permissions.size})")
        r.permissions.forEach {
            sb.appendLine("- `[${it.category}]` `${it.name}` — ${it.explanation}")
        }
        sb.appendLine()
        sb.appendLine("## Componentes (${r.components.size})")
        r.components.forEach {
            val launcher = if (it.isLauncher) ", launcher" else ""
            sb.appendLine("- ${it.type}: `${it.name}` (exportado: ${it.exported}$launcher)")
        }
        sb.appendLine()
        sb.appendLine("## Archivos del APK")
        r.zipZones.forEach {
            sb.appendLine("- ${it.name}: ${it.files} archivos, ${Format.humanSize(it.bytes)}")
        }
        sb.appendLine("- Archivos dex: ${r.dexCount}")
        sb.appendLine()
        sb.appendLine("## Firma")
        if (r.certs.isEmpty()) {
            sb.appendLine("- Sin certificado detectable.")
        }
        r.certs.forEach {
            sb.appendLine("- Sujeto: ${it.subject}")
            sb.appendLine("  - Emisor: ${it.issuer}")
            sb.appendLine("  - Algoritmo: ${it.algorithm}")
            sb.appendLine("  - SHA-256: ${it.sha256}")
            sb.appendLine("  - Vigencia: ${it.notBefore} → ${it.notAfter}")
        }
        sb.appendLine()
        sb.appendLine("## Ingeniería inversa (dex)")
        if (r.dexFindings.isEmpty()) {
            sb.appendLine("- Sin hallazgos.")
        }
        r.dexFindings.forEach {
            sb.appendLine("- ${it.label}: ${it.count}")
            it.samples.take(10).forEach { s -> sb.appendLine("  - `$s`") }
        }
        return sb.toString()
    }

    /** Escribe el Markdown como PDF simple multipágina. */
    fun writePdf(r: AuditReport, out: OutputStream) {
        val doc = PdfDocument()
        val paint = Paint().apply { textSize = 11f }
        val titlePaint = Paint().apply { textSize = 16f; isFakeBoldText = true }
        val pageW = 595
        val pageH = 842
        val margin = 40f
        val lineH = 15f
        val usableW = pageW - margin * 2

        val lines = toMarkdown(r).lines()
        var idx = 0
        var pageNum = 1
        while (idx < lines.size) {
            val pageInfo = PdfDocument.PageInfo.Builder(pageW, pageH, pageNum).create()
            val page = doc.startPage(pageInfo)
            val canvas = page.canvas
            var y = margin + 10f
            if (pageNum == 1) {
                canvas.drawText("Auditoría APK — ${r.fileName}".take(60), margin, y, titlePaint)
                y += lineH * 2
            }
            while (idx < lines.size && y < pageH - margin) {
                var line = lines[idx].take(400)
                // Corte simple por ancho.
                while (paint.measureText(line) > usableW && line.length > 10) {
                    line = line.dropLast(10)
                }
                canvas.drawText(line.ifEmpty { " " }, margin, y, paint)
                y += lineH
                idx++
            }
            doc.finishPage(page)
            pageNum++
        }
        doc.writeTo(out)
        doc.close()
    }

    private fun sdkOrUnknown(v: Int): String = if (v > 0) v.toString() else "?"
}
