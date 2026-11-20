package com.apkauditor.app.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.apkauditor.app.analysis.Format
import com.apkauditor.app.model.AuditReport
import com.apkauditor.app.model.PermCategory
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ReportScreen(
    auditId: Long,
    viewModel: AuditViewModel,
    onBack: () -> Unit
) {
    var report by remember { mutableStateOf<AuditReport?>(null) }
    var notFound by remember { mutableStateOf(false) }
    val snacks = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    LaunchedEffect(auditId) {
        report = viewModel.loadReport(auditId)
        if (report == null) notFound = true
    }

    val mdSaver = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/markdown")
    ) { uri: Uri? ->
        if (uri != null) scope.launch {
            runCatching { viewModel.exportMarkdown(auditId, uri) }
                .onSuccess { snacks.showSnackbar(it) }
                .onFailure { snacks.showSnackbar("Error: ${it.message}") }
        }
    }
    val pdfSaver = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/pdf")
    ) { uri: Uri? ->
        if (uri != null) scope.launch {
            runCatching { viewModel.exportPdf(auditId, uri) }
                .onSuccess { snacks.showSnackbar(it) }
                .onFailure { snacks.showSnackbar("Error: ${it.message}") }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Reporte", maxLines = 1) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Atrás")
                    }
                }
            )
        },
        snackbarHost = { SnackbarHost(snacks) }
    ) { pad ->
        val r = report
        when {
            r == null && !notFound -> Column(
                Modifier
                    .fillMaxSize()
                    .padding(pad),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                CircularProgressIndicator()
            }
            r == null -> Column(
                Modifier
                    .fillMaxSize()
                    .padding(pad)
                    .padding(16.dp)
            ) {
                Text("Reporte no encontrado. Quizá fue borrado del historial.")
            }
            else -> LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(pad)
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                item { SummaryCard(r) }
                item { FindingsCard(r) }
                item {
                    ExpandableCard("Permisos (${r.permissions.size})") {
                        if (r.permissions.isEmpty()) Text("No solicita permisos.")
                        r.permissions.forEach { p ->
                            Text(
                                "[${label(p.category)}] ${p.name}",
                                fontWeight = FontWeight.SemiBold,
                                style = MaterialTheme.typography.bodySmall
                            )
                            Text(
                                p.explanation,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(Modifier.height(6.dp))
                        }
                    }
                }
                item {
                    ExpandableCard("Componentes (${r.components.size})") {
                        if (r.components.isEmpty()) Text("Sin componentes declarados.")
                        val groups = r.components.groupBy { it.type }
                        groups.forEach { (type, list) ->
                            Text(type, fontWeight = FontWeight.Bold)
                            list.forEach {
                                Text(
                                    "• ${it.name}  [exportado: ${it.exported}]",
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                            Spacer(Modifier.height(6.dp))
                        }
                    }
                }
                item {
                    ExpandableCard("Archivos del APK") {
                        r.zipZones.forEach {
                            Text("• ${it.name}: ${it.files} archivos, ${human(it.bytes)}")
                        }
                        Text("• Archivos dex: ${r.dexCount}")
                    }
                }
                item {
                    ExpandableCard("Firma (${r.certs.size})") {
                        if (r.certs.isEmpty()) {
                            Text("Sin certificado detectable.")
                        }
                        r.certs.forEach { c ->
                            Text("Sujeto: ${c.subject}", style = MaterialTheme.typography.bodySmall)
                            Text("Emisor: ${c.issuer}", style = MaterialTheme.typography.bodySmall)
                            Text(
                                "Algoritmo: ${c.algorithm}",
                                style = MaterialTheme.typography.bodySmall
                            )
                            Text(
                                "SHA-256: ${c.sha256}",
                                style = MaterialTheme.typography.bodySmall
                            )
                            Text(
                                "Vigencia: ${c.notBefore} → ${c.notAfter}" +
                                    if (c.expired) " (VENCIDO)" else "",
                                style = MaterialTheme.typography.bodySmall
                            )
                            Spacer(Modifier.height(6.dp))
                        }
                        Text(
                            "Múltiples firmantes: ${r.hasMultipleSigners}",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
                item {
                    ExpandableCard("Ingeniería inversa (${r.dexFindings.size})") {
                        if (r.dexFindings.isEmpty()) Text("Sin hallazgos en el código.")
                        r.dexFindings.forEach { f ->
                            Text(
                                "${f.label}: ${f.count}",
                                fontWeight = FontWeight.SemiBold,
                                style = MaterialTheme.typography.bodySmall
                            )
                            f.samples.take(15).forEach { s ->
                                Text(
                                    "• $s",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Spacer(Modifier.height(6.dp))
                        }
                    }
                }
                item {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = { mdSaver.launch("${r.packageName}-reporte.md") },
                            modifier = Modifier.weight(1f)
                        ) { Text("Exportar MD") }
                        Button(
                            onClick = { pdfSaver.launch("${r.packageName}-reporte.pdf") },
                            modifier = Modifier.weight(1f)
                        ) { Text("Exportar PDF") }
                    }
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(
                        onClick = {
                            val ok = viewModel.deleteTemp()
                            scope.launch {
                                snacks.showSnackbar(
                                    if (ok) "Archivo temporal borrado."
                                    else "No hay temporal pendiente."
                                )
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text("Borrar archivo temporal") }
                }
            }
        }
    }
}

@Composable
private fun SummaryCard(r: AuditReport) {
    val date = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)
        .format(Date(r.dateMillis))
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Resumen", style = MaterialTheme.typography.titleLarge)
                ScoreBadge(r.score)
            }
            Spacer(Modifier.height(8.dp))
            Text("Archivo: ${r.fileName}")
            Text("Tamaño: ${Format.humanSize(r.sizeBytes)}")
            Text("Fecha: $date")
            Text("Paquete: ${r.packageName}")
            Text("Versión: ${r.versionName} (${r.versionCode})")
            Text("minSdk: ${sdk(r.minSdk)} · targetSdk: ${sdk(r.targetSdk)}")
            Text("Debuggable: ${if (r.debuggable) "sí" else "no"}")
            Spacer(Modifier.height(8.dp))
            Text("Por qué este score:", fontWeight = FontWeight.SemiBold)
            if (r.scoreHeuristic > 0) {
                Text(
                    "Base: ${r.scoreBase} · heurístico: -${r.scoreHeuristic}",
                    style = MaterialTheme.typography.bodySmall
                )
            }
            r.scoreNotes.forEach {
                Text("• $it", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun FindingsCard(r: AuditReport) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text("Riesgos y recomendaciones", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            r.findings.forEach { f ->
                val color = when (f.severity) {
                    "RIESGO" -> MaterialTheme.colorScheme.error
                    "AVISO" -> MaterialTheme.colorScheme.tertiary
                    else -> MaterialTheme.colorScheme.primary
                }
                Card(
                    colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.12f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(8.dp)) {
                        Text(
                            "[${f.severity}] ${f.title}",
                            fontWeight = FontWeight.SemiBold,
                            color = color
                        )
                        Text(f.detail, style = MaterialTheme.typography.bodySmall)
                    }
                }
                Spacer(Modifier.height(6.dp))
            }
        }
    }
}

@Composable
private fun ExpandableCard(title: String, content: @Composable () -> Unit) {
    var open by remember { mutableStateOf(false) }
    Card(modifier = Modifier.fillMaxWidth(), onClick = { open = !open }) {
        Column(Modifier.padding(16.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Icon(
                    if (open) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                    contentDescription = null
                )
            }
            if (open) {
                Spacer(Modifier.height(8.dp))
                HorizontalDivider()
                Spacer(Modifier.height(8.dp))
                content()
            }
        }
    }
}

private fun label(c: PermCategory): String = when (c) {
    PermCategory.NORMAL -> "normal"
    PermCategory.PELIGROSO -> "peligroso"
    PermCategory.ESPECIAL -> "especial"
    PermCategory.FIRMA -> "sistema"
    PermCategory.DESCONOCIDO -> "propio"
}

private fun sdk(v: Int): String = if (v > 0) v.toString() else "?"

private fun human(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024) return "%.1f KB".format(kb)
    val mb = kb / 1024.0
    if (mb < 1024) return "%.1f MB".format(mb)
    return "%.2f GB".format(mb / 1024.0)
}
