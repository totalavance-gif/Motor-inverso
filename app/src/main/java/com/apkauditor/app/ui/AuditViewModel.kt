package com.apkauditor.app.ui

import android.app.Application
import android.content.Context
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.room.Room
import com.apkauditor.app.analysis.ApkAnalysisException
import com.apkauditor.app.analysis.ApkAnalyzer
import com.apkauditor.app.data.ReportExporter
import com.apkauditor.app.data.ReportJson
import com.apkauditor.app.data.db.AuditDatabase
import com.apkauditor.app.data.db.AuditEntity
import com.apkauditor.app.model.AuditReport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

sealed interface AnalyzeState {
    data object Idle : AnalyzeState
    data class Working(val fraction: Float, val phase: String) : AnalyzeState
    data class Done(val id: Long) : AnalyzeState
    data class Error(val message: String) : AnalyzeState
}

class AuditViewModel(app: Application) : AndroidViewModel(app) {

    private val db = Room.databaseBuilder(
        app, AuditDatabase::class.java, "audits.db"
    ).fallbackToDestructiveMigration().build()
    private val dao = db.auditDao()

    val history: StateFlow<List<AuditEntity>> = dao.observeAll()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _state = MutableStateFlow<AnalyzeState>(AnalyzeState.Idle)
    val state: StateFlow<AnalyzeState> = _state

    private var lastTempApk: File? = null

    init {
        // Limpieza de temporales de sesiones anteriores.
        viewModelScope.launch(Dispatchers.IO) { cleanTempDir() }
    }

    fun resetState() {
        _state.value = AnalyzeState.Idle
    }

    /** Copia el APK elegido al cache privado y lo analiza. */
    fun analyzeUri(uri: Uri) {
        if (_state.value is AnalyzeState.Working) return
        viewModelScope.launch {
            _state.value = AnalyzeState.Working(0f, "Copiando archivo...")
            try {
                val apk = withContext(Dispatchers.IO) { copyToTemp(uri) }
                lastTempApk = apk
                val pm = getApplication<Application>().packageManager
                val report = withContext(Dispatchers.IO) {
                    ApkAnalyzer.analyze(pm, apk) { f, phase ->
                        _state.value = AnalyzeState.Working(0.05f + 0.95f * f, phase)
                    }
                }
                val id = dao.insert(
                    AuditEntity(
                        fileName = report.fileName,
                        packageName = report.packageName,
                        versionName = report.versionName,
                        score = report.score,
                        dateMillis = report.dateMillis,
                        reportJson = ReportJson.toJson(report)
                    )
                )
                _state.value = AnalyzeState.Done(id)
            } catch (e: ApkAnalysisException) {
                _state.value = AnalyzeState.Error(e.message ?: "Error al analizar.")
            } catch (e: Exception) {
                _state.value = AnalyzeState.Error("Error inesperado: ${e.message}")
            }
        }
    }

    suspend fun loadReport(id: Long): AuditReport? = withContext(Dispatchers.IO) {
        dao.getById(id)?.let { runCatching { ReportJson.fromJson(it.reportJson) }.getOrNull() }
    }

    fun deleteAudit(id: Long) {
        viewModelScope.launch(Dispatchers.IO) { dao.deleteById(id) }
    }

    fun clearHistory() {
        viewModelScope.launch(Dispatchers.IO) { dao.deleteAll() }
    }

    /** Borra el archivo temporal del último análisis (el reporte guardado se conserva). */
    fun deleteTemp(): Boolean {
        val ok = lastTempApk?.delete() ?: false
        lastTempApk = null
        cleanTempDir()
        return ok
    }

    /** Exporta el reporte a Markdown en la Uri elegida con SAF. */
    suspend fun exportMarkdown(id: Long, dest: Uri): String = withContext(Dispatchers.IO) {
        val report = loadReport(id) ?: throw ApkAnalysisException("Reporte no encontrado.")
        val ctx = getApplication<Application>()
        ctx.contentResolver.openOutputStream(dest)?.use {
            it.write(ReportExporter.toMarkdown(report).toByteArray(Charsets.UTF_8))
        } ?: throw ApkAnalysisException("No se pudo escribir el archivo.")
        "Markdown guardado."
    }

    /** Exporta el reporte a PDF en la Uri elegida con SAF. */
    suspend fun exportPdf(id: Long, dest: Uri): String = withContext(Dispatchers.IO) {
        val report = loadReport(id) ?: throw ApkAnalysisException("Reporte no encontrado.")
        val ctx = getApplication<Application>()
        ctx.contentResolver.openOutputStream(dest)?.use {
            ReportExporter.writePdf(report, it)
        } ?: throw ApkAnalysisException("No se pudo escribir el archivo.")
        "PDF guardado."
    }

    private fun tempDir(): File {
        val ctx = getApplication<Application>()
        return File(ctx.cacheDir, "apks").apply { mkdirs() }
    }

    private fun copyToTemp(uri: Uri): File {
        val ctx = getApplication<Application>()
        val name = queryName(ctx, uri) ?: "app.apk"
        val safe = name.replace(Regex("[^A-Za-z0-9._-]"), "_").takeLast(80)
        val ext = if (safe.endsWith(".apk", ignoreCase = true)) "" else ".apk"
        val dest = File(tempDir(), "${System.currentTimeMillis()}_$safe$ext")
        ctx.contentResolver.openInputStream(uri)?.use { input ->
            dest.outputStream().use { output ->
                val buf = ByteArray(256 * 1024)
                var total = 0L
                while (true) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    total += n
                    if (total > ApkAnalyzer.MAX_APK_BYTES) {
                        dest.delete()
                        throw ApkAnalysisException("El archivo supera el límite de 500 MB.")
                    }
                    output.write(buf, 0, n)
                }
            }
        } ?: throw ApkAnalysisException("No se pudo abrir el archivo elegido.")
        return dest
    }

    private fun queryName(ctx: Context, uri: Uri): String? {
        return try {
            ctx.contentResolver.query(uri, null, null, null, null)?.use { c ->
                val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun cleanTempDir() {
        // Conserva solo el temporal del análisis en curso.
        val keep = lastTempApk?.name
        tempDir().listFiles()?.forEach {
            if (it.name != keep) runCatching { it.delete() }
        }
    }

    /** Borrado al cerrar la app (mejor esfuerzo; al abrir también se limpia). */
    fun onAppClosing() {
        runCatching {
            tempDir().listFiles()?.forEach { it.delete() }
        }
        lastTempApk = null
    }
}
