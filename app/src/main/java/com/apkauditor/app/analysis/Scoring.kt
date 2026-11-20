package com.apkauditor.app.analysis

import com.apkauditor.app.model.ComponentInfo

/**
 * Entrada para el cálculo del score. Todo deducible del APK.
 *
 * @param dangerousCount permisos peligrosos solicitados
 * @param specialCount permisos especiales solicitados
 * @param exportedCount componentes exportados (sin contar el launcher)
 * @param debuggable APK compilado con debuggable=true
 * @param targetSdk targetSdk del APK (0 si se desconoce)
 * @param httpUrls URLs http:// (sin cifrar) halladas en el dex
 * @param sensitiveApis APIs sensibles con peso halladas en el dex
 * @param trackerCount SDKs de rastreo/analítica detectados
 * @param certProblem true si el certificado venció o vence en < 1 año
 * @param signed false si no se halló ninguna firma
 */
data class ScoreInput(
    val dangerousCount: Int,
    val specialCount: Int,
    val exportedCount: Int,
    val debuggable: Boolean,
    val targetSdk: Int,
    val httpUrls: Int,
    val sensitiveApis: Int,
    val trackerCount: Int,
    val certProblem: Boolean,
    val signed: Boolean
)

/** Resultado con desglose: base determinista + ajuste heurístico (dex). */
data class ScoreResult(
    val total: Int,
    val base: Int,
    val heuristic: Int, // puntos restados por lo heurístico (>= 0)
    val notes: List<String>
)

/**
 * Score de 0 a 100. Empieza en 100 y resta en dos partes:
 *
 * Base (determinista, deducida del manifest y la firma):
 * - 8 por cada permiso peligroso (máx. 40)
 * - 6 por cada permiso especial (máx. 24)
 * - 2 por cada componente exportado sin contar el launcher (máx. 20)
 * - 15 si es debuggable
 * - 10 si targetSdk tiene 2+ niveles de rezago vs [TARGET_BASELINE]
 * - 6 si el certificado venció o vence pronto
 * - 20 si no está firmado
 *
 * Heurístico (indicios del dex, marcados como tales):
 * - 8 si hay URLs http:// en el dex
 * - 3 por cada API sensible con peso (máx. 12)
 * - 2 por cada tracker detectado (máx. 10)
 *
 * El resultado se limita a [0, 100]. El mismo APK siempre da el mismo score,
 * sin importar en qué equipo se audite.
 */
object Scoring {

    /** Referencia fija para el rezago de targetSdk (lo que exige Play). */
    const val TARGET_BASELINE = 34

    fun score(input: ScoreInput): ScoreResult {
        var base = 100
        var heuristic = 0
        val notes = mutableListOf<String>()

        fun hitBase(points: Int, note: String) {
            base -= points
            notes.add("-$points: $note")
        }
        fun hitHeuristic(points: Int, note: String) {
            heuristic += points
            notes.add("-$points: $note (heurístico)")
        }

        val permHit = minOf(40, input.dangerousCount * 8)
        if (permHit > 0) hitBase(permHit, "${input.dangerousCount} permiso(s) peligroso(s)")
        val specialHit = minOf(24, input.specialCount * 6)
        if (specialHit > 0) hitBase(specialHit, "${input.specialCount} permiso(s) especial(es)")
        val expHit = minOf(20, input.exportedCount * 2)
        if (expHit > 0) hitBase(expHit, "${input.exportedCount} componente(s) exportado(s)")
        if (input.debuggable) hitBase(15, "APK debuggable (versión de desarrollo)")
        if (input.targetSdk > 0 && TARGET_BASELINE - input.targetSdk >= 2) {
            hitBase(10, "targetSdk ${input.targetSdk} desactualizado (referencia: $TARGET_BASELINE)")
        }
        if (input.certProblem) hitBase(6, "Certificado vencido o por vencer")
        if (!input.signed) hitBase(20, "APK sin firma detectable")

        if (input.httpUrls > 0) {
            hitHeuristic(8, "${input.httpUrls} URL(s) http:// sin cifrar en el código")
        }
        val apiHit = minOf(12, input.sensitiveApis * 3)
        if (apiHit > 0) hitHeuristic(apiHit, "${input.sensitiveApis} API(s) sensible(s) en el código")
        val trackerHit = minOf(10, input.trackerCount * 2)
        if (trackerHit > 0) hitHeuristic(trackerHit, "${input.trackerCount} SDK(s) de rastreo")

        if (notes.isEmpty()) notes.add("Sin penalizaciones: buenas prácticas.")
        return ScoreResult(
            total = maxOf(0, minOf(100, base - heuristic)),
            base = maxOf(0, minOf(100, base)),
            heuristic = heuristic,
            notes = notes
        )
    }

    /** Componentes exportados sin contar el launcher (toda app normal lo exporta). */
    fun exportedNonLauncher(components: List<ComponentInfo>): Int =
        components.count { it.exported && !it.isLauncher }
}
