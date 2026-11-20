package com.apkauditor.app.analysis

/**
 * Entrada para el cálculo del score. Todo deducible del APK + entorno.
 *
 * @param dangerousCount permisos peligrosos solicitados
 * @param specialCount permisos especiales solicitados
 * @param exportedCount componentes exportados (accesibles por otras apps)
 * @param debuggable APK compilado con debuggable=true
 * @param targetSdk targetSdk del APK (0 si se desconoce)
 * @param currentSdk SDK del equipo que audita (Build.VERSION.SDK_INT)
 * @param httpUrls URLs http:// (sin cifrar) halladas en el dex
 * @param sensitiveApis APIs sensibles halladas en el dex (exec, dex carga dinámica...)
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
    val currentSdk: Int,
    val httpUrls: Int,
    val sensitiveApis: Int,
    val trackerCount: Int,
    val certProblem: Boolean,
    val signed: Boolean
)

/**
 * Score de 0 a 100. Fórmula (empieza en 100 y resta):
 * - 8 por cada permiso peligroso (máx. 40)
 * - 6 por cada permiso especial (máx. 24)
 * - 2 por cada componente exportado (máx. 20)
 * - 15 si es debuggable
 * - 10 si targetSdk tiene 2+ años de rezago (currentSdk - targetSdk >= 2)
 * - 8 si hay URLs http:// en el dex
 * - 3 por cada API sensible en el dex (máx. 12)
 * - 2 por cada tracker detectado (máx. 10)
 * - 6 si el certificado venció o vence pronto
 * - 20 si no está firmado
 * El resultado se limita a [0, 100].
 */
object Scoring {

    fun score(input: ScoreInput): Pair<Int, List<String>> {
        var total = 100
        val notes = mutableListOf<String>()

        fun hit(points: Int, note: String) {
            total -= points
            notes.add("-$points: $note")
        }

        val permHit = minOf(40, input.dangerousCount * 8)
        if (permHit > 0) hit(permHit, "${input.dangerousCount} permiso(s) peligroso(s)")
        val specialHit = minOf(24, input.specialCount * 6)
        if (specialHit > 0) hit(specialHit, "${input.specialCount} permiso(s) especial(es)")
        val expHit = minOf(20, input.exportedCount * 2)
        if (expHit > 0) hit(expHit, "${input.exportedCount} componente(s) exportado(s)")
        if (input.debuggable) hit(15, "APK debuggable (versión de desarrollo)")
        if (input.targetSdk > 0 && input.currentSdk - input.targetSdk >= 2) {
            hit(10, "targetSdk ${input.targetSdk} desactualizado (equipo: ${input.currentSdk})")
        }
        if (input.httpUrls > 0) hit(8, "${input.httpUrls} URL(s) http:// sin cifrar en el código")
        val apiHit = minOf(12, input.sensitiveApis * 3)
        if (apiHit > 0) hit(apiHit, "${input.sensitiveApis} API(s) sensible(s) en el código")
        val trackerHit = minOf(10, input.trackerCount * 2)
        if (trackerHit > 0) hit(trackerHit, "${input.trackerCount} SDK(s) de rastreo")
        if (input.certProblem) hit(6, "Certificado vencido o por vencer")
        if (!input.signed) hit(20, "APK sin firma detectable")

        if (notes.isEmpty()) notes.add("Sin penalizaciones: buenas prácticas.")
        return maxOf(0, minOf(100, total)) to notes
    }
}
