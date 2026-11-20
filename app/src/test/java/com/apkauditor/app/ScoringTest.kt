package com.apkauditor.app

import com.apkauditor.app.analysis.ScoreInput
import com.apkauditor.app.analysis.Scoring
import com.apkauditor.app.model.ComponentInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ScoringTest {

    private fun base() = ScoreInput(
        dangerousCount = 0,
        specialCount = 0,
        exportedCount = 0,
        debuggable = false,
        targetSdk = 34,
        httpUrls = 0,
        sensitiveApis = 0,
        trackerCount = 0,
        certProblem = false,
        signed = true
    )

    @Test
    fun limpio_da_100() {
        val r = Scoring.score(base())
        assertEquals(100, r.total)
        assertEquals(100, r.base)
        assertEquals(0, r.heuristic)
    }

    @Test
    fun penaliza_permisos_con_tope() {
        assertEquals(100 - 24, Scoring.score(base().copy(dangerousCount = 3)).total)
        assertEquals(100 - 40, Scoring.score(base().copy(dangerousCount = 99)).total)
    }

    @Test
    fun penaliza_debuggable_y_target_viejo() {
        val r = Scoring.score(base().copy(debuggable = true, targetSdk = 30))
        assertEquals(100 - 15 - 10, r.total)
        assertTrue(r.notes.any { it.contains("debuggable", ignoreCase = true) })
    }

    @Test
    fun sin_firma_resta_20_y_nunca_baja_de_0() {
        val r = Scoring.score(
            base().copy(
                signed = false, debuggable = true, dangerousCount = 99,
                specialCount = 99, exportedCount = 99, httpUrls = 5,
                sensitiveApis = 99, trackerCount = 99, certProblem = true
            )
        )
        assertEquals(0, r.total)
    }

    @Test
    fun baseline_fijo_con_rezago_de_2() {
        // vs referencia 34: 33 pasa (rezago 1), 32 castiga (rezago 2).
        assertEquals(100, Scoring.score(base().copy(targetSdk = 33)).total)
        assertEquals(100 - 10, Scoring.score(base().copy(targetSdk = 32)).total)
        assertEquals(100 - 10, Scoring.score(base().copy(targetSdk = 28)).total)
    }

    @Test
    fun desglosa_base_y_heuristico() {
        val r = Scoring.score(base().copy(httpUrls = 2, trackerCount = 1))
        assertEquals(100, r.base)
        assertEquals(8 + 2, r.heuristic)
        assertEquals(90, r.total)
        assertTrue(r.notes.all { it.contains("(heurístico)") })
    }

    @Test
    fun launcher_no_cuenta_como_exportado() {
        val comps = listOf(
            ComponentInfo("Activity", "com.ejemplo.Main", exported = true, isLauncher = true),
            ComponentInfo("Activity", "com.ejemplo.Otra", exported = true),
            ComponentInfo("Service", "com.ejemplo.Srv", exported = false)
        )
        assertEquals(1, Scoring.exportedNonLauncher(comps))
        assertEquals(
            0,
            Scoring.exportedNonLauncher(comps.take(1) + comps.drop(2))
        )
    }
}
