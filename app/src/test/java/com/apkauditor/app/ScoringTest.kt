package com.apkauditor.app

import com.apkauditor.app.analysis.ScoreInput
import com.apkauditor.app.analysis.Scoring
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
        currentSdk = 34,
        httpUrls = 0,
        sensitiveApis = 0,
        trackerCount = 0,
        certProblem = false,
        signed = true
    )

    @Test
    fun limpio_da_100() {
        val (score, _) = Scoring.score(base())
        assertEquals(100, score)
    }

    @Test
    fun penaliza_permisos_con_tope() {
        val (score, _) = Scoring.score(base().copy(dangerousCount = 3))
        assertEquals(100 - 24, score)
        val (top, _) = Scoring.score(base().copy(dangerousCount = 99))
        assertEquals(100 - 40, top)
    }

    @Test
    fun penaliza_debuggable_y_target_viejo() {
        val (score, notes) = Scoring.score(
            base().copy(debuggable = true, targetSdk = 30)
        )
        assertEquals(100 - 15 - 10, score)
        assertTrue(notes.any { it.contains("debuggable", ignoreCase = true) })
    }

    @Test
    fun sin_firma_resta_20_y_nunca_baja_de_0() {
        val (score, _) = Scoring.score(
            base().copy(
                signed = false, debuggable = true, dangerousCount = 99,
                specialCount = 99, exportedCount = 99, httpUrls = 5,
                sensitiveApis = 99, trackerCount = 99, certProblem = true
            )
        )
        assertEquals(0, score)
    }
}
