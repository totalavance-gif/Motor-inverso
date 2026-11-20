package com.apkauditor.app

import com.apkauditor.app.analysis.Format
import org.junit.Assert.assertEquals
import org.junit.Test

class FormatTest {

    @Test
    fun bytes_y_kb() {
        assertEquals("0 B", Format.humanSize(0))
        assertEquals("33 B", Format.humanSize(33))
        assertEquals("1023 B", Format.humanSize(1023))
        assertEquals("1.0 KB", Format.humanSize(1024))
        assertEquals("35.3 KB", Format.humanSize(36147))
    }

    @Test
    fun mb_gb_y_negativo() {
        assertEquals("5.0 MB", Format.humanSize(5L * 1024 * 1024))
        assertEquals("3.00 GB", Format.humanSize(3L * 1024 * 1024 * 1024))
        assertEquals("?", Format.humanSize(-1))
    }
}
