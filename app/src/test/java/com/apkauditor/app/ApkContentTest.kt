package com.apkauditor.app

import com.apkauditor.app.analysis.ApkContent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ApkContentTest {

    @Test
    fun abis_y_64bit() {
        val abis = ApkContent.abisOf(
            listOf("lib/arm64-v8a/a.so", "lib/armeabi-v7a/a.so", "classes.dex")
        )
        assertEquals(setOf("arm64-v8a", "armeabi-v7a"), abis)
        assertFalse(ApkContent.missing64Bit(abis))
        assertTrue(ApkContent.missing64Bit(setOf("armeabi-v7a")))
        assertFalse(ApkContent.missing64Bit(emptySet()))
    }

    @Test
    fun droppers() {
        assertEquals(
            listOf("assets/payload.apk", "res/raw/x.dex", "extra.dex"),
            ApkContent.dropperFiles(
                listOf(
                    "assets/payload.apk", "res/raw/x.dex", "assets/img.png",
                    "classes.dex", "classes2.dex", "extra.dex", "lib/arm64-v8a/a.so"
                )
            )
        )
    }
}
