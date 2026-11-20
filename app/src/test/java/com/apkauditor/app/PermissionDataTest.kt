package com.apkauditor.app

import com.apkauditor.app.analysis.PermissionData
import com.apkauditor.app.model.PermCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PermissionDataTest {

    @Test
    fun camara_es_peligrosa_con_explicacion() {
        val p = PermissionData.classify("android.permission.CAMERA")
        assertEquals(PermCategory.PELIGROSO, p.category)
        assertTrue(p.explanation.contains("cámara"))
    }

    @Test
    fun instalar_paquetes_es_especial() {
        val p = PermissionData.classify("android.permission.REQUEST_INSTALL_PACKAGES")
        assertEquals(PermCategory.ESPECIAL, p.category)
    }

    @Test
    fun internet_es_normal() {
        val p = PermissionData.classify("android.permission.INTERNET")
        assertEquals(PermCategory.NORMAL, p.category)
    }

    @Test
    fun permiso_propio_es_desconocido() {
        val p = PermissionData.classify("com.ejemplo.MI_PERMISO")
        assertEquals(PermCategory.DESCONOCIDO, p.category)
    }
}
