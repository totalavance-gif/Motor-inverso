package com.apkauditor.app.analysis

import com.apkauditor.app.model.PermCategory
import com.apkauditor.app.model.PermInfo

/**
 * Clasifica permisos Android y explica los peligrosos en lenguaje simple.
 * Fuente de categorías: documentación de Android (protection levels).
 */
object PermissionData {

    private val dangerousExplanations = mapOf(
        "android.permission.READ_CALENDAR" to "Lee los eventos de tu calendario.",
        "android.permission.WRITE_CALENDAR" to "Crea o modifica eventos de tu calendario.",
        "android.permission.READ_CALL_LOG" to "Lee tu historial de llamadas.",
        "android.permission.WRITE_CALL_LOG" to "Modifica tu historial de llamadas.",
        "android.permission.PROCESS_OUTGOING_CALLS" to "Ve y puede redirigir tus llamadas salientes.",
        "android.permission.CAMERA" to "Usa la cámara para fotos o video.",
        "android.permission.READ_CONTACTS" to "Lee tu lista de contactos.",
        "android.permission.WRITE_CONTACTS" to "Modifica tu lista de contactos.",
        "android.permission.GET_ACCOUNTS" to "Ve las cuentas registradas en el equipo.",
        "android.permission.ACCESS_FINE_LOCATION" to "Obtiene tu ubicación exacta (GPS).",
        "android.permission.ACCESS_COARSE_LOCATION" to "Obtiene tu ubicación aproximada (red).",
        "android.permission.ACCESS_BACKGROUND_LOCATION" to "Obtiene tu ubicación aunque la app esté cerrada.",
        "android.permission.RECORD_AUDIO" to "Graba audio con el micrófono.",
        "android.permission.READ_PHONE_STATE" to "Lee el estado del teléfono (llamadas, operador).",
        "android.permission.READ_PHONE_NUMBERS" to "Lee tu número de teléfono.",
        "android.permission.CALL_PHONE" to "Realiza llamadas sin pasar por el marcador.",
        "android.permission.ANSWER_PHONE_CALLS" to "Contesta llamadas entrantes por ti.",
        "android.permission.READ_SMS" to "Lee tus mensajes SMS.",
        "android.permission.SEND_SMS" to "Envía SMS (pueden costar dinero).",
        "android.permission.RECEIVE_SMS" to "Recibe y lee SMS entrantes.",
        "android.permission.RECEIVE_MMS" to "Recibe y lee MMS entrantes.",
        "android.permission.RECEIVE_WAP_PUSH" to "Recibe mensajes WAP push.",
        "android.permission.READ_EXTERNAL_STORAGE" to "Lee archivos de tu almacenamiento.",
        "android.permission.WRITE_EXTERNAL_STORAGE" to "Escribe archivos en tu almacenamiento.",
        "android.permission.ACCESS_MEDIA_LOCATION" to "Lee la ubicación guardada en tus fotos.",
        "android.permission.READ_MEDIA_IMAGES" to "Lee tus imágenes.",
        "android.permission.READ_MEDIA_VIDEO" to "Lee tus videos.",
        "android.permission.READ_MEDIA_AUDIO" to "Lee tus audios.",
        "android.permission.BODY_SENSORS" to "Lee sensores corporales (ritmo cardíaco, etc.).",
        "android.permission.ACTIVITY_RECOGNITION" to "Detecta tu actividad física (caminar, correr).",
        "android.permission.BLUETOOTH_CONNECT" to "Se conecta a dispositivos Bluetooth.",
        "android.permission.BLUETOOTH_SCAN" to "Busca dispositivos Bluetooth cercanos.",
        "android.permission.BLUETOOTH_ADVERTISE" to "Se anuncia ante otros Bluetooth.",
        "android.permission.UWB_RANGING" to "Mide distancias con ultra-wideband.",
        "android.permission.POST_NOTIFICATIONS" to "Muestra notificaciones.",
        "android.permission.NEARBY_WIFI_DEVICES" to "Ve redes Wi-Fi cercanas (puede ubicarte)."
    )

    private val specialExplanations = mapOf(
        "android.permission.SYSTEM_ALERT_WINDOW" to "Dibuja ventanas sobre otras apps. Requiere permiso especial del usuario.",
        "android.permission.REQUEST_INSTALL_PACKAGES" to "Puede instalar otras apps (APKs). Riesgoso si no es su función.",
        "android.permission.QUERY_ALL_PACKAGES" to "Ve la lista completa de apps instaladas.",
        "android.permission.MANAGE_EXTERNAL_STORAGE" to "Acceso total a todos los archivos (permiso especial).",
        "android.permission.ACCESS_NOTIFICATION_POLICY" to "Cambia el modo No molestar.",
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to "Servicio de accesibilidad: puede leer la pantalla.",
        "android.permission.BIND_DEVICE_ADMIN" to "Administrador del dispositivo: control avanzado.",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" to "Lee todas tus notificaciones.",
        "android.permission.BIND_VPN_SERVICE" to "Crea conexiones VPN (ve tu tráfico).",
        "android.permission.PACKAGE_USAGE_STATS" to "Ve estadísticas de uso de otras apps.",
        "android.permission.SCHEDULE_EXACT_ALARM" to "Programa alarmas exactas.",
        "android.permission.USE_EXACT_ALARM" to "Programa alarmas exactas (sistema).",
        "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" to "Pide no ser optimizada en batería (corre en fondo).",
        "android.permission.BIND_AUTOFILL_SERVICE" to "Servicio de autocompletado (ve formularios)."
    )

    // Permisos signature/privilegiados comunes: solo útiles para apps de sistema.
    private val signature = setOf(
        "android.permission.INSTALL_PACKAGES",
        "android.permission.DELETE_PACKAGES",
        "android.permission.CLEAR_APP_CACHE",
        "android.permission.MASTER_CLEAR",
        "android.permission.REBOOT",
        "android.permission.DEVICE_POWER",
        "android.permission.STATUS_BAR",
        "android.permission.WRITE_SECURE_SETTINGS",
        "android.permission.DUMP",
        "android.permission.READ_LOGS",
        "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
        "android.permission.BATTERY_STATS",
        "android.permission.PACKAGE_VERIFICATION_AGENT",
        "android.permission.BIND_PACKAGE_VERIFIER",
        "android.permission.UPDATE_DEVICE_STATS"
    )

    fun classify(name: String): PermInfo {
        dangerousExplanations[name]?.let {
            return PermInfo(name, PermCategory.PELIGROSO, it)
        }
        specialExplanations[name]?.let {
            return PermInfo(name, PermCategory.ESPECIAL, it)
        }
        if (name in signature || name.startsWith("android.permission.BIND_")) {
            return PermInfo(
                name, PermCategory.FIRMA,
                "Permiso de sistema: solo funciona en apps firmadas por el fabricante o con privilegios."
            )
        }
        if (name.startsWith("android.permission.")) {
            return PermInfo(
                name, PermCategory.NORMAL,
                "Permiso normal: se concede al instalar sin preguntar."
            )
        }
        return PermInfo(
            name, PermCategory.DESCONOCIDO,
            "Permiso personalizado definido por el propio APK u otra app."
        )
    }
}
