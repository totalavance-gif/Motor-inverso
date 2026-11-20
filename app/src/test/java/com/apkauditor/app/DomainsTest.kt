package com.apkauditor.app

import com.apkauditor.app.analysis.Domains
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainsTest {

    @Test
    fun dominios_unicos_sin_sospechosos() {
        val r = Domains.analyze(
            listOf(
                "http://api.ejemplo.com/x",
                "https://api.ejemplo.com/y",
                "http://a.bc/"
            )
        )
        assertEquals(listOf("api.ejemplo.com", "a.bc"), r.domains)
        assertTrue(r.suspicious.isEmpty())
    }

    @Test
    fun marca_hosts_sospechosos() {
        val r = Domains.analyze(
            listOf(
                "http://192.168.1.1/x",
                "http://admin@huesped.com/",
                "https://huesped.com:8443/",
                "http://malvado.top/",
                "http://xn--pple-43d.com/"
            )
        )
        assertEquals(5, r.suspicious.size)
        assertTrue(r.suspicious.any { it.contains("IP literal") })
        assertTrue(r.suspicious.any { it.contains("usuario/clave") })
        assertTrue(r.suspicious.any { it.contains("puerto") })
        assertTrue(r.suspicious.any { it.contains("TLD") })
        assertTrue(r.suspicious.any { it.contains("punycode") })
    }

    @Test
    fun loopback_exento() {
        val r = Domains.analyze(listOf("http://127.0.0.1:8787/", "http://localhost:8080/a"))
        assertEquals(listOf("127.0.0.1", "localhost"), r.domains)
        assertTrue(r.suspicious.isEmpty())
        assertTrue(Domains.isLoopbackUrl("http://[::1]/"))
        assertTrue(Domains.isLoopbackUrl("http://127.0.0.1/"))
        assertFalse(Domains.isLoopbackUrl("http://192.168.1.1/"))
    }
}
