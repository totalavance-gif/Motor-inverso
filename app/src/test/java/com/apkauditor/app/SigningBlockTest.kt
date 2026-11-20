package com.apkauditor.app

import com.apkauditor.app.analysis.SigningBlock
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File

class SigningBlockTest {

    private fun le16(v: Int) = byteArrayOf((v and 0xFF).toByte(), ((v shr 8) and 0xFF).toByte())
    private fun le32(v: Int) = le16(v and 0xFFFF) + le16((v shr 16) and 0xFFFF)
    private fun le64(v: Long) =
        le32((v and 0xFFFFFFFFL).toInt()) + le32(((v shr 32) and 0xFFFFFFFFL).toInt())

    /** ZIP mínimo: [relleno][bloque?][dir central][EOCD]. */
    private fun buildZip(withBlock: Boolean): File {
        val out = ByteArrayOutputStream()
        out.write(ByteArray(100)) // relleno
        var cdOff = 100
        if (withBlock) {
            out.write(le64(32)) // size1
            out.write(le64(32)) // size2
            out.write(SigningBlock.MAGIC.toByteArray(Charsets.US_ASCII))
            cdOff += 32
        }
        out.write(ByteArray(20)) // dir central falsa
        val eocd = ByteArrayOutputStream()
        eocd.write(le32(0x06054B50))
        eocd.write(le16(0)) // disco
        eocd.write(le16(0)) // disco dir
        eocd.write(le16(0)) // entradas
        eocd.write(le16(0)) // entradas total
        eocd.write(le32(20)) // tamaño dir
        eocd.write(le32(cdOff)) // offset dir
        eocd.write(le16(0)) // comentario
        out.write(eocd.toByteArray())
        val f = File.createTempFile("sigblock", ".zip")
        f.deleteOnExit()
        f.writeBytes(out.toByteArray())
        return f
    }

    @Test
    fun detecta_bloque() {
        assertTrue(SigningBlock.hasSigningBlock(buildZip(true)))
    }

    @Test
    fun sin_bloque_da_falso() {
        assertFalse(SigningBlock.hasSigningBlock(buildZip(false)))
    }

    @Test
    fun archivo_raro_da_falso() {
        val f = File.createTempFile("sigblock", ".bin")
        f.deleteOnExit()
        f.writeBytes("hola".toByteArray())
        assertFalse(SigningBlock.hasSigningBlock(f))
    }
}
