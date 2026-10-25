package com.zzupocket.app.security

import com.zzupocket.app.core.security.copyLimitedTo
import com.zzupocket.app.core.security.imageSampleSize
import com.zzupocket.app.data.gms.GmsCookie
import com.zzupocket.app.data.gms.GmsScheduleParser
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.Random
import org.junit.Assert.*
import org.junit.Test

class UntrustedInputTest {
    @Test fun `huge reversed overflow and malformed weeks cannot expand`() {
        listOf("1-2147483647周", "99999999999999999999周", "0-10周", "60-1周", "61周")
            .forEach { assertNull(it, GmsScheduleParser.parseWeeks(it)) }
        assertEquals(listOf(2..17), GmsScheduleParser.parseWeeks("2-17周"))
        assertNull(GmsScheduleParser.parseCell("[".repeat(10000)))
    }

    @Test fun `deterministic malformed input corpus remains bounded`() {
        val random = Random(20261025)
        val alphabet = "0123456789[]-周;=\r\nabc"
        repeat(10000) {
            val input = buildString { repeat(random.nextInt(256)) { append(alphabet[random.nextInt(alphabet.length)]) } }
            GmsScheduleParser.parseCell(input)
            GmsScheduleParser.parseWeeks(input)?.forEach { r ->
                assertTrue(r.first in 1..60 && r.last in r.first..60)
            }
            assertTrue(GmsCookie.parse(input).size <= 64)
        }
        assertTrue(GmsCookie.parse("a=" + "x".repeat(65536)).isEmpty())
        assertTrue(GmsCookie.parse("a=b\r\nc=d").isEmpty())
    }

    @Test fun `image copy and extreme aspect ratios stay bounded`() {
        val out = ByteArrayOutputStream()
        try { ByteArrayInputStream(ByteArray(1025)).copyLimitedTo(out, 1024); fail("Limit bypassed") }
        catch (expected: IOException) { assertTrue(out.size() <= 1024) }
        assertEquals(1, imageSampleSize(100, 100))
        assertEquals(2, imageSampleSize(2049, 1))
        assertTrue(imageSampleSize(1, Int.MAX_VALUE) > 1000000)
        assertTrue(imageSampleSize(Int.MAX_VALUE, 1) > 1000000)
    }
}
