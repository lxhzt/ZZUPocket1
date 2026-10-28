package com.zzupocket.app.security

import com.zzupocket.app.core.net.readBoundedText
import com.zzupocket.app.core.security.SchoolNetworkInterceptor
import com.zzupocket.app.core.security.SchoolRequestPolicy
import com.zzupocket.app.core.security.SchoolService
import com.zzupocket.app.data.gms.GmsClient
import com.zzupocket.app.data.gms.GmsCookieJar
import java.io.IOException
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.Cookie
import okhttp3.Dns
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import okio.BufferedSource
import okio.GzipSink
import okio.GzipSource
import okio.Source
import okio.Timeout
import okio.buffer
import org.junit.Assert.*
import org.junit.Test

/**
 * Bounded adversarial workload, not a penetration-test certificate or device benchmark.
 * Every request terminates in an application interceptor. DNS always throws; no sockets,
 * real accounts, school business requests, login attempts or financial operations are used.
 */
class LocalAdversarialTest {
    private val guid = "12345678-1234-1234-1234-123456789abc"
    private val eas = "https://jwxt.zzu.edu.cn/eams-door/api/v1/calendar/get-all-semesters"
    private val cas = "https://cas.s.zzu.edu.cn/token/jwt/publicKey"
    private val noDns = object : Dns {
        override fun lookup(hostname: String): List<java.net.InetAddress> =
            throw AssertionError("Local adversarial tests forbid DNS: $hostname")
    }

    private fun request(url: String, method: String = "GET", token: Boolean = false): Request =
        Request.Builder().url(url).apply {
            if (token) header("Authorization", "synthetic-test-token")
            if (method != "GET") method(method, "{}".toRequestBody())
        }.build()

    @Test fun `destination canonicalization corpus cannot escape academic capability`() {
        val attempts = AtomicInteger()
        val client = OkHttpClient.Builder().dns(noDns)
            .addInterceptor(SchoolNetworkInterceptor(SchoolService.EAS))
            .addInterceptor { attempts.incrementAndGet(); throw AssertionError("Denied request escaped") }
            .build()
        val suffix = "/eams-door/api/v1/calendar/get-all-semesters"
        val urls = listOf(
            "http://jwxt.zzu.edu.cn$suffix", "https://jwxt.zzu.edu.cn:444$suffix",
            "https://jwxt.zzu.edu.cn.evil.invalid$suffix", "https://jwxt.zzu.edu.cn.$suffix",
            "https://jwxt.zzu.edu.cn@evil.invalid$suffix", "https://u:p@jwxt.zzu.edu.cn$suffix",
            "https://127.0.0.1$suffix", "https://[::1]$suffix",
            "$eas/", "$eas//", "$eas;session=synthetic", "$eas%00", "$eas%2f",
            "$eas%252f", "$eas?", "$eas?token=synthetic", "$eas#synthetic-fragment",
            "https://ecard.v.zzu.edu.cn$suffix", "https://cas.s.zzu.edu.cn$suffix",
            "https://jwxt.zzu.edu.cn/eams-micro-server/api/v1/room/place/building?campusAssoc=1&%63ampusAssoc=2",
            "https://jwxt.zzu.edu.cn/eams-micro-server/api/v1/room/place/building?campusAssoc%00=1",
        )
        urls.forEach { value ->
            val parsed = value.toHttpUrlOrNull() ?: return@forEach // Parser rejection is also a safe outcome.
            try {
                client.newCall(request(parsed.toString(), token = true)).execute().close()
                fail("Destination escaped: $value")
            } catch (expected: IOException) { /* Rejected before transport. */ }
        }
        assertEquals(0, attempts.get())
    }

    @Test fun `GMS rejects noncanonical encoded routes and unauthorized module variants`() {
        val valid = GmsClient.encodeRoute("pygl/xskbcx/loadKb", guid)
        assertTrue(SchoolRequestPolicy.permits(request("https://gmsstu.zzu.edu.cn/stu/$valid", "POST"), SchoolService.GMS))
        val modules = listOf(
            "pygl/xskbcx/loadKb/delete", "pygl/xskbcx/LOADKB", "pygl/xskbcx/loadKb/",
            "pygl/xskbcx/../loadKb", "pygl/xskbcx/loadKb?redirect=synthetic", "utilities/pay",
        )
        val encoded = modules.map { GmsClient.encodeRoute(it, guid) } + listOf(
            "$valid=", "$valid/", valid.dropLast(1), "A".repeat(257), "%2f$valid", "!$valid",
        )
        encoded.forEach {
            assertFalse(it, SchoolRequestPolicy.permits(request("https://gmsstu.zzu.edu.cn/stu/$it", "POST"), SchoolService.GMS))
        }
        listOf("not-a-guid", "$guid#extra", "../$guid", "").forEach {
            val route = GmsClient.encodeRoute("pygl/xskbcx/loadKb", it)
            assertFalse(SchoolRequestPolicy.permits(request("https://gmsstu.zzu.edu.cn/stu/$route", "POST"), SchoolService.GMS))
        }
    }

    @Test(timeout = 60000) fun `mixed concurrent traffic preserves capability separation across 24000 calls`() {
        data class Case(val service: SchoolService, val request: Request, val allowed: Boolean)
        val cases = listOf(
            Case(SchoolService.CAS, request(cas), true),
            Case(SchoolService.EAS, request(eas, token = true), true),
            Case(SchoolService.GMS, request("https://gmsstu.zzu.edu.cn/stu/"), true),
            Case(SchoolService.FINANCE_DISABLED, request(eas, token = true), false),
            Case(SchoolService.CAS, request("https://ecard.v.zzu.edu.cn/server/auth/getToken"), false),
            Case(SchoolService.EAS, request(cas, token = true), false),
            Case(SchoolService.GMS, request("https://gmsstu.zzu.edu.cn/stu/unknown"), false),
            Case(SchoolService.EAS, request("$eas?redirect=synthetic", token = true), false),
            Case(SchoolService.CAS, request(cas).newBuilder().header("Cookie", "synthetic=value").build(), false),
            Case(SchoolService.GMS, request("https://gmsstu.zzu.edu.cn/stu/", token = true), false),
            Case(SchoolService.EAS, request(eas, token = true).newBuilder().header("X-Id-Token", "synthetic").build(), false),
            Case(SchoolService.CAS, request(cas, "POST"), false),
        )
        val transports = AtomicInteger()
        val rejected = AtomicInteger()
        val clients = SchoolService.entries.associateWith { service ->
            OkHttpClient.Builder().dns(noDns).addInterceptor(SchoolNetworkInterceptor(service))
                .addInterceptor {
                    transports.incrementAndGet()
                    Response.Builder().request(it.request()).protocol(Protocol.HTTP_1_1).code(200)
                        .message("synthetic").body("{}".toResponseBody()).build()
                }.build()
        }
        val pool = Executors.newFixedThreadPool(8)
        try {
            val work = (0 until 8).map { Callable {
                repeat(250) {
                    cases.forEach { case ->
                        try {
                            clients.getValue(case.service).newCall(case.request).execute().use { response ->
                                assertTrue("Rejected capability reached transport: ${case.service}", case.allowed)
                                assertEquals(200, response.code)
                            }
                        } catch (expected: IOException) {
                            assertFalse("Retained operation rejected: ${case.service}", case.allowed)
                            rejected.incrementAndGet()
                        }
                    }
                }
            } }
            pool.invokeAll(work, 45, TimeUnit.SECONDS).forEach { it.get() }
        } finally { pool.shutdownNow() }
        assertEquals(6000, transports.get())
        assertEquals(18000, rejected.get())
    }

    private class GeneratedSource(private var remaining: Long) : Source {
        var emitted = 0L
        var closed = false
        override fun read(sink: Buffer, byteCount: Long): Long {
            check(!closed)
            if (remaining == 0L) return -1
            val size = minOf(byteCount, remaining, 8192L).toInt()
            sink.write(ByteArray(size) { 'x'.code.toByte() })
            remaining -= size
            emitted += size
            return size.toLong()
        }
        override fun timeout() = Timeout.NONE
        override fun close() { closed = true }
    }

    private class SyntheticBody(private val data: BufferedSource, private val declaredSize: Long) : ResponseBody() {
        override fun contentType(): MediaType? = null
        override fun contentLength() = declaredSize
        override fun source() = data
    }

    @Test fun `lying and unbounded bodies stop near the limit and always close`() {
        val limit = 64L * 1024
        listOf(-1L, 0L, 1L).forEach { declared ->
            val generated = GeneratedSource(Long.MAX_VALUE)
            try {
                SyntheticBody(generated.buffer(), declared).readBoundedText(limit)
                fail("Endless response accepted with declared length $declared")
            } catch (expected: IOException) { /* No allocation proportional to the claimed stream size. */ }
            assertTrue(generated.closed)
            assertTrue(generated.emitted in (limit + 1)..(limit + 8192))
        }
        val declaredOversize = GeneratedSource(Long.MAX_VALUE)
        try {
            SyntheticBody(declaredOversize.buffer(), limit + 1).readBoundedText(limit)
            fail("Known oversized body accepted")
        } catch (expected: IOException) { }
        assertEquals(0L, declaredOversize.emitted)
        assertTrue(declaredOversize.closed)
        val exact = GeneratedSource(limit)
        assertEquals(limit.toInt(), SyntheticBody(exact.buffer(), -1).readBoundedText(limit).length)
        assertTrue(exact.closed)
    }

    @Test fun `compressed response expansion obeys the default four MiB decoded limit`() {
        val compressed = Buffer()
        GzipSink(compressed).buffer().use { gzip ->
            val block = ByteArray(8192) { 'x'.code.toByte() }
            repeat(1024) { gzip.write(block) } // Eight MiB decoded, compressed locally without sockets.
        }
        assertTrue(compressed.size < 32 * 1024)
        val inflated = GzipSource(compressed).buffer()
        try {
            SyntheticBody(inflated, -1).readBoundedText()
            fail("Compressed expansion passed decoded response limit")
        } catch (expected: IOException) { }
        // ResponseBody.use closes the decompressor on the rejection path.
        try { inflated.request(1); fail("Rejected decompressor remained open") }
        catch (expected: IllegalStateException) { }
    }

    @Test fun `escaped quote and bracket corpus cannot bypass JSON nesting bound`() {
        val quoted = JsonObject(mapOf("payload" to JsonPrimitive("\\\"[{}]".repeat(10000)))).toString()
        assertEquals(quoted, quoted.toResponseBody().readBoundedText())
        val limit = "[".repeat(64) + "0" + "]".repeat(64)
        assertEquals(limit, limit.toResponseBody().readBoundedText())
        listOf(
            "[".repeat(65) + quoted + "]".repeat(65),
            "{\"a\":".repeat(65) + "0" + "}".repeat(65),
        ).forEach {
            try { it.toResponseBody().readBoundedText(); fail("Nested input accepted") }
            catch (expected: IOException) { }
        }
    }

    @Test fun `response cookie churn stays capped and does not poison other origins`() {
        val jar = GmsCookieJar()
        val origin = "https://gmsstu.zzu.edu.cn/stu/".toHttpUrl()
        jar.seed(origin.host, mapOf("bootstrap" to "synthetic"))
        assertEquals(1, jar.size())
        repeat(100) { batch ->
            jar.saveFromResponse(origin, (0 until 32).map { index ->
                Cookie.Builder().hostOnlyDomain(origin.host).path("/stu").name("cookie-${batch * 32 + index}")
                    .value("synthetic").build()
            })
            assertEquals(minOf(64, 1 + (batch + 1) * 32), jar.size())
        }
        assertEquals(64, jar.size())
        assertEquals(64, jar.loadForRequest(origin).size)
        val poison = Cookie.Builder().domain("evil.invalid").name("session").value("synthetic").build()
        jar.saveFromResponse(origin, listOf(poison))
        jar.saveFromResponse("https://evil.invalid/stu/".toHttpUrl(), listOf(poison))
        jar.saveFromResponse("http://gmsstu.zzu.edu.cn/stu/".toHttpUrl(), listOf(
            Cookie.Builder().hostOnlyDomain(origin.host).name("plaintext").value("synthetic").build(),
        ))
        assertEquals(64, jar.size())
        assertTrue(jar.loadForRequest("https://evil.invalid/stu/".toHttpUrl()).isEmpty())
        assertTrue(jar.loadForRequest("https://sub.gmsstu.zzu.edu.cn/stu/".toHttpUrl()).isEmpty())
        assertTrue(jar.loadForRequest("http://gmsstu.zzu.edu.cn/stu/".toHttpUrl()).isEmpty())
    }

    @Test fun `cookie value limits path boundaries replacement and expiry survive hostile updates`() {
        val jar = GmsCookieJar()
        val origin = "https://gmsstu.zzu.edu.cn/stu/".toHttpUrl()
        jar.seed(origin.host, mapOf("session" to "synthetic", "tooLong" to "x".repeat(4097)))
        assertEquals(1, jar.size())
        listOf("/student", "/stu-evil", "/", "/other/stu").forEach {
            assertTrue(it, jar.loadForRequest("https://${origin.host}$it".toHttpUrl()).isEmpty())
        }
        fun cookie(value: String, expiry: Long? = null) = Cookie.Builder()
            .hostOnlyDomain(origin.host).path("/stu").name("session").value(value)
            .apply { if (expiry != null) expiresAt(expiry) }.build()
        jar.saveFromResponse(origin, listOf(cookie("replacement")))
        assertEquals(listOf("replacement"), jar.loadForRequest(origin).map { it.value })
        assertTrue(jar.loadForRequest(origin).single().secure)
        jar.saveFromResponse(origin, listOf(cookie("x".repeat(4097))))
        // A malformed update is ignored; only a valid expiry can remove an accepted session.
        assertEquals(listOf("replacement"), jar.loadForRequest(origin).map { it.value })
        jar.saveFromResponse(origin, listOf(cookie("synthetic")))
        jar.saveFromResponse(origin, listOf(cookie("expired", 0)))
        assertEquals(0, jar.size())
    }
}
