package com.zzupocket.app.security

import com.zzupocket.app.core.AppError
import com.zzupocket.app.core.net.readBoundedText
import com.zzupocket.app.core.security.SchoolNetworkInterceptor
import com.zzupocket.app.core.security.SchoolNetworkPolicy
import com.zzupocket.app.core.security.SchoolService
import com.zzupocket.app.data.ecard.EcardClient
import com.zzupocket.app.data.auth.CasClient
import com.zzupocket.app.data.gms.GmsClient
import com.zzupocket.app.data.gms.GmsCookieJar
import java.io.IOException
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import okhttp3.Cookie
import okhttp3.Dns
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import org.junit.Assert.*
import org.junit.Test

/** No real credentials, DNS, sockets or external requests. All transport is synthetic. */
class SecurityBoundaryTest {
    private val noDns = object : Dns {
        override fun lookup(hostname: String): List<java.net.InetAddress> =
            throw AssertionError("Tests must never resolve a network host")
    }

    @Test fun `financial entry points fail before the supplied transport`() = runBlocking {
        val attempts = AtomicInteger()
        val transport = OkHttpClient.Builder().dns(noDns).addInterceptor {
            attempts.incrementAndGet()
            throw AssertionError("Financial request reached transport")
        }.build()
        val api = EcardClient(transport, Json { ignoreUnknownKeys = true })
        val calls: List<suspend () -> Any> = listOf(
            { api.fetchTid("synthetic") }, { api.fetchTokens("synthetic") },
            { api.queryRemainingKwh("synthetic", "synthetic") },
            { api.fetchBoundLocation("synthetic") },
            { api.fetchLocationLevel("synthetic", "area") },
            { api.rawCall("/user/tradeList", "synthetic", "{}") },
            { api.fetchTradeTypes("synthetic") },
            { api.fetchTradeList("synthetic", "1", "2026-01-01", "2026-01-02") },
            { api.fetchCardBalance("synthetic") }, { api.rawCardBalance("synthetic") },
        )
        calls.forEach { call ->
            try { call(); fail("Financial capability must be disabled") }
            catch (expected: AppError.SecurityRestriction) { /* local rejection */ }
        }
        assertEquals(0, attempts.get())
    }

    @Test fun `scheme port userinfo suffix and finance bypasses are rejected`() {
        listOf(
            "http://jwxt.zzu.edu.cn/", "https://jwxt.zzu.edu.cn:8443/",
            "https://jwxt.zzu.edu.cn.evil.invalid/", "https://jwxt.zzu.edu.cn@evil.invalid/",
            "https://user:pass@jwxt.zzu.edu.cn/", "https://127.0.0.1/",
            "https://ecard.v.zzu.edu.cn/server/auth/getToken",
            "https://info.s.zzu.edu.cn/portal-api/v1/thrid-adapter/get-person-info-card-list",
            "https://order.lib.zzu.edu.cn/", "https://jwxt.zzu.edu.cn./",
        ).forEach { assertFalse(it, SchoolNetworkPolicy.permits(it.toHttpUrl())) }
        assertTrue(SchoolNetworkPolicy.permits("https://jwxt.zzu.edu.cn/".toHttpUrl()))
        assertFalse(SchoolNetworkPolicy.permits("https://jwxt.zzu.edu.cn/".toHttpUrl(), SchoolNetworkPolicy.webHosts))
    }

    @Test fun `MFA state and SMS codes cannot be sent to untrusted destinations`() = runBlocking {
        val attempts = AtomicInteger()
        val transport = OkHttpClient.Builder().dns(noDns).addInterceptor {
            attempts.incrementAndGet()
            throw AssertionError("Untrusted MFA request reached transport")
        }.build()
        val api = CasClient(transport, Json, "synthetic-device")
        listOf("https://evil.invalid/", "http://cas.s.zzu.edu.cn/", "https://cas.s.zzu.edu.cn:8443/",
            "https://user:pass@cas.s.zzu.edu.cn/", "https://cas.s.zzu.edu.cn/?redirect=evil").forEach { url ->
            val challenge = CasClient.MfaChallenge("synthetic-state", "synthetic-gid", url)
            try { api.sendSmsCode(challenge); fail("Untrusted MFA destination accepted") }
            catch (expected: AppError.SecurityRestriction) { /* no network */ }
            try { api.verifySmsCode(challenge, "000000"); fail("SMS code left the trust boundary") }
            catch (expected: AppError.SecurityRestriction) { /* no network */ }
        }
        assertEquals(0, attempts.get())
    }

    @Test fun `blocked requests never reach transport or DNS under concurrent load`() {
        val attempts = AtomicInteger()
        val client = OkHttpClient.Builder().dns(noDns)
            .addInterceptor(SchoolNetworkInterceptor(SchoolService.EAS)).addInterceptor {
                attempts.incrementAndGet()
                Response.Builder().request(it.request()).protocol(Protocol.HTTP_1_1)
                    .code(200).message("synthetic").body("{}".toResponseBody()).build()
            }.build()
        val pool = Executors.newFixedThreadPool(16)
        try {
            pool.invokeAll((0 until 32).map { Callable {
                repeat(250) {
                    try {
                        client.newCall(Request.Builder().url("https://ecard.v.zzu.edu.cn/blocked").build()).execute().close()
                        fail("Policy bypass")
                    } catch (expected: IOException) { /* no DNS or sockets */ }
                }
            } }, 30, TimeUnit.SECONDS).forEach { it.get() }
            assertEquals(0, attempts.get())
        } finally { pool.shutdownNow() }
    }

    @Test fun `native research client does not follow credential bearing redirects`() {
        val client = GmsClient.newClient()
        assertFalse(client.followRedirects)
        assertFalse(client.followSslRedirects)
        assertFalse(client.retryOnConnectionFailure)
        assertTrue(client.interceptors.any { it is SchoolNetworkInterceptor })
    }

    @Test fun `decompressed and unknown length responses are bounded`() {
        assertEquals("ok", "ok".toResponseBody().readBoundedText(2))
        val oversized = object : ResponseBody() {
            override fun contentType(): okhttp3.MediaType? = null
            override fun contentLength() = -1L
            override fun source() = Buffer().writeUtf8("x".repeat(1025))
        }
        try { oversized.readBoundedText(1024); fail("Oversized body accepted") }
        catch (expected: IOException) { /* before decoding */ }
        try { ("[".repeat(65) + "0" + "]".repeat(65)).toResponseBody().readBoundedText(); fail("Deep JSON accepted") }
        catch (expected: IOException) { /* parser stack is protected */ }
        assertEquals("{\"value\":\"[[[\"}", "{\"value\":\"[[[\"}".toResponseBody().readBoundedText())
    }

    @Test fun `cookie scope expiry secure deletion and concurrent mutation`() {
        val jar = GmsCookieJar()
        val good = "https://gmsstu.zzu.edu.cn/stu/api".toHttpUrl()
        jar.seed(good.host, mapOf("session" to "synthetic"))
        assertEquals(1, jar.loadForRequest(good).size)
        assertTrue(jar.loadForRequest("http://gmsstu.zzu.edu.cn/stu/api".toHttpUrl()).isEmpty())
        assertTrue(jar.loadForRequest("https://gmsstu.zzu.edu.cn/other".toHttpUrl()).isEmpty())
        assertTrue(jar.loadForRequest("https://sub.gmsstu.zzu.edu.cn/stu/api".toHttpUrl()).isEmpty())
        jar.saveFromResponse(good, listOf(Cookie.Builder().hostOnlyDomain(good.host).path("/stu")
            .name("session").value("").expiresAt(0).build()))
        assertTrue(jar.loadForRequest(good).isEmpty())
        val pool = Executors.newFixedThreadPool(16)
        try {
            pool.invokeAll((0 until 32).map { n -> Callable {
                repeat(250) {
                    jar.seed(good.host, mapOf("session" to "synthetic-$n"))
                    jar.loadForRequest(good).forEach { assertTrue(it.secure && it.hostOnly && it.httpOnly) }
                    if (it % 10 == 0) jar.clear()
                }
            } }, 30, TimeUnit.SECONDS).forEach { it.get() }
        } finally { pool.shutdownNow() }
        jar.clear()
        assertEquals(0, jar.size())
    }
}
