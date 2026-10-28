package com.zzupocket.app.security

import com.zzupocket.app.core.AppError
import com.zzupocket.app.core.net.HttpClients
import com.zzupocket.app.core.security.*
import com.zzupocket.app.data.eas.EasClient
import com.zzupocket.app.data.gms.GmsClient
import java.io.IOException
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.Assert.*
import org.junit.Test

/** Synthetic credentials and in-process transport only. DNS and sockets are forbidden. */
class CredentialContainmentTest {
    private val guid = "12345678-1234-1234-1234-123456789abc"
    private val noDns = object : Dns {
        override fun lookup(hostname: String): List<java.net.InetAddress> = throw AssertionError("No DNS allowed")
    }
    private fun request(url: String, method: String = "GET", token: Boolean = false): Request =
        Request.Builder().url(url).apply {
            if (token) header("Authorization", "synthetic-token")
            if (method != "GET") method(method, "{}".toRequestBody())
        }.build()

    @Test fun `all retained EAS operations are allowed only in the EAS client`() {
        val micro = "https://jwxt.zzu.edu.cn/eams-micro-server/api/v1"
        val urls = listOf(
            "https://jwxt.zzu.edu.cn/eams-door/api/v1/calendar/get-all-semesters",
            "https://jwxt.zzu.edu.cn/eams-door/api/v1/portal/home/user-info",
            "$micro/semester/current-semester", "$micro/room/system/course-units",
            "$micro/lesson/student/course-table/20261", "$micro/room/place/campus",
            "$micro/room/place/roomTypes", "$micro/room/place/floors", "$micro/room/place/building?campusAssoc=1",
        ).map { request(it, token = true) } + request("$micro/room/place/rooms", "POST", true)
        urls.forEach { r ->
            SchoolService.entries.forEach { service ->
                assertEquals("${r.url} / $service", service == SchoolService.EAS, SchoolRequestPolicy.permits(r, service))
            }
        }
    }

    @Test fun `CAS login and MFA stay available without financial ticket exchange`() {
        val base = "https://cas.s.zzu.edu.cn"
        val allowed = listOf(
            request("$base/token/jwt/publicKey"),
            request("$base/token/mfa/detect?username=synthetic&password=synthetic&deviceId=synthetic", "POST"),
            request("$base/token/mfa/initByType/securephone?state=synthetic"),
            request("$base/token/password/passwordLogin?username=synthetic&password=synthetic&appId=synthetic&osType=android&geo=&deviceId=synthetic&clientId=&mfaState=synthetic", "POST"),
            request("$base/attest/api/guard/securephone/send", "POST"),
            request("$base/attest/api/guard/securephone/valid", "POST"),
            request("$base/attest/api/guard/api/guard/securephone/send", "POST"),
        )
        allowed.forEach { r ->
            assertTrue(SchoolRequestPolicy.permits(r, SchoolService.CAS))
            assertFalse(SchoolRequestPolicy.permits(r, SchoolService.EAS))
        }
        assertFalse(SchoolRequestPolicy.permits(request("$base/server/auth/host/open?token=synthetic"), SchoolService.CAS))
    }

    @Test fun `research requests decode to three exact read routes only`() {
        listOf("kbcx_drop" to "GET", "loadKb" to "POST", "bzkb_load" to "POST").forEach { (module, method) ->
            val url = "https://gmsstu.zzu.edu.cn/stu/" + GmsClient.encodeRoute("pygl/xskbcx/$module", guid)
            assertTrue(SchoolRequestPolicy.permits(request(url, method), SchoolService.GMS))
            assertFalse(SchoolRequestPolicy.permits(request(url, if (method == "GET") "POST" else "GET"), SchoolService.GMS))
        }
        assertTrue(SchoolRequestPolicy.permits(request("https://gmsstu.zzu.edu.cn/stu/"), SchoolService.GMS))
        listOf("pygl/xskbcx/loadKb/delete", "utilities/pay", "auth/host/open").forEach {
            assertFalse(SchoolRequestPolicy.permits(request("https://gmsstu.zzu.edu.cn/stu/" + GmsClient.encodeRoute(it, guid), "POST"), SchoolService.GMS))
        }
    }

    @Test fun `forged destinations methods queries and credential headers stop before transport`() {
        val attempts = AtomicInteger()
        val client = OkHttpClient.Builder().dns(noDns).addInterceptor(SchoolNetworkInterceptor(SchoolService.EAS))
            .addInterceptor { attempts.incrementAndGet(); throw AssertionError("Rejected request escaped") }.build()
        val good = "https://jwxt.zzu.edu.cn/eams-door/api/v1/calendar/get-all-semesters"
        val bad = listOf(
            request("https://cas.s.zzu.edu.cn/token/jwt/publicKey", token = true),
            request("https://ecard.v.zzu.edu.cn/server/utilities/pay", "POST", true),
            request("https://jwxt.zzu.edu.cn/server/utilities/pay", "POST", true),
            request("$good?token=synthetic", token = true), request(good, "POST", true),
            request("https://jwxt.zzu.edu.cn/eams-micro-server/api/v1/room/place/building?campusAssoc=1&campusAssoc=2", token = true),
            request(good, token = true).newBuilder().header("Cookie", "userToken=synthetic").build(),
            request(good, token = true).newBuilder().header("Host", "ecard.v.zzu.edu.cn").build(),
            request(good, token = true).newBuilder().header("X-Id-Token", "synthetic").build(),
        )
        bad.forEach { r ->
            try { client.newCall(r).execute(); fail("Rejected request accepted") }
            catch (expected: IOException) { /* no transport, DNS or socket */ }
        }
        assertEquals(0, attempts.get())
    }

    @Test fun `production finance factory cannot send even a valid school request`() {
        val attempts = AtomicInteger()
        val client = HttpClients.ecard.newBuilder().dns(noDns).addInterceptor {
            attempts.incrementAndGet(); throw AssertionError("Finance transport enabled")
        }.build()
        try { client.newCall(request("https://cas.s.zzu.edu.cn/token/jwt/publicKey")).execute(); fail("Finance client escaped") }
        catch (expected: IOException) { }
        assertEquals(0, attempts.get())
    }

    @Test fun `real retained EAS methods reach synthetic transport with approved shapes`() = runBlocking {
        val attempts = AtomicInteger()
        val client = HttpClients.eas.newBuilder().apply {
            // JVM tests have no Android Log implementation; retain every policy/transport guard.
            assertTrue(interceptors().any { it is SchoolNetworkInterceptor })
            interceptors().removeAll { it.javaClass.simpleName == "SafeLogInterceptor" }
        }.dns(noDns).addInterceptor {
            assertTrue(SchoolRequestPolicy.permits(it.request(), SchoolService.EAS))
            attempts.incrementAndGet(); throw IOException("synthetic stop")
        }.build()
        val api = EasClient(client, Json)
        val calls: List<suspend () -> Any?> = listOf(
            { api.fetchSemesters("synthetic") }, { api.fetchCurrentSemester("synthetic") },
            { api.fetchPeriods("synthetic") }, { api.fetchCourseTable("synthetic", 20261) },
            { api.fetchCampuses("synthetic") }, { api.fetchRoomTypes("synthetic") },
            { api.fetchFloors("synthetic") }, { api.fetchBuildings("synthetic", 1L) },
            { api.fetchBuildings("synthetic", null) },
            { api.fetchRooms("synthetic", EasClient.RoomQueryBody(1, 30, listOf(1L), date = "2026-10-26")) },
        )
        calls.forEach { call ->
            try { call(); fail("Expected synthetic stop") }
            catch (expected: AppError.Network) { }
        }
        assertEquals(calls.size, attempts.get())
    }

    @Test fun `real retained GMS methods reach synthetic transport with approved encoded routes`() = runBlocking {
        val attempts = AtomicInteger()
        val jar = com.zzupocket.app.data.gms.GmsCookieJar()
        jar.seed("gmsstu.zzu.edu.cn", mapOf(com.zzupocket.app.data.gms.GmsCookie.SESSION_COOKIE to guid))
        val client = GmsClient.newClient(jar).newBuilder().dns(noDns).addInterceptor {
            assertTrue(SchoolRequestPolicy.permits(it.request(), SchoolService.GMS))
            attempts.incrementAndGet(); throw IOException("synthetic stop")
        }.build()
        val api = GmsClient(client, Json)
        val calls: List<suspend () -> Any?> = listOf(
            { api.fetchTerms() }, { api.fetchTermTable("20261") }, { api.fetchWeekTable() },
        )
        calls.forEach { call ->
            try { call(); fail("Expected synthetic stop") }
            catch (expected: AppError.Network) { }
        }
        assertEquals(calls.size, attempts.get())
    }

    @Test fun `raw diagnostic API cannot forward a credential even with an injected client`() = runBlocking {
        val attempts = AtomicInteger()
        val client = OkHttpClient.Builder().dns(noDns).addInterceptor {
            attempts.incrementAndGet(); throw AssertionError("Raw API reached transport")
        }.build()
        try { EasClient(client, Json).rawCall("https://cas.s.zzu.edu.cn/", "synthetic"); fail("Raw call escaped") }
        catch (expected: AppError.SecurityRestriction) { }
        assertEquals(0, attempts.get())
    }

    @Test fun `GMS browser cannot be repurposed for financial CAS service`() {
        val base = "https://cas.s.zzu.edu.cn/cas/a/login?service="
        assertTrue(SecureWebView.permits(com.zzupocket.app.data.gms.GmsProbe.CAS_SERVICE_ENTRY))
        assertTrue(SecureWebView.permits(base + "https%3A%2F%2Fgmsstu.zzu.edu.cn%2Fstu%2F"))
        listOf("https://ecard.v.zzu.edu.cn/", "https://gmsstu.zzu.edu.cn.evil.invalid/stu/", "http://gmsstu.zzu.edu.cn/stu/", "https://gmsstu.zzu.edu.cn/other").forEach {
            assertFalse(SecureWebView.permits(base + java.net.URLEncoder.encode(it, "UTF-8")))
        }
        assertFalse(SecureWebView.permits(base + "https%3A%2F%2Fgmsstu.zzu.edu.cn%2Fstu%2F&service=https%3A%2F%2Fecard.v.zzu.edu.cn"))
    }

    @Test fun `password lease expires during inactivity and SMS resend cannot extend it`() {
        var clock = 1000L
        val pending = PendingLoginCredentials<String> { clock }
        pending.start("synthetic-account", "synthetic-password")
        clock += PendingLoginCredentials.LIFETIME_MS - 1
        assertTrue(pending.attachChallenge("synthetic-challenge"))
        assertNotNull(pending.get())
        assertFalse(pending.get().toString().contains("synthetic"))
        clock++
        assertNull(pending.get())
        assertFalse(pending.attachChallenge("late-challenge"))
        pending.start("synthetic-account", "synthetic-password")
        pending.clear()
        assertNull(pending.get())
    }
}
