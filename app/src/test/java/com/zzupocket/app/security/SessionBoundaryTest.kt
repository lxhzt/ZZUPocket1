package com.zzupocket.app.security

import com.zzupocket.app.data.gms.GmsCookie
import com.zzupocket.app.data.gms.GmsCookieJar
import com.zzupocket.app.data.gms.GmsClient
import com.zzupocket.app.core.AppError
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import okhttp3.Cookie
import okhttp3.Dns
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Synthetic sessions only: no DNS, school traffic or Android credential mocks. */
class SessionBoundaryTest {
    private val host = "gmsstu.zzu.edu.cn"
    private val url = "https://gmsstu.zzu.edu.cn/stu/".toHttpUrl()
    private val guid = "01234567-89ab-cdef-0123-456789abcdef"

    private fun cookie(name: String, value: String = "synthetic", path: String = "/stu"): Cookie =
        Cookie.Builder().hostOnlyDomain(host).path(path).name(name).value(value).secure().build()

    @Test
    fun `academic adoption excludes CAS and other cookies while preserving the documented session`() {
        val mixed = GmsCookie.parse(
            "${GmsCookie.SESSION_COOKIE}=$guid; TGC=synthetic-tgt; SESSION=synthetic-sso; " +
                "userToken=synthetic-jwt; route=node1",
        )
        assertEquals(mapOf(GmsCookie.SESSION_COOKIE to guid), GmsCookie.academicSessionOnly(mixed))
        val migrated = GmsCookie.join(GmsCookie.academicSessionOnly(mixed))
        assertEquals("${GmsCookie.SESSION_COOKIE}=$guid", migrated)
        assertEquals(migrated, GmsCookie.join(GmsCookie.academicSessionOnly(GmsCookie.parse(migrated))))
    }

    @Test
    fun `missing or malformed academic session never falls back to SSO cookies`() {
        listOf(null, "", "TGC=synthetic-tgt; SESSION=synthetic-sso", "${GmsCookie.SESSION_COOKIE}=not-a-guid",
            "${GmsCookie.SESSION_COOKIE}=$guid-extra", "${GmsCookie.SESSION_COOKIE}=$guid\r\nTGC=synthetic")
            .forEach { assertTrue(GmsCookie.academicSessionOnly(GmsCookie.parse(it)).isEmpty()) }
    }

    @Test
    fun `logout prevents a late response from reviving the cookie jar`() {
        val jar = GmsCookieJar()
        jar.seed(host, mapOf(GmsCookie.SESSION_COOKIE to guid))
        val oldRequest = jar.forCurrentSession()
        assertEquals(1, oldRequest.loadForRequest(url).size)
        jar.clear()
        assertFalse(oldRequest.isCurrent())
        oldRequest.saveFromResponse(url, listOf(cookie(GmsCookie.SESSION_COOKIE, guid)))
        jar.saveFromResponse(url, listOf(cookie(GmsCookie.SESSION_COOKIE, guid)))
        assertEquals(0, jar.size())
        assertTrue(oldRequest.loadForRequest(url).isEmpty())
    }

    @Test
    fun `late response from an earlier login cannot replace a newly adopted session`() {
        val jar = GmsCookieJar()
        jar.seed(host, mapOf(GmsCookie.SESSION_COOKIE to guid))
        val oldRequest = jar.forCurrentSession()
        jar.clear()
        val nextGuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        jar.seed(host, mapOf(GmsCookie.SESSION_COOKIE to nextGuid))
        val newRequest = jar.forCurrentSession()
        oldRequest.saveFromResponse(url, listOf(cookie(GmsCookie.SESSION_COOKIE, guid), cookie("route", "old")))
        assertEquals(nextGuid, jar.loadForRequest(url).single().value)
        newRequest.saveFromResponse(url, listOf(cookie("route", "new")))
        assertTrue(newRequest.isCurrent())
        assertEquals(setOf(nextGuid, "new"), jar.loadForRequest(url).map { it.value }.toSet())
    }

    @Test
    fun `oversized response cookie fields cannot replace accepted cookies`() {
        val jar = GmsCookieJar()
        jar.seed(host, mapOf(GmsCookie.SESSION_COOKIE to guid))
        val scope = jar.forCurrentSession()
        scope.saveFromResponse(url, listOf(
            cookie("n".repeat(129)),
            cookie("oversized-path", path = "/" + "p".repeat(2048)),
            cookie(GmsCookie.SESSION_COOKIE, "v".repeat(4097)),
            cookie("route", "node1"),
        ))
        assertEquals(setOf(GmsCookie.SESSION_COOKIE, "route"), jar.loadForRequest(url).map { it.name }.toSet())
        assertEquals(guid, jar.loadForRequest(url).first { it.name == GmsCookie.SESSION_COOKIE }.value)
    }

    @Test
    fun `production GMS client rejects a result that returns after logout`() = runBlocking {
        val jar = GmsCookieJar()
        jar.seed(host, mapOf(GmsCookie.SESSION_COOKIE to guid))
        var calls = 0
        val client = GmsClient.newClient(jar).newBuilder()
            .dns(object : Dns {
                override fun lookup(hostname: String): List<java.net.InetAddress> =
                    throw AssertionError("No network allowed: $hostname")
            })
            .addInterceptor { chain ->
                calls++
                val home = chain.request().url.encodedPath == "/stu/"
                val body = if (home) "<html>academic home</html>" else "{\"termcode\":[]}"
                if (!home) jar.clear()
                Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(200).message("OK")
                    .body(body.toResponseBody("application/json".toMediaType())).build()
            }.build()
        val error = runCatching { GmsClient(client, Json).fetchTerms() }.exceptionOrNull()
        assertTrue(error is AppError.ReLoginRequired)
        assertEquals(2, calls)
        assertEquals(0, jar.size())
    }
}
