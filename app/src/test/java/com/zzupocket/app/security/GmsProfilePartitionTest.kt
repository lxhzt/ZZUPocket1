package com.zzupocket.app.security

import com.zzupocket.app.core.AppError
import com.zzupocket.app.data.gms.GmsClient
import com.zzupocket.app.data.gms.GmsCookie
import com.zzupocket.app.data.gms.GmsCookieJar
import com.zzupocket.app.data.gms.GmsProfileIds
import com.zzupocket.app.data.gms.GmsScheduleMapper
import com.zzupocket.app.data.gms.GmsScheduleSource
import com.zzupocket.app.data.gms.GmsSessionStorage
import com.zzupocket.app.data.gms.GmsStoredSession
import com.zzupocket.app.ui.schedule.ScheduleUiState
import com.zzupocket.app.ui.schedule.forGmsProfile
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.*
import org.junit.Test
import java.time.LocalDate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** Real partition/source/mapper logic with synthetic in-memory storage and no network. */
class GmsProfilePartitionTest {
    private val guid = "01234567-89ab-cdef-0123-456789abcdef"
    private val cookie = "${GmsCookie.SESSION_COOKIE}=$guid"

    private class MemoryStorage : GmsSessionStorage {
        var lastIssued = GmsProfileIds.LEGACY
        var saved: GmsStoredSession? = null
        override fun restoreGmsSession() = saved
        override fun adoptGmsSession(cookie: String, loginAt: Long): GmsStoredSession {
            val id = GmsProfileIds.nextAfter(lastIssued)
            return GmsStoredSession(cookie, id, loginAt).also { saved = it; lastIssued = id }
        }
        override fun clearGmsSession() { saved = null }
    }

    private fun source(storage: MemoryStorage = MemoryStorage()): GmsScheduleSource =
        GmsScheduleSource(GmsClient(OkHttpClient.Builder().dns(object : Dns {
            override fun lookup(hostname: String): List<java.net.InetAddress> =
                throw AssertionError("Network forbidden: $hostname")
        }).build(), Json), GmsCookieJar(), storage)

    private fun entry() = GmsClient.WeekEntry(
        weekIndex = 7, weekday = 1, period = 1, courseName = "Synthetic course", courseCode = "SYN101",
        className = null, teacher = "Synthetic teacher", room = "Synthetic room",
    )

    @Test
    fun `partition allocator never reuses legacy or wraps on exhaustion`() {
        var last = GmsProfileIds.LEGACY
        val ids = (1..10_000).map { GmsProfileIds.nextAfter(last).also { last = it } }
        assertEquals(10_000, ids.toSet().size)
        assertTrue(ids.all(GmsProfileIds::isProfile))
        assertFalse(GmsProfileIds.isProfile(GmsProfileIds.LEGACY))
        assertEquals(Int.MIN_VALUE, GmsProfileIds.nextAfter(Int.MIN_VALUE + 1))
        for (bad in listOf(Int.MIN_VALUE, 0, -1, 20261)) {
            assertTrue(runCatching { GmsProfileIds.nextAfter(bad) }.isFailure)
        }
    }

    @Test
    fun `same academic content in different logins has disjoint session and course keys`() {
        val first = GmsScheduleMapper.toSessions(listOf(entry()), semesterId = -10002)
        val second = GmsScheduleMapper.toSessions(listOf(entry()), semesterId = -10003)
        assertNotEquals(first.single().id, second.single().id)
        val firstCourse = GmsScheduleMapper.toCourses(first).single()
        val secondCourse = GmsScheduleMapper.toCourses(second).single()
        assertNotEquals(firstCourse.key, secondCourse.key)
        assertEquals(setOf(-10002, -10003), GmsScheduleMapper.toCourses(first + second).map { it.semesterId }.toSet())
        val semester = GmsScheduleMapper.toSemester(
            GmsClient.TermDto("20261", "Synthetic term", true), listOf(entry()), emptyList(),
            LocalDate.of(2026, 10, 27), semesterId = -10003,
        )
        assertEquals(-10003, semester.id)
    }

    @Test
    fun `each web login gets a new partition even with identical cookies and logout preserves allocation`() {
        val storage = MemoryStorage()
        val src = source(storage)
        assertTrue(src.onWebViewLogin("$cookie; TGC=synthetic-sso; SESSION=synthetic-session"))
        val first = src.profileSnapshot()!!
        assertEquals(cookie, storage.saved!!.cookie)
        assertTrue(first.isCurrent())
        assertTrue(src.onWebViewLogin(cookie))
        val second = src.profileSnapshot()!!
        assertNotEquals(first.semesterId, second.semesterId)
        assertFalse(first.isCurrent())
        src.clear()
        assertNull(src.profileSnapshot())
        assertNull(storage.saved)
        assertFalse(second.isCurrent())
        assertTrue(src.onWebViewLogin(cookie))
        assertTrue(src.profileSnapshot()!!.semesterId < second.semesterId)
    }

    @Test
    fun `restart restores its saved partition and malformed cookies cannot replace it`() {
        val storage = MemoryStorage()
        val firstSource = source(storage)
        assertTrue(firstSource.onWebViewLogin(cookie))
        val id = firstSource.profileSnapshot()!!.semesterId
        val restored = source(storage)
        restored.restore()
        assertEquals(id, restored.profileSnapshot()!!.semesterId)
        assertEquals(id, storage.lastIssued)
        assertFalse(restored.onWebViewLogin("TGC=synthetic-only"))
        assertEquals(id, restored.profileSnapshot()!!.semesterId)
        assertTrue(restored.hasSession())
    }

    @Test
    fun `publication accepts only the exact active snapshot including the logged-out null state`() {
        val src = source()
        var published = 0
        assertTrue(src.withCurrentProfile(null) { published++ })
        src.onWebViewLogin(cookie)
        val first = src.profileSnapshot()!!
        assertFalse(src.withCurrentProfile(null) { published++ })
        assertTrue(src.withCurrentProfile(first) { published++ })
        src.onWebViewLogin(cookie)
        assertFalse(src.withCurrentProfile(first) { published++ })
        src.clear()
        assertFalse(src.withCurrentProfile(first) { published++ })
        assertTrue(src.withCurrentProfile(null) { published++ })
        assertEquals(3, published)
    }

    @Test
    fun `logout waits for a synchronous publication then revokes subsequent old publications`() {
        val src = source()
        src.onWebViewLogin(cookie)
        val profile = src.profileSnapshot()!!
        val inside = CountDownLatch(1)
        val release = CountDownLatch(1)
        val clearStarted = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        try {
            val publish = executor.submit<Boolean> {
                src.withCurrentProfile(profile) { inside.countDown(); check(release.await(5, TimeUnit.SECONDS)) }
            }
            assertTrue(inside.await(5, TimeUnit.SECONDS))
            val clear = executor.submit { clearStarted.countDown(); src.clear() }
            assertTrue(clearStarted.await(5, TimeUnit.SECONDS))
            try {
                clear.get(100, TimeUnit.MILLISECONDS)
                fail("Logout must serialize with a publication already holding the source lock")
            } catch (_: TimeoutException) { }
            release.countDown()
            assertTrue(publish.get(5, TimeUnit.SECONDS))
            clear.get(5, TimeUnit.SECONDS)
            assertFalse(src.withCurrentProfile(profile) { fail("Stale publication") })
            assertNull(src.profileSnapshot())
        } finally {
            release.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun `switching the rendered partition revokes old graduate lessons and course detail`() {
        val sessions = GmsScheduleMapper.toSessions(listOf(entry()), semesterId = -10002)
        val course = GmsScheduleMapper.toCourses(sessions).single()
        val oldUi = ScheduleUiState(gradMode = true, gmsProfileId = -10002, gmsSessions = sessions,
            gmsCourses = listOf(course), detailCourse = course, dataFetchedAt = 1L)
        val next = oldUi.forGmsProfile(-10003)
        assertEquals(-10003, next.gmsProfileId)
        assertTrue(next.gmsSessions.isEmpty())
        assertTrue(next.gmsCourses.isEmpty())
        assertNull(next.detailCourse)
        assertNull(next.dataFetchedAt)
        assertTrue(oldUi.gmsSessions.isNotEmpty()) // Immutable history was not deleted or mutated.
        assertNull(next.forGmsProfile(null).gmsProfileId)
    }

    @Test
    fun `an in-flight academic result cannot be returned under a subsequent login`() = runBlocking {
        val storage = MemoryStorage()
        val jar = GmsCookieJar()
        lateinit var src: GmsScheduleSource
        var calls = 0
        val client = GmsClient.newClient(jar).newBuilder()
            .dns(object : Dns {
                override fun lookup(hostname: String): List<java.net.InetAddress> =
                    throw AssertionError("No network allowed: $hostname")
            })
            .addInterceptor { chain ->
                calls++
                val home = chain.request().url.encodedPath == "/stu/"
                if (!home) src.onWebViewLogin(cookie)
                val text = if (home) "<html>Synthetic home</html>" else
                    "{\"termcode\":[{\"value\":\"20261\",\"text\":\"Old private term\",\"selected\":true}]}"
                Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(200).message("OK")
                    .body(text.toResponseBody("application/json".toMediaType())).build()
            }.build()
        src = GmsScheduleSource(GmsClient(client, Json), jar, storage)
        src.onWebViewLogin(cookie)
        val old = src.profileSnapshot()!!
        val error = runCatching { src.terms() }.exceptionOrNull()
        assertTrue(error is AppError.ReLoginRequired)
        assertFalse(old.isCurrent())
        assertTrue(src.profileSnapshot()!!.semesterId < old.semesterId)
        assertEquals(2, calls)
    }
}
