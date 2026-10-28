package com.zzupocket.app.security

import com.zzupocket.app.core.security.runAcademicRead
import com.zzupocket.app.data.gms.GmsClient
import com.zzupocket.app.data.gms.GmsCookie
import com.zzupocket.app.data.gms.GmsCookieJar
import com.zzupocket.app.data.gms.GmsProfileIds
import com.zzupocket.app.data.gms.GmsScheduleSource
import com.zzupocket.app.data.gms.GmsSessionStorage
import com.zzupocket.app.data.gms.GmsStoredSession
import java.io.IOException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import okhttp3.Dns
import okhttp3.OkHttpClient
import org.junit.Assert.*
import org.junit.Test

/** Real profile transitions and a recoverable local reader; no Android, DNS or sockets. */
class AcademicReadRecoveryTest {
    private val cookie = "${GmsCookie.SESSION_COOKIE}=01234567-89ab-cdef-0123-456789abcdef"

    private class MemoryStorage : GmsSessionStorage {
        var last = GmsProfileIds.LEGACY
        var saved: GmsStoredSession? = null
        override fun restoreGmsSession() = saved
        override fun adoptGmsSession(cookie: String, loginAt: Long): GmsStoredSession {
            last = GmsProfileIds.nextAfter(last)
            return GmsStoredSession(cookie, last, loginAt).also { saved = it }
        }
        override fun clearGmsSession() { saved = null }
    }

    private fun source(): GmsScheduleSource {
        val noNetwork = OkHttpClient.Builder().dns(object : Dns {
            override fun lookup(hostname: String): List<java.net.InetAddress> =
                throw AssertionError("No network permitted: $hostname")
        }).addInterceptor { throw AssertionError("No requests permitted") }.build()
        return GmsScheduleSource(GmsClient(noNetwork, Json), GmsCookieJar(), MemoryStorage())
    }

    @Test fun `read error permits retry and later login and logout still revoke academic UI`() = runBlocking {
        withTimeout(5000) {
            val source = source()
            assertTrue(source.onWebViewLogin(cookie))
            val first = source.profileSnapshot()!!
            val ui = MutableStateFlow(listOf("previous private course"))
            val events = Channel<String>(Channel.UNLIMITED)
            val observer = launch(start = CoroutineStart.UNDISPATCHED) {
                source.profileChanges.collectLatest { profile ->
                    source.withCurrentProfile(profile) { ui.value = emptyList() }
                    runAcademicRead(onFailure = {
                        source.withCurrentProfile(profile) { ui.value = emptyList() }
                        events.trySend("failed")
                    }) {
                        if (profile === first) throw IOException("Synthetic local storage error")
                        source.withCurrentProfile(profile) {
                            ui.value = if (profile == null) emptyList() else listOf("next profile course")
                        }
                        events.send(if (profile == null) "logged out" else "loaded")
                    }
                }
            }
            try {
                assertEquals("failed", events.receive())
                assertTrue(ui.value.isEmpty())
                assertTrue(observer.isActive)
                // The same path used by a manual retry can recover without replacing the listener.
                runAcademicRead(onFailure = { throw AssertionError("Retry failed", it) }) {
                    source.withCurrentProfile(first) { ui.value = listOf("retry course") }
                }
                assertEquals(listOf("retry course"), ui.value)
                assertTrue(source.onWebViewLogin(cookie))
                assertEquals("loaded", events.receive())
                assertEquals(listOf("next profile course"), ui.value)
                source.clear()
                assertEquals("logged out", events.receive())
                assertTrue(ui.value.isEmpty())
                assertTrue(observer.isActive)
            } finally {
                observer.cancelAndJoin()
                events.close()
            }
        }
    }

    @Test fun `late failure from a replaced profile cannot clear the new profile UI`() = runBlocking {
        val source = source()
        assertTrue(source.onWebViewLogin(cookie))
        val old = source.profileSnapshot()!!
        assertTrue(source.onWebViewLogin(cookie))
        val next = source.profileSnapshot()!!
        var ui = listOf("new private course")
        var failures = 0
        runAcademicRead(onFailure = {
            failures++
            source.withCurrentProfile(old) { ui = emptyList() }
        }) { throw IOException("Late old local read failed") }
        assertEquals(1, failures)
        assertTrue(next.isCurrent())
        assertEquals(listOf("new private course"), ui)
    }

    @Test fun `cancellation is propagated without publishing fallback UI`() = runBlocking {
        val cancelled = CancellationException("Synthetic cancellation")
        var fallbackCalls = 0
        val caught = runCatching {
            runAcademicRead(onFailure = { fallbackCalls++ }) { throw cancelled }
        }.exceptionOrNull()
        assertSame(cancelled, caught)
        assertEquals(0, fallbackCalls)
    }
}
