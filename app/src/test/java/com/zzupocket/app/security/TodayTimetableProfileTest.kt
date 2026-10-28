package com.zzupocket.app.security

import com.zzupocket.app.data.gms.GmsProfileSnapshot
import com.zzupocket.app.data.repo.TodayTimetable
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

/** Local data access callbacks only; no Android services, database, DNS or sockets. */
class TodayTimetableProfileTest {
    @Test fun `missing profile does not read legacy graduate cache`() = runBlocking {
        var reads = 0
        val result = TodayTimetable.readGraduate<List<String>>(null, emptyList()) {
            reads++
            listOf("legacy-sensitive-course")
        }
        assertTrue(result.isEmpty())
        assertEquals(0, reads)
    }

    @Test fun `revoked profile cannot start a graduate cache read`() = runBlocking {
        var reads = 0
        val old = GmsProfileSnapshot(-10002) { false }
        val result = TodayTimetable.readGraduate<List<String>>(old, emptyList()) {
            reads++
            listOf("old-sensitive-course")
        }
        assertTrue(result.isEmpty())
        assertEquals(0, reads)
    }

    @Test fun `active graduate cache reads use the captured namespace exclusively`() = runBlocking {
        val requests = mutableListOf<Int>()
        val first = GmsProfileSnapshot(-10002) { true }
        val second = GmsProfileSnapshot(-10003) { true }
        val cache = mapOf(-10001 to listOf("legacy"), -10002 to listOf("first"), -10003 to listOf("second"))
        suspend fun read(profile: GmsProfileSnapshot) = TodayTimetable.readGraduate(profile, emptyList<String>()) {
            requests += it
            cache.getValue(it)
        }
        assertEquals(listOf("first"), read(first))
        assertEquals(listOf("second"), read(second))
        assertEquals(listOf(-10002, -10003), requests)
        assertFalse(requests.contains(-10001))
    }

    @Test fun `graduate result arriving after logout is discarded`() = runBlocking {
        val active = AtomicBoolean(true)
        val profile = GmsProfileSnapshot(-10002) { active.get() }
        val started = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val result = async {
            TodayTimetable.readGraduate(profile, emptyList<String>()) { requested ->
                assertEquals(-10002, requested)
                started.complete(Unit)
                release.await()
                listOf("old-sensitive-course")
            }
        }
        started.await()
        active.set(false)
        release.complete(Unit)
        assertTrue(result.await().isEmpty())
    }
}
