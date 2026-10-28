package com.zzupocket.app.securitylab

import android.Manifest
import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import android.content.pm.PackageManager
import androidx.room.Room
import com.zzupocket.app.core.WeekSettings
import com.zzupocket.app.core.WeekSource
import com.zzupocket.app.core.security.SchoolNetworkInterceptor
import com.zzupocket.app.core.security.SchoolService
import com.zzupocket.app.data.auth.AuthRepository
import com.zzupocket.app.data.auth.CasClient
import com.zzupocket.app.data.auth.TokenStore
import com.zzupocket.app.data.db.AppDatabase
import com.zzupocket.app.data.eas.EasClient
import com.zzupocket.app.data.ecard.EcardClient
import com.zzupocket.app.data.gms.GmsClient
import com.zzupocket.app.data.gms.GmsCookie
import com.zzupocket.app.data.gms.GmsCookieJar
import com.zzupocket.app.data.gms.GmsProfileIds
import com.zzupocket.app.data.gms.GmsScheduleMapper
import com.zzupocket.app.data.gms.GmsScheduleSource
import com.zzupocket.app.data.prefs.UiPrefsStore
import com.zzupocket.app.data.repo.ScheduleRepository
import com.zzupocket.app.data.repo.TodayTimetable
import com.zzupocket.app.domain.Session
import java.time.LocalDate
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody

/**
 * Real Android Room and encrypted preferences with invented local records only.
 * This verifies imported GMS schedules, not ownership of manual or focus history.
 */
object RoomPartitionChecks {
    private const val LEGACY = GmsProfileIds.LEGACY
    private val date = LocalDate.of(2026, 10, 26) // Monday, first teaching week in this fixture.

    /** Keep the runner's setup/cold-restore preference markers intact. */
    private class NamespacedPreferencesContext(base: Context, private val prefix: String) : ContextWrapper(base) {
        override fun getApplicationContext(): Context = this
        override fun getSharedPreferences(name: String, mode: Int): SharedPreferences =
            super.getSharedPreferences(prefix + name, mode)
    }

    fun run(context: Context): List<LabCheckResult> = runBlocking {
        val results = mutableListOf<LabCheckResult>()
        val calls = AtomicInteger()
        val originalWeekSettings = linkedMapOf<Int, WeekSettings>()
        var database: AppDatabase? = null
        var preferences: UiPrefsStore? = null
        var source: GmsScheduleSource? = null

        fun record(name: String, passed: Boolean, detail: String = "") {
            results += LabCheckResult(name, passed, detail)
        }

        fun syntheticClient(service: SchoolService): OkHttpClient = OkHttpClient.Builder()
            .dns(object : Dns {
                override fun lookup(hostname: String): List<java.net.InetAddress> =
                    throw AssertionError("Room lab forbids DNS")
            })
            .addInterceptor(SchoolNetworkInterceptor(service))
            .addInterceptor { chain ->
                calls.incrementAndGet()
                Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1)
                    .code(200).message("Synthetic lab transport").body("{}".toResponseBody()).build()
            }
            .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false).build()

        try {
            record(
                "room-lab-internet-permission-absent",
                context.checkSelfPermission(Manifest.permission.INTERNET) != PackageManager.PERMISSION_GRANTED,
                "Target APK must be unable to use INTERNET; clients also forbid DNS and sockets.",
            )
            val tokenContext = NamespacedPreferencesContext(context, "security_lab_room_${UUID.randomUUID()}_")
            val store = TokenStore(tokenContext)
            val json = Json { ignoreUnknownKeys = true }
            val cas = CasClient(syntheticClient(SchoolService.CAS), json, "synthetic-device")
            val eas = EasClient(syntheticClient(SchoolService.EAS), json)
            val financial = EcardClient(syntheticClient(SchoolService.FINANCE_DISABLED), json)
            val auth = AuthRepository(store, cas, financial)
            val db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java).build()
            database = db
            val repo = ScheduleRepository(db, eas, auth)
            val prefs = UiPrefsStore(context)
            preferences = prefs
            val jar = GmsCookieJar()
            val gms = GmsClient(syntheticClient(SchoolService.GMS), json)
            val src = GmsScheduleSource(gms, jar, store)
            source = src

            fun mapped(id: Int, label: String): List<Session> = GmsScheduleMapper.toSessions(
                listOf(
                    GmsClient.WeekEntry(
                        weekIndex = 1, weekday = 1, period = 1,
                        courseName = "Synthetic $label course", courseCode = "LAB101",
                        className = null, teacher = "Synthetic $label teacher", room = "Synthetic $label room",
                    ),
                ),
                periods = GmsScheduleMapper.defaultPeriods(), semesterId = id,
            )

            suspend fun save(id: Int, label: String): List<Session> {
                val sessions = mapped(id, label).map {
                    // Preserve the actual pre-partition ID format in the legacy fixture.
                    if (id == LEGACY) it.copy(id = "gms:1:1:1-1:LAB101") else it
                }
                repo.saveTimetable(GmsScheduleSource.SOURCE, id, sessions, GmsScheduleMapper.toCourses(sessions))
                if (!originalWeekSettings.containsKey(id)) originalWeekSettings[id] = prefs.weekSettings(id)
                prefs.saveWeekSettings(id, WeekSettings(weekOneStart = date, totalWeeks = 8, confirmed = true, source = WeekSource.USER))
                return sessions
            }

            val legacy = save(LEGACY, "legacy")
            val cookieA = "${GmsCookie.SESSION_COOKIE}=11111111-1111-1111-1111-111111111111"
            check(src.onWebViewLogin("$cookieA; TGC=synthetic-sso-a; userToken=synthetic-wide-token"))
            val profileA = checkNotNull(src.profileSnapshot())
            val first = save(profileA.semesterId, "A")
            record(
                "room-lab-real-token-store-adopts-academic-cookie-only",
                store.restoreGmsSession()?.let { it.cookie == cookieA && it.semesterId == profileA.semesterId } == true,
                "Real Android encrypted preference storage retained the academic cookie and its local partition.",
            )

            val cookieB = "${GmsCookie.SESSION_COOKIE}=22222222-2222-2222-2222-222222222222"
            check(src.onWebViewLogin(cookieB))
            val profileB = checkNotNull(src.profileSnapshot())
            val second = save(profileB.semesterId, "B")
            val ids = listOf(LEGACY, profileA.semesterId, profileB.semesterId)
            val expected = listOf(legacy.single(), first.single(), second.single())

            record(
                "room-lab-real-room-retains-legacy-a-b-with-disjoint-primary-keys",
                ids.toSet().size == 3 && expected.map { it.id }.toSet().size == 3 &&
                    ids.all { db.courseSessionDao().bySemester(it).size == 1 } &&
                    ids.map { db.courseDao().bySemester(it).single().key }.toSet().size == 3 &&
                    ids.flatMap { db.courseSessionDao().bySemester(it) }.map { it.id }.toSet() == expected.map { it.id }.toSet(),
                "Same course code, week, weekday and period persisted as three separate real Room records.",
            )

            val visibleB = TodayTimetable.sessionsOn(repo, prefs, date, profileB)
            record(
                "room-lab-production-today-reader-shows-only-current-b",
                visibleB.size == 1 && visibleB.single().id == second.single().id &&
                    visibleB.single().semesterId == profileB.semesterId &&
                    visibleB.single().roomText == "Synthetic B room" &&
                    TodayTimetable.gradWeekAt(prefs, date, profileB) == 1 &&
                    TodayTimetable.hasAnySchedule(repo, prefs, profileB),
                "Production repository, Room DAO, DataStore week settings and TodayTimetable all read B only.",
            )

            var oldPublished = false
            val oldAccepted = src.withCurrentProfile(profileA) { oldPublished = true }
            record(
                "room-lab-old-a-snapshot-cannot-read-or-publish-under-b",
                !oldAccepted && !oldPublished && !profileA.isCurrent() &&
                    TodayTimetable.sessionsOn(repo, prefs, date, profileA).isEmpty(),
                "A remains stored, but its revoked snapshot is rejected by the production read and publication guards.",
            )

            record(
                "room-lab-null-profile-never-falls-back-to-legacy",
                TodayTimetable.sessionsOn(repo, prefs, date, null).isEmpty() &&
                    TodayTimetable.gradWeekAt(prefs, date, null) == null &&
                    !TodayTimetable.hasAnySchedule(repo, prefs, null),
                "Legacy has a valid week anchor and real rows; absence of a current profile still reveals none.",
            )

            // Reconstruct the encrypted preference reader, then restore the same production source.
            val reopened = TokenStore(tokenContext).restoreGmsSession()
            src.restore()
            val restored = checkNotNull(src.profileSnapshot())
            var staleRestorationPublished = false
            val staleRestorationAccepted = src.withCurrentProfile(profileB) { staleRestorationPublished = true }
            record(
                "room-lab-encrypted-restore-keeps-b-partition-and-revokes-old-snapshot",
                reopened?.let { it.semesterId == profileB.semesterId && it.cookie == cookieB } == true &&
                    restored.semesterId == profileB.semesterId && restored.isCurrent() &&
                    !profileB.isCurrent() && !staleRestorationAccepted && !staleRestorationPublished &&
                    TodayTimetable.sessionsOn(repo, prefs, date, restored).single().id == second.single().id,
                "This check recreates storage objects within the device process; the runner separately checks process restart.",
            )

            val beforeLogout = ids.associateWith { db.courseSessionDao().bySemester(it) }
            val coursesBeforeLogout = ids.associateWith { db.courseDao().bySemester(it) }
            val syncBeforeLogout = ids.associateWith { db.timetableSyncDao().get(GmsScheduleSource.SOURCE, it) }
            src.clear()
            record(
                "room-lab-logout-revokes-current-view-and-preserves-real-room-history",
                src.profileSnapshot() == null && !restored.isCurrent() && store.restoreGmsSession() == null &&
                    ids.all { db.courseSessionDao().bySemester(it) == beforeLogout[it] } &&
                    ids.all { db.courseDao().bySemester(it) == coursesBeforeLogout[it] } &&
                    ids.all { db.timetableSyncDao().get(GmsScheduleSource.SOURCE, it) == syncBeforeLogout[it] } &&
                    syncBeforeLogout.values.all { it != null } &&
                    TodayTimetable.sessionsOn(repo, prefs, date, src.profileSnapshot()).isEmpty(),
                "Logout changed credentials and the active pointer; legacy/A/B courses, sessions and sync rows survived intact.",
            )

            check(src.onWebViewLogin(cookieB))
            val next = checkNotNull(src.profileSnapshot())
            record(
                "room-lab-login-after-logout-does-not-reuse-cached-namespace",
                next.semesterId < profileB.semesterId && next.semesterId !in ids &&
                    repo.cachedSessions(GmsScheduleSource.SOURCE, next.semesterId).isEmpty() &&
                    TodayTimetable.sessionsOn(repo, prefs, date, next).isEmpty() &&
                    ids.all { db.courseSessionDao().bySemester(it) == beforeLogout[it] },
                "Identical synthetic cookie after logout still receives a fresh empty import namespace.",
            )
        } catch (error: Throwable) {
            record("room-lab-infrastructure-or-precondition", false, error.javaClass.simpleName)
        } finally {
            try {
                val prefs = preferences
                if (prefs != null) originalWeekSettings.forEach { (id, settings) -> prefs.saveWeekSettings(id, settings) }
                source?.clear()
            } catch (error: Throwable) {
                record("room-lab-fixture-cleanup", false, error.javaClass.simpleName)
            }
            try {
                database?.close()
            } catch (error: Throwable) {
                record("room-lab-memory-database-close", false, error.javaClass.simpleName)
            }
            record("room-lab-zero-school-transport-calls", calls.get() == 0, "Synthetic transport calls: ${calls.get()}; DNS and sockets forbidden.")
        }
        results
    }
}
