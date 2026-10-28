package com.zzupocket.app.data.gms

/** A local import partition, never a school identity or authorization claim. */
class GmsProfileSnapshot internal constructor(
    val semesterId: Int,
    private val stillCurrent: () -> Boolean,
) {
    init { require(GmsProfileIds.isProfile(semesterId)) }
    fun isCurrent(): Boolean = stillCurrent()
    override fun toString(): String = "GmsProfileSnapshot(semesterId=$semesterId)"
}

object GmsProfileIds {
    const val LEGACY = -10_001
    const val FIRST = -10_002
    fun isProfile(id: Int): Boolean = id <= FIRST
    fun nextAfter(lastIssued: Int): Int {
        require(lastIssued <= LEGACY && lastIssued > Int.MIN_VALUE) { "Local academic partition counter is invalid or exhausted" }
        return lastIssued - 1
    }
}

class GmsStoredSession(val cookie: String, val semesterId: Int, val loginAt: Long) {
    init { require(GmsProfileIds.isProfile(semesterId)) }
    override fun toString(): String = "GmsStoredSession(semesterId=$semesterId, cookie=<redacted>)"
}

/** Implementations must allocate and persist cookie, partition, counter and time atomically. */
interface GmsSessionStorage {
    fun restoreGmsSession(): GmsStoredSession?
    fun adoptGmsSession(cookie: String, loginAt: Long): GmsStoredSession
    fun clearGmsSession()
}
