package com.zzupocket.app.core.security

/** A short, monotonic lease for the password needed between CAS login and SMS verification. */
class PendingLoginCredentials<T>(private val now: () -> Long) {
    class Snapshot<T>(val account: String, val password: String, val challenge: T?) {
        override fun toString(): String = "PendingLoginCredentials.Snapshot(redacted)"
    }

    private var value: Snapshot<T>? = null
    private var expiresAt = 0L

    fun start(account: String, password: String) {
        value = Snapshot(account, password, null)
        expiresAt = now() + LIFETIME_MS
    }

    fun get(): Snapshot<T>? {
        if (now() >= expiresAt) clear()
        return value
    }

    fun attachChallenge(challenge: T): Boolean {
        val current = get() ?: return false
        value = Snapshot(current.account, current.password, challenge)
        return true
    }

    fun clear() { value = null; expiresAt = 0L }

    companion object { const val LIFETIME_MS = 5 * 60 * 1000L }
}
