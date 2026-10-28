package com.zzupocket.app.data.auth

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.zzupocket.app.core.AppError
import com.zzupocket.app.data.gms.GmsCookie
import com.zzupocket.app.data.gms.GmsProfileIds
import com.zzupocket.app.data.gms.GmsSessionStorage
import com.zzupocket.app.data.gms.GmsStoredSession

/**
 * 令牌存储。
 *
 * ⚠️ **只存令牌，不存密码。** 代价是 userToken（约 1 个月）过期后需要重新登录一次；
 * 收益是设备上不存在可直接复用的账号密码。
 *
 * 文件名 `secure_prefs` 与 `res/xml/backup_rules.xml` / `data_extraction_rules.xml`
 * 里的排除项必须一致 —— 令牌不进任何备份。
 */
class TokenStore(context: Context) : GmsSessionStorage {

    private val prefs: SharedPreferences by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            FILE_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        ).also { encrypted ->
            // Retire only unused authentication material; never delete business/history data.
            encrypted.edit().remove(KEY_CAS_REFRESH).remove(KEY_ECARD_ACCESS)
                .remove(KEY_ECARD_REFRESH).remove(KEY_ECARD_AT).apply()
        }
    }

    var casUserToken: String?
        get() = prefs.getString(KEY_CAS_USER, null)
        set(value) = prefs.edit().putString(KEY_CAS_USER, value).apply()

    var casRefreshToken: String?
        get() = prefs.getString(KEY_CAS_REFRESH, null)
        set(value) = prefs.edit().putString(KEY_CAS_REFRESH, value).apply()

    var ecardAccessToken: String?
        get() = prefs.getString(KEY_ECARD_ACCESS, null)
        set(value) = prefs.edit().putString(KEY_ECARD_ACCESS, value).apply()

    var ecardRefreshToken: String?
        get() = prefs.getString(KEY_ECARD_REFRESH, null)
        set(value) = prefs.edit().putString(KEY_ECARD_REFRESH, value).apply()

    var ecardTokenAt: Long
        get() = prefs.getLong(KEY_ECARD_AT, 0L)
        set(value) = prefs.edit().putLong(KEY_ECARD_AT, value).apply()

    /** Only the documented GMS application cookie is retained, with its local import partition. */
    @Synchronized
    override fun restoreGmsSession(): GmsStoredSession? {
        val parsed = GmsCookie.academicSessionOnly(GmsCookie.parse(prefs.getString(KEY_GMS_COOKIE, null)))
        if (parsed.isEmpty()) {
            clearGmsSession()
            return null
        }
        val cookie = GmsCookie.join(parsed)
        val savedId = prefs.getInt(KEY_GMS_PROFILE, GmsProfileIds.LEGACY)
        val lastId = prefs.getInt(KEY_GMS_LAST_PROFILE, GmsProfileIds.LEGACY)
        val loginAt = prefs.getLong(KEY_GMS_COOKIE_AT, 0L)
        if (GmsProfileIds.isProfile(savedId)) {
            check(lastId <= savedId) { "Local academic partition counter is inconsistent" }
            persistGmsSession(cookie, savedId, lastId, loginAt)
            return GmsStoredSession(cookie, savedId, loginAt)
        }
        // Old -10001 records have no verified owner: retain them but never assign them to this login.
        return adoptGmsSession(cookie, loginAt)
    }

    @Synchronized
    override fun adoptGmsSession(cookie: String, loginAt: Long): GmsStoredSession {
        val parsed = GmsCookie.academicSessionOnly(GmsCookie.parse(cookie))
        require(parsed.isNotEmpty()) { "Missing academic session" }
        val id = GmsProfileIds.nextAfter(prefs.getInt(KEY_GMS_LAST_PROFILE, GmsProfileIds.LEGACY))
        val sanitized = GmsCookie.join(parsed)
        persistGmsSession(sanitized, id, id, loginAt)
        return GmsStoredSession(sanitized, id, loginAt)
    }

    private fun persistGmsSession(cookie: String, id: Int, lastId: Int, loginAt: Long) {
        if (!prefs.edit().putString(KEY_GMS_COOKIE, cookie).putInt(KEY_GMS_PROFILE, id)
                .putInt(KEY_GMS_LAST_PROFILE, lastId).putLong(KEY_GMS_COOKIE_AT, loginAt).commit()) {
            throw AppError.SecurityRestriction("无法安全保存研究生登录，请检查设备存储后重试。")
        }
    }

    @Synchronized
    override fun clearGmsSession() {
        if (!prefs.edit().remove(KEY_GMS_COOKIE).remove(KEY_GMS_PROFILE).remove(KEY_GMS_COOKIE_AT).commit()) {
            throw AppError.SecurityRestriction("无法清除研究生登录，请检查设备存储。")
        }
    }

    val gmsCookieAt: Long
        get() = prefs.getLong(KEY_GMS_COOKIE_AT, 0L)

    /** 上次登录成功的时间，用于诊断页展示 */
    var lastLoginAt: Long
        get() = prefs.getLong(KEY_LAST_LOGIN, 0L)
        set(value) = prefs.edit().putLong(KEY_LAST_LOGIN, value).apply()

    /** Until imported caches are fully namespaced, this installation stays bound to one account. */
    var boundAccount: String?
        get() = prefs.getString("bound_account", null)
        set(value) = prefs.edit().putString("bound_account", value).apply()

    @Synchronized
    fun clearAll() {
        val binding = boundAccount
        val lastProfile = prefs.getInt(KEY_GMS_LAST_PROFILE, GmsProfileIds.LEGACY)
        // The allocation counter survives logout so an old database partition is never reused.
        if (!prefs.edit().clear().putString("bound_account", binding)
                .putInt(KEY_GMS_LAST_PROFILE, lastProfile).commit()) {
            throw AppError.SecurityRestriction("无法清除登录，请检查设备存储。")
        }
    }

    companion object {
        private const val FILE_NAME = "secure_prefs"
        private const val KEY_CAS_USER = "cas_user_token"
        private const val KEY_CAS_REFRESH = "cas_refresh_token"
        private const val KEY_ECARD_ACCESS = "ecard_access_token"
        private const val KEY_ECARD_REFRESH = "ecard_refresh_token"
        private const val KEY_ECARD_AT = "ecard_token_at"
        private const val KEY_GMS_COOKIE = "gms_cookie"
        private const val KEY_GMS_COOKIE_AT = "gms_cookie_at"
        private const val KEY_GMS_PROFILE = "gms_profile_semester_id"
        private const val KEY_GMS_LAST_PROFILE = "gms_last_profile_semester_id"
        private const val KEY_LAST_LOGIN = "last_login_at"
    }
}
