package com.zzupocket.app.securitylab

import android.Manifest
import android.app.Activity
import android.app.Instrumentation
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inspector.WindowInspector
import android.webkit.CookieManager
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import com.zzupocket.app.BuildConfig
import com.zzupocket.app.core.security.SecureWebView
import com.zzupocket.app.core.security.WebSessionCleaner
import com.zzupocket.app.data.auth.TokenStore
import com.zzupocket.app.data.gms.GmsCookie
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Platform instrumentation only. No school accounts, test framework downloads or network permission. */
class OfflineSecurityInstrumentation : Instrumentation() {
    private var arguments = Bundle()
    private val checks = mutableListOf<LabCheckResult>()
    private var dialogWindowIdentity: WindowDumpIdentity? = null

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        this.arguments = arguments ?: Bundle()
        start()
    }

    override fun onStart() {
        val phase = arguments.getString("phase", "verify") ?: "verify"
        try {
            // Do not create the dialog, mutate credentials or run database checks before all gates pass.
            networkGates()
            check(phase == "setup" || phase == "verify") { "Use phase=setup or phase=verify" }
            if (phase == "setup") setupCredentials() else verifyRuntime()
        } catch (error: Throwable) {
            record(LabCheckResult("phase_aborted", false, describe(error)))
        }
        val success = checks.isNotEmpty() && checks.all { it.passed }
        val report = report(phase, success)
        val reportName = if (phase == "setup") "offline-security-setup.json" else "offline-security-verify.json"
        val result = Bundle().apply {
            putBoolean("lab_passed", success)
            putInt("lab_check_count", checks.size)
            putString("lab_report", report.toString())
            putString("stream", "Offline security lab: ${checks.count { it.passed }}/${checks.size} checks passed\n")
        }
        try {
            writePrivate(reportName, report.toString(2))
            result.putString("lab_report_path", File(targetContext.filesDir, reportName).absolutePath)
        } catch (error: Throwable) {
            result.putString("lab_report_write_error", describe(error))
        }
        finish(if (success) Activity.RESULT_OK else Activity.RESULT_CANCELED, result)
    }

    private fun networkGates() {
        requireCheck("lab_target_package") {
            check(targetContext.packageName == TARGET_PACKAGE && BuildConfig.APPLICATION_ID == TARGET_PACKAGE)
            check(BuildConfig.BUILD_TYPE == "securityLab")
        }
        requireCheck("target_internet_permission_denied") { requireNoInternet(targetContext.packageName) }
        requireCheck("test_internet_permission_denied") {
            check(context.packageName == TEST_PACKAGE)
            requireNoInternet(context.packageName)
        }
        requireCheck("lab_only_application") {
            check(targetContext.applicationContext is OfflineSecurityApplication)
        }
        requireCheck("emulator_hardware") {
            check(Build.HARDWARE == "ranchu" || Build.HARDWARE == "goldfish") {
                "This runner is restricted to the isolated Android emulator"
            }
        }
        requireCheck("webview_network_loads_blocked_before_dialog") {
            onMain {
                val probe = WebView(targetContext)
                try { check(probe.settings.blockNetworkLoads) { "WebView network loads are enabled" } }
                finally { probe.destroy() }
            }
        }
    }

    private fun requireNoInternet(packageName: String) {
        val manager = targetContext.packageManager
        check(manager.checkPermission(Manifest.permission.INTERNET, packageName) == PackageManager.PERMISSION_DENIED)
        @Suppress("DEPRECATION")
        val requested = manager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS).requestedPermissions.orEmpty()
        check(Manifest.permission.INTERNET !in requested) { "INTERNET remains in the installed manifest" }
    }

    private fun setupCredentials() {
        val runId = arguments.getString("runId", "offline-lab") ?: "offline-lab"
        check(runId.matches(Regex("[A-Za-z0-9_-]{1,64}"))) { "Invalid runId" }
        val store = TokenStore(targetContext)
        val loginAt = System.currentTimeMillis()
        // This package is a separate lab sandbox and contains synthetic data only.
        store.clearAll()
        val first = store.adoptGmsSession("$SYNTHETIC_COOKIE; TGC=synthetic-sso; SESSION=synthetic-session", loginAt)
        requireCheck("tokenstore_filters_sso_material") { check(first.cookie == SYNTHETIC_COOKIE) }
        requireCheck("tokenstore_new_instance_restores_group") {
            val restored = TokenStore(targetContext).restoreGmsSession() ?: error("Missing saved session")
            check(restored.cookie == first.cookie && restored.semesterId == first.semesterId && restored.loginAt == loginAt)
        }
        val second = store.adoptGmsSession(SYNTHETIC_COOKIE, loginAt)
        requireCheck("tokenstore_identical_cookie_new_partition") { check(second.semesterId < first.semesterId) }
        requireCheck("tokenstore_rejects_sso_only_without_replacing_session") {
            check(runCatching { store.adoptGmsSession("TGC=synthetic-only", loginAt) }.isFailure)
            check(store.restoreGmsSession()?.semesterId == second.semesterId)
        }
        requireCheck("encrypted_preferences_no_plaintext_cookie") { requireEncryptedCookieFile() }
        writePrivate(MARKER, JSONObject().apply {
            put("run_id", runId)
            put("setup_pid", Process.myPid())
            put("semester_id", second.semesterId)
            put("login_at", loginAt)
            put("cookie_sha256", sha256(SYNTHETIC_COOKIE.toByteArray(Charsets.UTF_8)))
        }.toString())
        record(LabCheckResult("cold_restore_marker_committed", true, "Force-stop the lab package before phase=verify"))
    }

    private fun verifyRuntime() {
        verifyColdCredentials()
        verifyCookieAndStorageCleanup()
        verifyRealDialog()
        RoomPartitionChecks.run(targetContext).forEach(::record)
    }

    private fun verifyColdCredentials() {
        val marker = JSONObject(File(targetContext.filesDir, MARKER).readText(Charsets.UTF_8))
        requireCheck("cold_process_marker_matches") {
            check(marker.getString("run_id") == arguments.getString("runId", "offline-lab"))
            check(marker.getInt("setup_pid") != Process.myPid()) { "Run verify only after force-stopping the setup process" }
        }
        val store = TokenStore(targetContext)
        val restored = store.restoreGmsSession() ?: error("Cold restore lost the saved session")
        requireCheck("tokenstore_cold_process_restore") {
            check(restored.semesterId == marker.getInt("semester_id"))
            check(restored.loginAt == marker.getLong("login_at"))
            check(sha256(restored.cookie.toByteArray(Charsets.UTF_8)) == marker.getString("cookie_sha256"))
        }
        requireCheck("encrypted_preferences_cold_no_plaintext") { requireEncryptedCookieFile() }
        store.clearAll()
        requireCheck("tokenstore_logout_revokes_active_pointer") { check(store.restoreGmsSession() == null) }
        val next = store.adoptGmsSession(SYNTHETIC_COOKIE, System.currentTimeMillis())
        requireCheck("tokenstore_counter_survives_logout") { check(next.semesterId < restored.semesterId) }
        store.clearGmsSession()
    }

    private fun requireEncryptedCookieFile() {
        val xml = File(targetContext.applicationInfo.dataDir, "shared_prefs/secure_prefs.xml").readText(Charsets.UTF_8)
        check(SYNTHETIC_GUID !in xml && GmsCookie.SESSION_COOKIE !in xml && "synthetic-sso" !in xml)
        check("__androidx_security_crypto_encrypted_prefs_value_keyset__" in xml)
    }

    private fun verifyCookieAndStorageCleanup() {
        val web = onMain {
            WebView(targetContext).apply {
                check(settings.blockNetworkLoads)
                settings.javaScriptEnabled = true
                settings.domStorageEnabled = true
                SecureWebView.configure(this)
            }
        }
        try {
            loadInline(web)
            requireCheck("webview_local_storage_seeded_offline") {
                check(evaluate(web, "localStorage.setItem('offline_security_lab','synthetic');localStorage.getItem('offline_security_lab')") == "\"synthetic\"")
            }
            setCookie(OFFLINE_ORIGIN, "offline_security_lab=synthetic-cookie; Path=/; Secure; HttpOnly")
            // CookieManager writes are local operations; neither URL is loaded or requested.
            setCookie(GMS_ORIGIN, "$SYNTHETIC_COOKIE; Path=/stu; Secure; HttpOnly")
            setCookie("https://cas.s.zzu.edu.cn/cas/", "TGC=synthetic-sso; Domain=.zzu.edu.cn; Path=/; Secure; HttpOnly")
            requireCheck("webview_cookie_path_and_sso_filtering") {
                val academic = onMain { CookieManager.getInstance().getCookie(GMS_ORIGIN) }
                val root = onMain { CookieManager.getInstance().getCookie("https://gmsstu.zzu.edu.cn/") }.orEmpty()
                check(academic.orEmpty().contains(SYNTHETIC_COOKIE))
                check(!root.contains(GmsCookie.SESSION_COOKIE))
                check(GmsCookie.join(GmsCookie.academicSessionOnly(GmsCookie.parse(academic))) == SYNTHETIC_COOKIE)
            }
            // Exercise the production cleaner from a non-main thread, including its posted work.
            WebSessionCleaner.clear()
            requireCheck("webview_cookie_cleaner_completes") {
                eventually(5_000) {
                    onMain {
                        val cookies = CookieManager.getInstance()
                        cookies.getCookie(OFFLINE_ORIGIN).isNullOrEmpty() && cookies.getCookie(GMS_ORIGIN).isNullOrEmpty() &&
                            cookies.getCookie("https://cas.s.zzu.edu.cn/cas/").isNullOrEmpty()
                    }
                }
            }
            loadInline(web)
            requireCheck("webview_dom_storage_removed") {
                eventually(5_000) { evaluate(web, "localStorage.getItem('offline_security_lab')") == "null" }
            }
        } finally {
            onMain { WebSessionCleaner.unregister(web); web.stopLoading(); web.destroy() }
        }
    }

    private fun verifyRealDialog() {
        val activity = startActivitySync(Intent(targetContext, OfflineHarnessActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            as OfflineHarnessActivity
        try {
            onMain { activity.showLogin() }
            var browser: DialogBrowser? = null
            eventually(10_000) { onMain { findDialogBrowser().also { browser = it } != null } }
            val found = browser ?: error("No real GMS login WebView")
            requireCheck("dialog_network_still_blocked") { onMain { check(found.web.settings.blockNetworkLoads) } }
            checkCase("dialog_secure_window_is_independent") {
                onMain {
                    check(found.root !== activity.window.decorView)
                    val attributes = found.root.layoutParams as WindowManager.LayoutParams
                    check(attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
                }
            }
            checkCase("dialog_webview_security_settings") {
                onMain {
                    with(found.web.settings) {
                        check(!allowFileAccess && !allowContentAccess)
                        check(mixedContentMode == WebSettings.MIXED_CONTENT_NEVER_ALLOW)
                        check(cacheMode == WebSettings.LOAD_NO_CACHE && safeBrowsingEnabled)
                        check(!javaScriptCanOpenWindowsAutomatically && !supportMultipleWindows() && !saveFormData)
                    }
                    check(!CookieManager.getInstance().acceptThirdPartyCookies(found.web))
                }
            }
            checkCase("dialog_rejects_full_and_partial_obscured_touch") {
                onMain {
                    for (flags in listOf(MotionEvent.FLAG_WINDOW_IS_OBSCURED, MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED)) {
                        val event = touch(flags)
                        try { check(!found.web.onFilterTouchEventForSecurity(event)) } finally { event.recycle() }
                    }
                    val normal = touch(0)
                    try { check(found.web.onFilterTouchEventForSecurity(normal)) } finally { normal.recycle() }
                }
            }
            checkCase("dialog_overlay_window_flag_dump") {
                val identity = onMain {
                    val attributes = found.root.layoutParams as WindowManager.LayoutParams
                    check(attributes.type == WindowManager.LayoutParams.TYPE_APPLICATION)
                    check(attributes.packageName == TARGET_PACKAGE)
                    // A unique title identifies this existing dialog. Do not set any security flags here.
                    val title = "ZZUPocketOfflineDialog-" + Process.myPid() + "-" + SystemClock.elapsedRealtime()
                    attributes.setTitle(title)
                    val manager = requireNotNull(found.root.context.getSystemService(WindowManager::class.java))
                    manager.updateViewLayout(found.root, attributes)
                    val actual = found.root.layoutParams as WindowManager.LayoutParams
                    WindowDumpIdentity(actual.title.toString(), actual.type, actual.packageName, targetContext.applicationInfo.uid)
                }
                dialogWindowIdentity = identity
                val dump = readShell("dumpsys window windows")
                writePrivate("offline-security-window-dump.txt", dump)
                check(WindowDumpEvidence.confirmsHiddenOverlays(dump, identity)) {
                    "The actual dialog title/type/owner and private overlay flag were not verified in its own attributes"
                }
            }
        } finally {
            onMain { activity.hideLogin(); activity.finish() }
            waitForIdleSync()
        }
    }

    private data class DialogBrowser(val web: WebView, val root: View)

    private fun findDialogBrowser(): DialogBrowser? {
        for (root in WindowInspector.getGlobalWindowViews()) {
            findWebView(root)?.let { return DialogBrowser(it, root) }
        }
        return null
    }

    private fun findWebView(view: View): WebView? {
        if (view is WebView) return view
        if (view is ViewGroup) for (index in 0 until view.childCount) findWebView(view.getChildAt(index))?.let { return it }
        return null
    }

    private fun touch(flags: Int): MotionEvent {
        val now = SystemClock.uptimeMillis()
        val properties = arrayOf(MotionEvent.PointerProperties().apply { id = 0; toolType = MotionEvent.TOOL_TYPE_FINGER })
        val coordinates = arrayOf(MotionEvent.PointerCoords().apply { x = 10f; y = 10f; pressure = 1f; size = 1f })
        return MotionEvent.obtain(now, now, MotionEvent.ACTION_DOWN, 1, properties, coordinates, 0, 0, 1f, 1f,
            0, 0, InputDevice.SOURCE_TOUCHSCREEN, flags)
    }

    private fun loadInline(web: WebView) {
        val loaded = CountDownLatch(1)
        onMain {
            check(web.settings.blockNetworkLoads)
            web.webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView?, url: String?) { if (url != "about:blank") loaded.countDown() }
            }
            web.loadDataWithBaseURL(OFFLINE_ORIGIN, "<!doctype html><html><body>Offline synthetic data only</body></html>",
                "text/html", "UTF-8", null)
        }
        check(loaded.await(5, TimeUnit.SECONDS)) { "Inline page did not complete" }
    }

    private fun evaluate(web: WebView, script: String): String? {
        val done = CountDownLatch(1)
        val value = AtomicReference<String?>()
        onMain { web.evaluateJavascript(script) { value.set(it); done.countDown() } }
        check(done.await(5, TimeUnit.SECONDS)) { "Local JavaScript callback timed out" }
        return value.get()
    }

    private fun setCookie(url: String, value: String) {
        val done = CountDownLatch(1)
        val accepted = AtomicReference(false)
        onMain { CookieManager.getInstance().setCookie(url, value) { accepted.set(it); done.countDown() } }
        check(done.await(5, TimeUnit.SECONDS) && accepted.get()) { "Synthetic local cookie was rejected" }
    }

    private fun eventually(timeoutMs: Long, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        do {
            if (condition()) return
            Thread.sleep(25)
        } while (SystemClock.elapsedRealtime() < deadline)
        error("Local Android state did not settle within ${timeoutMs}ms")
    }

    private fun <T> onMain(block: () -> T): T {
        val value = AtomicReference<T>()
        val failure = AtomicReference<Throwable?>()
        runOnMainSync { try { value.set(block()) } catch (error: Throwable) { failure.set(error) } }
        failure.get()?.let { throw it }
        return value.get()
    }

    private fun checkCase(name: String, block: () -> Unit): Boolean = try {
        block()
        record(LabCheckResult(name, true))
        true
    } catch (error: Throwable) {
        record(LabCheckResult(name, false, describe(error)))
        false
    }

    private fun requireCheck(name: String, block: () -> Unit) {
        check(checkCase(name, block)) { "Required check failed: $name" }
    }

    private fun record(result: LabCheckResult) {
        checks += result
        sendStatus(if (result.passed) 0 else -2, Bundle().apply {
            putString("lab_case", result.name); putBoolean("passed", result.passed); putString("detail", result.detail)
        })
    }

    private fun writePrivate(name: String, contents: String) {
        targetContext.openFileOutput(name, 0).use { stream ->
            stream.write(contents.toByteArray(Charsets.UTF_8)); stream.fd.sync()
        }
    }

    private fun readShell(command: String): String = ParcelFileDescriptor.AutoCloseInputStream(uiAutomation.executeShellCommand(command)).use { input ->
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val size = input.read(buffer)
            if (size < 0) break
            check(out.size() + size <= 2 * 1024 * 1024) { "Window dump exceeded the local evidence limit" }
            out.write(buffer, 0, size)
        }
        out.toString("UTF-8")
    }

    private fun report(phase: String, success: Boolean): JSONObject = JSONObject().apply {
        put("format_version", 1); put("phase", phase); put("passed", success); put("pid", Process.myPid())
        put("target_package", targetContext.packageName); put("test_package", context.packageName)
        put("sdk_int", Build.VERSION.SDK_INT); put("hardware", Build.HARDWARE); put("fingerprint", Build.FINGERPRINT)
        put("webview_package", WebView.getCurrentWebViewPackage()?.packageName)
        put("webview_version", WebView.getCurrentWebViewPackage()?.versionName)
        dialogWindowIdentity?.let { identity ->
            put("dialog_window_identity", JSONObject().apply {
                put("title", identity.title); put("type", identity.type)
                put("owner_package", identity.ownerPackage); put("owner_uid", identity.ownerUid)
            })
        }
        put("checks", JSONArray().apply { checks.forEach { put(JSONObject().apply {
            put("name", it.name); put("passed", it.passed); put("detail", it.detail)
        }) } })
        put("limits", JSONArray(listOf("emulator_only_not_hardware_keystore_attestation", "no_school_login_or_server_authorization_test",
            "cold_process_restore_not_power_loss_atomicity", "synthetic_touch_flags_not_real_overlay_app_attack",
            "cookie_and_dom_cleanup_not_historical_file_secure_erasure")))
    }

    private fun describe(error: Throwable): String = "${error.javaClass.simpleName}: ${error.message.orEmpty().take(300)}"
    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    companion object {
        private const val TARGET_PACKAGE = "com.zzupocket.app.secure.securitylab"
        private const val TEST_PACKAGE = "$TARGET_PACKAGE.test"
        private const val MARKER = "offline-security-marker.json"
        private const val SYNTHETIC_GUID = "01234567-89ab-cdef-0123-456789abcdef"
        private const val SYNTHETIC_COOKIE = "cn_com_southsoft_gmis_stu=$SYNTHETIC_GUID"
        private const val OFFLINE_ORIGIN = "https://offline.invalid/lab/"
        private const val GMS_ORIGIN = "https://gmsstu.zzu.edu.cn/stu/"
    }
}
