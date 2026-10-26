package com.zzupocket.app.core.security

import android.net.Uri
import android.net.http.SslError
import android.webkit.CookieManager
import android.webkit.SslErrorHandler
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import java.io.ByteArrayInputStream
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

object SecureWebView {
    fun permits(url: String): Boolean = url.toHttpUrlOrNull()?.let {
        if (!SchoolNetworkPolicy.permits(it, SchoolNetworkPolicy.webHosts)) return@let false
        // This browser exists only to establish the GMS session, never another CAS service.
        if (it.host == "cas.s.zzu.edu.cn" && "service" in it.queryParameterNames) {
            val services = it.queryParameterValues("service")
            if (services.size != 1) return@let false
            val service = services.single()?.toHttpUrlOrNull() ?: return@let false
            if (!SchoolNetworkPolicy.permits(service, setOf("gmsstu.zzu.edu.cn")) ||
                service.encodedPath !in setOf("/stu", "/stu/", "/stu/cas") ||
                service.query != null || service.fragment != null) return@let false
        }
        true
    } == true

    fun configure(view: WebView) {
        WebSessionCleaner.register(view)
        WebView.setWebContentsDebuggingEnabled(false)
        view.settings.apply {
            allowFileAccess = false
            allowContentAccess = false
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            safeBrowsingEnabled = true
            cacheMode = WebSettings.LOAD_NO_CACHE
            setGeolocationEnabled(false)
            javaScriptCanOpenWindowsAutomatically = false
            setSupportMultipleWindows(false)
            @Suppress("DEPRECATION")
            setSaveFormData(false)
        }
        CookieManager.getInstance().setAcceptThirdPartyCookies(view, false)
    }
}

/** Default TLS checks are kept; untrusted pages/resources are never opened externally. */
open class SecureSchoolWebViewClient : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest): Boolean =
        !SecureWebView.permits(request.url.toString())

    @Suppress("DEPRECATION")
    override fun shouldOverrideUrlLoading(view: WebView?, url: String): Boolean =
        !SecureWebView.permits(url)

    override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest): WebResourceResponse? {
        if (SecureWebView.permits(request.url.toString())) return null
        return WebResourceResponse("text/plain", "UTF-8", 403, "Blocked", emptyMap(),
            ByteArrayInputStream(ByteArray(0)))
    }

    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler, error: SslError?) {
        handler.cancel()
    }
}
