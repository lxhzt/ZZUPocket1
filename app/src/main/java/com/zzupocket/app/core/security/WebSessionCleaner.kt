package com.zzupocket.app.core.security

import android.os.Handler
import android.os.Looper
import android.webkit.CookieManager
import android.webkit.WebStorage
import android.webkit.WebView
import java.util.Collections
import java.util.WeakHashMap

/** WebView's cookie store is separate from the encrypted native token store. */
object WebSessionCleaner {
    private val views = Collections.newSetFromMap(WeakHashMap<WebView, Boolean>())

    fun register(view: WebView) { views.add(view) }
    fun unregister(view: WebView) { views.remove(view) }

    fun clear() {
        val action = Runnable {
            views.toList().forEach {
                it.stopLoading()
                it.clearHistory()
                it.clearCache(true)
                it.loadUrl("about:blank")
            }
            CookieManager.getInstance().removeAllCookies { CookieManager.getInstance().flush() }
            WebStorage.getInstance().deleteAllData()
        }
        if (Looper.myLooper() == Looper.getMainLooper()) action.run()
        else Handler(Looper.getMainLooper()).post(action)
    }
}
