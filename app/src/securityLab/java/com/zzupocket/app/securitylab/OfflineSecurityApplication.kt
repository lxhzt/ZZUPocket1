package com.zzupocket.app.securitylab

import android.app.Application
import com.zzupocket.app.core.AppGraph

/** Lab-only startup: no business workers, restored timers, login or network activity. */
class OfflineSecurityApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        AppGraph.init(this)
    }
}
