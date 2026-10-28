package com.zzupocket.app.securitylab

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.zzupocket.app.ui.diag.GmsProbeDialog

/** Non-exported and absent from debug/release. The runner opens the dialog only after its network gates. */
class OfflineHarnessActivity : ComponentActivity() {
    private var loginVisible by mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Text("Offline Android security validation")
                if (loginVisible) {
                    GmsProbeDialog(onDismiss = ::hideLogin, onReport = { hideLogin() }, loginMode = true)
                }
            }
        }
    }

    fun showLogin() {
        check(checkSelfPermission(Manifest.permission.INTERNET) == PackageManager.PERMISSION_DENIED)
        loginVisible = true
    }

    fun hideLogin() { loginVisible = false }
}
