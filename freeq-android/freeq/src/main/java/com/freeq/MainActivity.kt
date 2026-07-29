package com.freeq

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import com.freeq.model.AppState
import com.freeq.model.ServerConfig
import com.freeq.ui.FreeqApp

class MainActivity : ComponentActivity() {
    private var appState: AppState? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        requestNotificationPermission()

        setContent {
            val state: AppState = viewModel()
            appState = state

            // Handle initial deep link
            intent?.data?.let { handleDeepLink(it, state) }

            FreeqApp(appState = state)
        }
    }

    override fun onStop() {
        super.onStop()
        // Backgrounding is the last reliable moment before Android may kill
        // the process; snapshot the conversations so the next launch has them.
        appState?.flushBuffersToCache()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        intent.data?.let { uri ->
            appState?.let { state ->
                handleDeepLink(uri, state)
            }
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
            }
        }
    }

    private fun handleDeepLink(uri: Uri, state: AppState) {
        if (uri.scheme != "freeq") return

        when (uri.host) {
            "chat" -> {
                // freeq://chat/{channelName} — navigate to channel/DM
                val channel = uri.pathSegments.firstOrNull() ?: return
                state.pendingNavigation.value = channel
            }
            else -> {
                // OAuth callback: freeq://auth?token=...&broker_token=...&nick=...&did=...
                val token = uri.getQueryParameter("token") ?: return
                val brokerTok = uri.getQueryParameter("broker_token")
                val nick = uri.getQueryParameter("nick") ?: return
                val did = uri.getQueryParameter("did")

                state.pendingWebToken = token
                brokerTok?.let { state.brokerToken = it }
                did?.let { state.authenticatedDID.value = it }
                // Persist secrets for session restore
                brokerTok?.let {
                    state.securePrefs.edit().putString("brokerToken", it).apply()
                    // Track login time for 14-day minimum session duration
                    state.prefs.edit().putLong("lastLoginTime", System.currentTimeMillis()).apply()
                }
                did?.let {
                    state.securePrefs.edit().putString("did", it).apply()
                }
                state.serverAddress.value = ServerConfig.ircServer
                state.connect(nick)
            }
        }
    }
}
