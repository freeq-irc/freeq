package com.freeq.model

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.util.Log
import androidx.compose.runtime.mutableStateOf
import kotlinx.coroutines.*

class NetworkMonitor(context: Context) {
    val isConnected = mutableStateOf(true)

    private val connectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private var appState: AppState? = null
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    private lateinit var tracker: DefaultNetworkTracker<Network>

    // A default-network callback hears only the network the device is
    // using, so a second network (a VPN, IMS, Wi-Fi beside mobile data)
    // coming and going does not flip the banner.
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            Log.i(TAG, "onAvailable $network")
            scope.launch {
                // Reconnect whenever we're disconnected, not only after a
                // seen onLost: a dozed process misses connectivity
                // callbacks entirely, so on wake there may be no recorded
                // loss — just a dead session and a network that works.
                val reconnect = tracker.onAvailable(network)
                isConnected.value = tracker.isConnected
                if (reconnect) attemptReconnect()
            }
        }

        override fun onLost(network: Network) {
            Log.i(TAG, "onLost $network")
            scope.launch {
                tracker.onLost(network)
                isConnected.value = tracker.isConnected
            }
        }
    }

    init {
        // Check initial state
        val active = connectivityManager.activeNetwork
        val caps = active?.let { connectivityManager.getNetworkCapabilities(it) }
        isConnected.value = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
        tracker = DefaultNetworkTracker(isConnected.value)

        connectivityManager.registerDefaultNetworkCallback(callback)
    }

    fun bind(appState: AppState) {
        this.appState = appState
    }

    private fun attemptReconnect() {
        val state = appState ?: return
        if (state.connectionState.value != ConnectionState.Disconnected) return
        if (state.intentionalDisconnect) return

        scope.launch {
            delay(1000)
            if (state.connectionState.value != ConnectionState.Disconnected) return@launch
            when (state.reconnectAction) {
                // Authenticated path — a plain connect() here would come
                // back as a guest. Fresh call resets the broker retry
                // budget the failed wake-up episode exhausted.
                ReconnectDecision.Action.ReconnectSavedSession -> state.reconnectSavedSession()
                ReconnectDecision.Action.ConnectAsGuest -> state.connect(state.nick.value)
                ReconnectDecision.Action.None -> {}
            }
        }
    }

    fun destroy() {
        connectivityManager.unregisterNetworkCallback(callback)
        scope.cancel()
    }

    private companion object {
        const val TAG = "freeq.net"
    }
}
