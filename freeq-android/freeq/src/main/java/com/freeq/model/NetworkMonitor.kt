package com.freeq.model

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import androidx.compose.runtime.mutableStateOf
import kotlinx.coroutines.*

class NetworkMonitor(context: Context) {
    val isConnected = mutableStateOf(true)

    private val connectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private var appState: AppState? = null
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            scope.launch {
                isConnected.value = true
                // Reconnect whenever we're disconnected, not only after a
                // seen onLost: a dozed process misses connectivity
                // callbacks entirely, so on wake there may be no recorded
                // loss — just a dead session and a network that works.
                attemptReconnect()
            }
        }

        override fun onLost(network: Network) {
            scope.launch {
                isConnected.value = false
            }
        }
    }

    init {
        // Check initial state
        val active = connectivityManager.activeNetwork
        val caps = active?.let { connectivityManager.getNetworkCapabilities(it) }
        isConnected.value = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        connectivityManager.registerNetworkCallback(request, callback)
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
            if (state.hasSavedSession) {
                // Authenticated path — a plain connect() here would come
                // back as a guest. Fresh call resets the broker retry
                // budget the failed wake-up episode exhausted.
                state.reconnectSavedSession()
            } else if (state.nick.value.isNotEmpty()) {
                state.connect(state.nick.value)
            }
        }
    }

    fun destroy() {
        connectivityManager.unregisterNetworkCallback(callback)
        scope.cancel()
    }
}
