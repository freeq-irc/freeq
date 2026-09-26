package com.freeq.ui

import androidx.compose.runtime.*
import com.freeq.model.AppState
import com.freeq.model.ConnectionState
import com.freeq.model.RootScreen
import com.freeq.ui.components.MotdDialog
import com.freeq.ui.navigation.MainScreen
import com.freeq.ui.screens.ConnectScreen
import com.freeq.ui.theme.FreeqTheme

@Composable
fun FreeqApp(appState: AppState) {
    val isDark by appState.isDarkTheme
    val connectionState by appState.connectionState
    val loggedOut by appState.loggedOut

    // Auto-reconnect saved session on app start
    LaunchedEffect(Unit) {
        if (connectionState == ConnectionState.Disconnected && appState.hasSavedSession) {
            appState.reconnectSavedSession()
        }
    }

    FreeqTheme(darkTheme = isDark) {
        // A saved session keeps the main screen through a drop, so the chat
        // on screen and the line being read stay put; the status bar at its
        // top says what the connection is doing.
        when (RootScreen.decide(connectionState, appState.hasSavedSession, loggedOut)) {
            RootScreen.Screen.Main -> MainScreen(appState)
            RootScreen.Screen.Connect -> ConnectScreen(appState)
        }

        MotdDialog(appState)
    }
}
