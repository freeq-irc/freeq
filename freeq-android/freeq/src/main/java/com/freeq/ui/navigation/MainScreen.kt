package com.freeq.ui.navigation

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBars
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Chat
import androidx.compose.material.icons.filled.Explore
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.freeq.model.AppState
import com.freeq.ui.components.ConnectionStatusBar
import com.freeq.ui.components.rememberConnectionStatusBar
import com.freeq.ui.screens.ChatsTab
import com.freeq.ui.screens.ChatDetailScreen
import com.freeq.ui.screens.DiscoverTab
import com.freeq.ui.screens.SettingsTab

private enum class Tab(val route: String, val label: String) {
    Chats("chats", "Chats"),
    Discover("discover", "Discover"),
    Settings("settings", "Settings")
}

/**
 * The main screen, kept through a dropped connection: the status bar at the
 * top says what the connection is doing, and the tabs and any open chat stay
 * where they were underneath it.
 */
@Composable
fun MainScreen(appState: AppState) {
    val statusBar = rememberConnectionStatusBar(appState)
    Column {
        if (statusBar != null) {
            ConnectionStatusBar(statusBar, onSignInAgain = { appState.logout() })
        }
        MainContent(
            appState,
            modifier = Modifier
                .weight(1f)
                // The bar takes the status-bar inset while it shows, so the
                // screens under it do not pad for it again.
                .then(if (statusBar != null) Modifier.consumeWindowInsets(WindowInsets.statusBars) else Modifier)
        )
    }
}

@Composable
private fun MainContent(appState: AppState, modifier: Modifier) {
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    // Hide bottom bar when in chat detail
    val showBottomBar = currentRoute in listOf(Tab.Chats.route, Tab.Discover.route, Tab.Settings.route)

    val totalUnread = appState.unreadCounts.values.sum()

    // Snackbar for server errors/notices
    val snackbarHostState = remember { SnackbarHostState() }
    val errorMessage by appState.errorMessage
    LaunchedEffect(errorMessage) {
        errorMessage?.let {
            snackbarHostState.showSnackbar(it, duration = SnackbarDuration.Short)
            appState.errorMessage.value = null
        }
    }

    // Handle pending navigation from notification tap
    val pendingNav = appState.pendingNavigation.value
    LaunchedEffect(pendingNav) {
        if (pendingNav != null) {
            appState.pendingNavigation.value = null
            appState.activeChannel.value = pendingNav
            navController.navigate("chat/$pendingNav") {
                launchSingleTop = true
            }
        }
    }

    Scaffold(
        modifier = modifier,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        bottomBar = {
            if (showBottomBar) {
                NavigationBar(
                    containerColor = MaterialTheme.colorScheme.surface,
                    contentColor = MaterialTheme.colorScheme.onSurface,
                ) {
                    NavigationBarItem(
                        icon = {
                            BadgedBox(badge = {
                                if (totalUnread > 0) {
                                    Badge { Text("$totalUnread") }
                                }
                            }) {
                                Icon(Icons.AutoMirrored.Filled.Chat, contentDescription = "Chats")
                            }
                        },
                        label = { Text(Tab.Chats.label) },
                        selected = currentRoute == Tab.Chats.route,
                        onClick = {
                            navController.navigate(Tab.Chats.route) {
                                popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = MaterialTheme.colorScheme.primary,
                            selectedTextColor = MaterialTheme.colorScheme.primary,
                            indicatorColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.12f),
                        )
                    )

                    NavigationBarItem(
                        icon = { Icon(Icons.Default.Explore, contentDescription = "Discover") },
                        label = { Text(Tab.Discover.label) },
                        selected = currentRoute == Tab.Discover.route,
                        onClick = {
                            navController.navigate(Tab.Discover.route) {
                                popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = MaterialTheme.colorScheme.primary,
                            selectedTextColor = MaterialTheme.colorScheme.primary,
                            indicatorColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.12f),
                        )
                    )

                    NavigationBarItem(
                        icon = {
                            // A dot while this device's key is not published to
                            // the account — the one place Settings can be
                            // opened from, so it is where the state is shown.
                            BadgedBox(badge = {
                                if (appState.signingKeyUnpublished.value) Badge()
                            }) {
                                Icon(Icons.Default.Settings, contentDescription = "Settings")
                            }
                        },
                        label = { Text(Tab.Settings.label) },
                        selected = currentRoute == Tab.Settings.route,
                        onClick = {
                            navController.navigate(Tab.Settings.route) {
                                popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = MaterialTheme.colorScheme.primary,
                            selectedTextColor = MaterialTheme.colorScheme.primary,
                            indicatorColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.12f),
                        )
                    )
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = Tab.Chats.route,
            modifier = Modifier.padding(innerPadding)
        ) {
            composable(Tab.Chats.route) {
                ChatsTab(
                    appState = appState,
                    onChannelClick = { channelName ->
                        appState.activeChannel.value = channelName
                        navController.navigate("chat/$channelName")
                    }
                )
            }
            composable(Tab.Discover.route) {
                DiscoverTab(appState = appState)
            }
            composable(Tab.Settings.route) {
                SettingsTab(appState = appState)
            }
            composable("chat/{channelName}") { backStackEntry ->
                val channelName = backStackEntry.arguments?.getString("channelName") ?: return@composable
                ChatDetailScreen(
                    appState = appState,
                    channelName = channelName,
                    onBack = { navController.popBackStack() },
                    onNavigateToChat = { nick ->
                        // Open DMs under their canonical key (peer DID when
                        // known) so the thread the echo lands in is the one
                        // on screen.
                        val key = if (nick.startsWith("#")) nick
                            else appState.didForNick(nick) ?: nick
                        navController.navigate("chat/$key")
                    }
                )
            }
        }
    }
}
