package com.freeq.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Logout
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.freeq.model.AppState
import com.freeq.model.ConnectionState
import com.freeq.ui.components.UserAvatar
import com.freeq.ui.theme.FreeqColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsTab(appState: AppState) {
    val nick by appState.nick
    val authenticatedDID by appState.authenticatedDID
    val serverAddress by appState.serverAddress
    val connectionState by appState.connectionState
    val isDarkTheme by appState.isDarkTheme
    val customStatus by appState.customStatus
    var showDisconnectDialog by remember { mutableStateOf(false) }
    var showStatusDialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // ── Account section ──
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        "ACCOUNT",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                        letterSpacing = 1.sp
                    )

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(14.dp)
                    ) {
                        UserAvatar(nick = nick, size = 56.dp)

                        Column {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Text(
                                    nick,
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = MaterialTheme.colorScheme.onBackground
                                )
                                if (authenticatedDID != null) {
                                    Icon(
                                        Icons.Default.Verified,
                                        contentDescription = "AT Protocol identity",
                                        tint = FreeqColors.accent,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }
                            }

                            if (authenticatedDID != null) {
                                Text(
                                    authenticatedDID!!,
                                    fontSize = 12.sp,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1
                                )
                            } else {
                                Text(
                                    "Guest",
                                    fontSize = 12.sp,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }

                    HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f))

                    // Custom status — shipped as the IRC AWAY message
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { showStatusDialog = true },
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Icon(
                            Icons.Default.EmojiEmotions,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                "Status",
                                fontSize = 15.sp,
                                color = MaterialTheme.colorScheme.onBackground
                            )
                            Text(
                                if (customStatus.isEmpty()) "Set a status" else customStatus,
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Icon(
                            Icons.Default.ChevronRight,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            // ── Appearance section ──
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        "APPEARANCE",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                        letterSpacing = 1.sp
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Icon(
                                if (isDarkTheme) Icons.Default.DarkMode else Icons.Default.LightMode,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                "Dark theme",
                                fontSize = 15.sp,
                                color = MaterialTheme.colorScheme.onBackground
                            )
                        }

                        Switch(
                            checked = isDarkTheme,
                            onCheckedChange = { appState.toggleTheme() },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = FreeqColors.accent,
                                checkedTrackColor = FreeqColors.accent.copy(alpha = 0.3f)
                            )
                        )
                    }
                }
            }

            // ── Connection section ──
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        "CONNECTION",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                        letterSpacing = 1.sp
                    )

                    // Server
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            "Server",
                            fontSize = 14.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            serverAddress,
                            fontSize = 14.sp,
                            color = MaterialTheme.colorScheme.onBackground
                        )
                    }

                    // Status
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            "Status",
                            fontSize = 14.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            val statusColor = when (connectionState) {
                                ConnectionState.Registered -> FreeqColors.success
                                ConnectionState.Connected,
                                ConnectionState.Connecting -> FreeqColors.warning
                                ConnectionState.Disconnected -> FreeqColors.danger
                            }
                            val statusText = when (connectionState) {
                                ConnectionState.Registered -> "Connected"
                                ConnectionState.Connected -> "Connected"
                                ConnectionState.Connecting -> "Connecting"
                                ConnectionState.Disconnected -> "Disconnected"
                            }
                            Box(
                                modifier = Modifier
                                    .size(8.dp)
                                    .clip(CircleShape)
                                    .background(statusColor)
                            )
                            Text(
                                statusText,
                                fontSize = 14.sp,
                                color = MaterialTheme.colorScheme.onBackground
                            )
                        }
                    }

                    // Channels count
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            "Channels",
                            fontSize = 14.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            "${appState.channels.size}",
                            fontSize = 14.sp,
                            color = MaterialTheme.colorScheme.onBackground
                        )
                    }
                }
            }

            // ── Safety section ──
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        "SAFETY",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                        letterSpacing = 1.sp
                    )

                    Text(
                        "Blocked users",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Medium,
                        color = MaterialTheme.colorScheme.onBackground
                    )

                    if (appState.blockedNicks.isEmpty() && appState.blockedDids.isEmpty()) {
                        Text(
                            "No blocked users",
                            fontSize = 13.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    } else {
                        appState.blockedNicks.forEach { blockedNick ->
                            BlockedUserRow(
                                label = blockedNick,
                                onUnblock = { appState.unblockUser(nick = blockedNick) }
                            )
                        }
                        appState.blockedDids.forEach { blockedDid ->
                            BlockedUserRow(
                                label = blockedDid,
                                onUnblock = { appState.unblockUser(did = blockedDid) }
                            )
                        }
                    }

                    HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f))

                    Text(
                        "freeq has zero tolerance for objectionable content or " +
                            "abusive behavior. Blocking hides a user's messages and " +
                            "conversations on this device; reporting a message or " +
                            "profile also blocks the user. To report serious abuse, " +
                            "contact abuse@freeq.at.",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // ── About section ──
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        "ABOUT",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                        letterSpacing = 1.sp
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            "Version",
                            fontSize = 14.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            "0.1",
                            fontSize = 14.sp,
                            color = MaterialTheme.colorScheme.onBackground
                        )
                    }

                    val uriHandler = LocalUriHandler.current

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { uriHandler.openUri("https://freeq.at") },
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Icon(
                            Icons.Default.Language,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            "Website",
                            fontSize = 14.sp,
                            color = MaterialTheme.colorScheme.onBackground,
                            modifier = Modifier.weight(1f)
                        )
                        Icon(
                            Icons.AutoMirrored.Filled.OpenInNew,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { uriHandler.openUri("https://github.com/freeq-irc/freeq") },
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Icon(
                            Icons.Default.Code,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            "Source Code",
                            fontSize = 14.sp,
                            color = MaterialTheme.colorScheme.onBackground,
                            modifier = Modifier.weight(1f)
                        )
                        Icon(
                            Icons.AutoMirrored.Filled.OpenInNew,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            // ── Disconnect button ──
            Button(
                onClick = { showDisconnectDialog = true },
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = FreeqColors.danger
                ),
                contentPadding = PaddingValues(vertical = 14.dp)
            ) {
                Icon(
                    Icons.AutoMirrored.Filled.Logout,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    "Disconnect",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
    }

    // Status editor
    if (showStatusDialog) {
        StatusEditorDialog(
            currentStatus = customStatus,
            onSave = { status ->
                appState.setCustomStatus(status)
                showStatusDialog = false
            },
            onDismiss = { showStatusDialog = false }
        )
    }

    // Disconnect confirmation
    if (showDisconnectDialog) {
        AlertDialog(
            onDismissRequest = { showDisconnectDialog = false },
            title = { Text("Disconnect?") },
            text = { Text("You will be disconnected from the server.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        appState.logout()
                        showDisconnectDialog = false
                    }
                ) {
                    Text("Disconnect", color = FreeqColors.danger)
                }
            },
            dismissButton = {
                TextButton(onClick = { showDisconnectDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@Composable
private fun BlockedUserRow(label: String, onUnblock: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            label,
            fontSize = 14.sp,
            color = MaterialTheme.colorScheme.onBackground,
            maxLines = 1,
            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f)
        )
        TextButton(onClick = onUnblock) {
            Text("Unblock", color = MaterialTheme.colorScheme.primary)
        }
    }
}

@Composable
private fun StatusEditorDialog(
    currentStatus: String,
    onSave: (String) -> Unit,
    onDismiss: () -> Unit
) {
    var draft by remember { mutableStateOf(currentStatus) }
    val presets = listOf(
        "🟢 Available",
        "🍔 Lunch",
        "🎧 Focusing",
        "✈️ Traveling",
        "🌙 Do not disturb"
    )

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Set Status") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = draft,
                    onValueChange = { draft = it },
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text("What's your status?") },
                    singleLine = true,
                    shape = RoundedCornerShape(10.dp)
                )

                Text(
                    "Presets",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    presets.forEach { preset ->
                        Text(
                            preset,
                            fontSize = 15.sp,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { draft = preset }
                                .padding(vertical = 6.dp)
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onSave(draft) }) {
                Text("Save")
            }
        },
        dismissButton = {
            Row {
                if (currentStatus.isNotEmpty()) {
                    TextButton(onClick = { onSave("") }) {
                        Text("Clear", color = FreeqColors.danger)
                    }
                }
                TextButton(onClick = onDismiss) {
                    Text("Cancel")
                }
            }
        }
    )
}
