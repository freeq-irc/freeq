package com.freeq.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.filled.Search
import androidx.compose.foundation.clickable
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.freeq.model.ChatMessage
import com.freeq.model.AppState
import com.freeq.ui.components.ChannelSettingsSheet
import com.freeq.ui.components.ComposeBar
import com.freeq.ui.components.MemberListSheet
import com.freeq.ui.components.MessageList
import com.freeq.ui.components.PinnedMessagesSheet
import com.freeq.ui.components.SearchSheet
import com.freeq.ui.components.UserProfileSheet

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatDetailScreen(
    appState: AppState,
    channelName: String,
    onBack: () -> Unit,
    onNavigateToChat: ((String) -> Unit)? = null
) {
    // Don't cache channelState - it changes on reconnect when channels are recreated
    val channelState = appState.channels.firstOrNull { it.name.equals(channelName, ignoreCase = true) }
        ?: appState.dmBuffers.firstOrNull { it.name.equals(channelName, ignoreCase = true) }
        // A nick-keyed DM can merge into its DID-keyed thread while open
        // (the peer's first reply teaches the binding): follow it.
        ?: appState.didForNick(channelName)?.let { did ->
            appState.dmBuffers.firstOrNull { it.name == did }
        }

    var showMembers by remember { mutableStateOf(false) }
    var showSearch by remember { mutableStateOf(false) }
    var showChannelSettings by remember { mutableStateOf(false) }
    var showPinnedMessages by remember { mutableStateOf(false) }
    // (nick, origin): origin is non-null only when opened from a federated message.
    var profileTarget by remember { mutableStateOf<Triple<String, String?, ChatMessage?>?>(null) }
    var scrollToMessageId by remember { mutableStateOf<String?>(null) }
    val isChannel = channelName.startsWith("#")

    // Update active channel and mark read
    LaunchedEffect(channelName) {
        appState.activeChannel.value = channelName
        appState.markRead(channelName)
        appState.noteThreadOpened(channelName)
    }

    // Clear active channel when leaving (back button or tab navigation)
    DisposableEffect(channelName) {
        onDispose {
            if (appState.activeChannel.value == channelName) {
                appState.activeChannel.value = null
            }
        }
    }

    // Mark read as messages arrive
    LaunchedEffect(channelState?.messages?.size) {
        appState.markRead(channelName)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column(
                        modifier = if (isChannel && channelState != null)
                            Modifier.clickable { showChannelSettings = true }
                        else Modifier
                    ) {
                        Text(
                            if (isChannel) channelName else appState.displayNameForKey(channelName),
                            fontSize = 17.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                        if (isChannel && channelState != null) {
                            Text(
                                "${channelState.members.size} members",
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                fontWeight = FontWeight.Normal
                            )
                        }
                    }
                },
                navigationIcon = {
                    IconButton(onClick = {
                        appState.activeChannel.value = null
                        onBack()
                    }) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back"
                        )
                    }
                },
                actions = {
                    IconButton(onClick = { showSearch = true }) {
                        Icon(
                            Icons.Default.Search,
                            contentDescription = "Search",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    if (isChannel) {
                        IconButton(onClick = { showMembers = !showMembers }) {
                            Icon(
                                Icons.Default.Group,
                                contentDescription = "Members",
                                tint = if (showMembers) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface
                )
            )
        }
    ) { padding ->
        if (channelState == null) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    "Channel not found",
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            return@Scaffold
        }

        Row(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding()
        ) {
            // Main content: messages + compose
            Column(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxHeight()
            ) {
                // Topic bar
                val topic by channelState.topic
                if (topic.isNotEmpty()) {
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = topic,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                            fontSize = 13.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 2
                        )
                    }
                }

                // Messages
                MessageList(
                    appState = appState,
                    channelState = channelState,
                    onProfileClick = { nick, origin, anchor -> profileTarget = Triple(nick, origin, anchor) },
                    scrollToMessageId = scrollToMessageId,
                    onJumpToMessage = { msgId -> scrollToMessageId = msgId },
                    modifier = Modifier.weight(1f)
                )

                // Compose bar
                ComposeBar(appState = appState)
            }
        }

        // Member list sheet
        if (showMembers && isChannel) {
            MemberListSheet(
                members = channelState.members,
                onDismiss = { showMembers = false },
                onMemberClick = { nick ->
                    showMembers = false
                    profileTarget = Triple(nick, null, null)
                }
            )
        }

        // Search sheet
        if (showSearch) {
            SearchSheet(
                appState = appState,
                onDismiss = { showSearch = false },
                onNavigateToChannel = { channel, messageId ->
                    if (channel.equals(channelName, ignoreCase = true)) {
                        scrollToMessageId = messageId
                    } else {
                        onNavigateToChat?.invoke(channel)
                    }
                }
            )
        }

        // Channel settings sheet
        if (showChannelSettings && isChannel) {
            ChannelSettingsSheet(
                channelState = channelState,
                appState = appState,
                onDismiss = { showChannelSettings = false },
                onLeave = {
                    appState.activeChannel.value = null
                    onBack()
                },
                onShowPinnedMessages = {
                    showChannelSettings = false
                    showPinnedMessages = true
                }
            )
        }

        // Pinned messages sheet
        if (showPinnedMessages && isChannel) {
            PinnedMessagesSheet(
                channelName = channelName,
                onDismiss = { showPinnedMessages = false },
                onNavigateToMessage = { msgId ->
                    showPinnedMessages = false
                    scrollToMessageId = msgId
                }
            )
        }

        // Profile sheet
        profileTarget?.let { (nick, origin, anchor) ->
            UserProfileSheet(
                nick = nick,
                appState = appState,
                origin = origin,
                anchor = anchor,
                onDismiss = { profileTarget = null },
                onNavigateToDM = { dmNick ->
                    val key = appState.didForNick(dmNick) ?: dmNick
                    appState.getOrCreateDM(key)
                    showMembers = false
                    profileTarget = null
                    onNavigateToChat?.invoke(key)
                }
            )
        }
    }
}
