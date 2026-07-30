package com.freeq.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Chat
import androidx.compose.material.icons.automirrored.filled.ExitToApp
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.freeq.model.AppState
import com.freeq.model.ChannelState
import com.freeq.model.ChatMessage
import com.freeq.model.PeoplePicker
import com.freeq.ui.components.UserAvatar
import com.freeq.ui.theme.FreeqColors
import com.freeq.ui.theme.Theme
import java.text.DateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatsTab(
    appState: AppState,
    onChannelClick: (String) -> Unit
) {
    var searchText by remember { mutableStateOf("") }
    var showJoinDialog by remember { mutableStateOf(false) }
    var showNewMessageDialog by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()

    val allConversations by remember {
        derivedStateOf {
            // Blocked users' DM conversations are hidden (safety layer);
            // unblocking in Settings → Safety brings them back.
            (appState.channels + appState.dmBuffers.filter {
                it.name.isNotEmpty() && it.messages.isNotEmpty() &&
                    !appState.isBlocked(it.name, appState.didForNick(it.name))
            })
                .sortedByDescending { it.lastActivityTime.value }
        }
    }

    // Scroll to top when conversations are ready
    val firstConversation = allConversations.firstOrNull()?.name
    LaunchedEffect(firstConversation) {
        if (firstConversation != null) {
            listState.scrollToItem(0)
        }
    }
    val filteredConversations = if (searchText.isEmpty()) {
        allConversations
    } else {
        allConversations.filter { it.name.contains(searchText, ignoreCase = true) }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Chats") },
                actions = {
                    // Two explicit entries, mirroring the platform family:
                    // join-a-channel (iOS's pencil sheet, bare names get a
                    // "#") and new-message-by-name (macOS's NewDMSheet).
                    // One combined guess-which dialog mis-filed bare
                    // channel names as people.
                    IconButton(onClick = { showJoinDialog = true }) {
                        Icon(
                            Icons.Default.Add,
                            contentDescription = "Join channel",
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                    IconButton(onClick = { showNewMessageDialog = true }) {
                        Icon(
                            Icons.Default.Edit,
                            contentDescription = "New message",
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface
                )
            )
        }
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            // Network warning banner
            val networkConnected by appState.networkMonitor.isConnected
            if (!networkConnected) {
                Surface(
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            Icons.Default.WifiOff,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = MaterialTheme.colorScheme.onError
                        )
                        Text(
                            "No network connection",
                            fontSize = 13.sp,
                            color = MaterialTheme.colorScheme.onError
                        )
                    }
                }
            }

            // Search bar
            OutlinedTextField(
                value = searchText,
                onValueChange = { searchText = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                placeholder = { Text("Search chats") },
                leadingIcon = {
                    Icon(
                        Icons.Default.Search,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline,
                    focusedContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                )
            )

            if (allConversations.isEmpty()) {
                // Empty state
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Icon(
                            Icons.AutoMirrored.Filled.Chat,
                            contentDescription = null,
                            modifier = Modifier.size(48.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                        )
                        Text(
                            "No conversations yet",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Medium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            "Join a channel to get started",
                            fontSize = 14.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                        )
                        TextButton(onClick = { showJoinDialog = true }) {
                            Icon(
                                Icons.Default.Add,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Join Channel")
                        }
                    }
                }
            } else {
                LazyColumn(state = listState, modifier = Modifier.fillMaxSize()) {
                    items(filteredConversations, key = { it.name }) { conversation ->
                        val isChannel = conversation.name.startsWith("#")
                        if (isChannel) {
                            val dismissState = rememberSwipeToDismissBoxState(
                                confirmValueChange = { value ->
                                    if (value == SwipeToDismissBoxValue.EndToStart) {
                                        appState.partChannel(conversation.name)
                                        true
                                    } else false
                                }
                            )
                            SwipeToDismissBox(
                                state = dismissState,
                                backgroundContent = {
                                    Box(
                                        modifier = Modifier
                                            .fillMaxSize()
                                            .background(MaterialTheme.colorScheme.error)
                                            .padding(horizontal = 20.dp),
                                        contentAlignment = Alignment.CenterEnd
                                    ) {
                                        Icon(
                                            Icons.AutoMirrored.Filled.ExitToApp,
                                            contentDescription = "Leave",
                                            tint = MaterialTheme.colorScheme.onError
                                        )
                                    }
                                },
                                enableDismissFromStartToEnd = false
                            ) {
                                Surface(color = MaterialTheme.colorScheme.background) {
                                    ChatRow(
                                        conversation = conversation,
                                        unreadCount = appState.unreadCounts[conversation.name] ?: 0,
                                        onClick = { onChannelClick(conversation.name) },
                                        displayName = appState.displayNameForKey(conversation.name)
                                    )
                                }
                            }
                        } else {
                            ChatRow(
                                conversation = conversation,
                                unreadCount = appState.unreadCounts[conversation.name] ?: 0,
                                onClick = { onChannelClick(conversation.name) },
                                displayName = appState.displayNameForKey(conversation.name)
                            )
                        }
                        HorizontalDivider(
                            modifier = Modifier.padding(start = 76.dp),
                            color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f)
                        )
                    }
                }
            }
        }
    }

    // Join channel dialog
    if (showJoinDialog) {
        JoinChannelDialog(
            appState = appState,
            onDismiss = { showJoinDialog = false }
        )
    }
    if (showNewMessageDialog) {
        NewMessageDialog(
            appState = appState,
            onDismiss = { showNewMessageDialog = false },
            onOpenDm = { name -> onChannelClick(appState.getOrCreateDM(name).name) }
        )
    }
}

@Composable
private fun ChatRow(
    conversation: ChannelState,
    unreadCount: Int,
    onClick: () -> Unit,
    displayName: String = conversation.name,
) {
    val isChannel = conversation.name.startsWith("#")
    val lastMessage = conversation.messages.lastOrNull { it.from.isNotEmpty() && !it.isDeleted }
    val timeString = lastMessage?.let { formatTime(it.timestamp) } ?: ""
    val typingActive = conversation.activeTypers.isNotEmpty()

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Avatar / channel icon
        if (isChannel) {
            Box(
                modifier = Modifier
                    .size(50.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    "#",
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
            }
        } else {
            UserAvatar(nick = displayName, size = 50.dp)
        }

        // Content
        Column(modifier = Modifier.weight(1f)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = displayName,
                    fontSize = 16.sp,
                    fontWeight = if (unreadCount > 0) FontWeight.Bold else FontWeight.Normal,
                    color = MaterialTheme.colorScheme.onBackground,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                Text(
                    text = timeString,
                    fontSize = 12.sp,
                    color = if (unreadCount > 0) MaterialTheme.colorScheme.primary
                    else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(2.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                val previewText = when {
                    lastMessage != null -> {
                        if (lastMessage.isAction) "${lastMessage.from} ${lastMessage.text}"
                        else "${lastMessage.from}: ${lastMessage.text}"
                    }
                    conversation.topic.value.isNotEmpty() -> conversation.topic.value
                    isChannel -> "No messages yet"
                    else -> "Start a conversation"
                }

                Text(
                    text = previewText,
                    fontSize = 14.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )

                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    if (typingActive) {
                        Icon(
                            Icons.Default.MoreHoriz,
                            contentDescription = "Typing",
                            modifier = Modifier.size(16.dp),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }

                    if (unreadCount > 0) {
                        Box(
                            modifier = Modifier
                                .clip(CircleShape)
                                .background(MaterialTheme.colorScheme.primary)
                                .padding(horizontal = 7.dp, vertical = 2.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "$unreadCount",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onPrimary
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun JoinChannelDialog(
    appState: AppState,
    onDismiss: () -> Unit
) {
    var channelName by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Join Channel") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                OutlinedTextField(
                    value = channelName,
                    onValueChange = { channelName = it },
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text("channel-name") },
                    prefix = { Text("#") },
                    singleLine = true,
                    shape = RoundedCornerShape(10.dp)
                )

                Text(
                    "Popular channels",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                val popularChannels = listOf("#general", "#freeq", "#dev", "#music", "#random", "#crypto", "#gaming")
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    popularChannels.forEach { ch ->
                        val isJoined = appState.channels.any { it.name.equals(ch, ignoreCase = true) }
                        TextButton(
                            onClick = {
                                if (!isJoined) {
                                    appState.joinChannel(ch)
                                    onDismiss()
                                }
                            },
                            enabled = !isJoined
                        ) {
                            Text(
                                ch,
                                color = if (isJoined) MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                                else MaterialTheme.colorScheme.primary
                            )
                            if (isJoined) {
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Joined", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f))
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    if (channelName.isNotBlank()) {
                        // joinChannel normalizes a bare name to "#name",
                        // matching iOS's join sheet.
                        appState.joinChannel(channelName.trim())
                        onDismiss()
                    }
                },
                enabled = channelName.isNotBlank()
            ) {
                Text("Join")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

/** New message — the macOS `NewDMSheet` flow: a people picker over
 *  everyone you share a channel or DM thread with, live-filtered as you
 *  type, with a free-form row so a name nobody matches can still be
 *  messaged. Channel joining is deliberately a separate dialog. */
@Composable
private fun NewMessageDialog(
    appState: AppState,
    onDismiss: () -> Unit,
    onOpenDm: (String) -> Unit
) {
    var query by remember { mutableStateOf("") }
    val candidates = remember {
        PeoplePicker.candidates(
            memberNicks = appState.channels.flatMap { ch -> ch.members.map { it.nick } },
            dmThreads = appState.dmBuffers.map { it.name },
            selfNick = appState.nick.value,
            nickToDid = appState::didForNick,
            displayName = appState::displayNameForKey,
        )
    }
    val filtered = PeoplePicker.filter(candidates, query)
    val freeform = PeoplePicker.freeform(query, candidates)

    fun open(key: String) {
        onOpenDm(key)
        onDismiss()
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("New message") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text("Type a name…") },
                    singleLine = true,
                    shape = RoundedCornerShape(10.dp)
                )
                LazyColumn(modifier = Modifier.heightIn(max = 320.dp)) {
                    if (freeform != null) {
                        item(key = "freeform") {
                            PersonRow(
                                label = freeform,
                                subtitle = "Send a new message",
                                onClick = { open(freeform) }
                            )
                        }
                    }
                    items(filtered.size, key = { filtered[it].key }) { i ->
                        val person = filtered[i]
                        PersonRow(
                            label = person.label,
                            subtitle = if (person.online) "Online" else null,
                            onClick = { open(person.key) }
                        )
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
private fun PersonRow(label: String, subtitle: String?, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 4.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        UserAvatar(nick = label, size = 36.dp)
        Column {
            Text(label, fontSize = 15.sp, color = MaterialTheme.colorScheme.onSurface)
            if (subtitle != null) {
                Text(subtitle, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

private fun formatTime(date: Date): String {
    val cal = Calendar.getInstance()
    val today = Calendar.getInstance()

    cal.time = date

    return when {
        cal.get(Calendar.YEAR) == today.get(Calendar.YEAR) &&
                cal.get(Calendar.DAY_OF_YEAR) == today.get(Calendar.DAY_OF_YEAR) -> {
            DateFormat.getTimeInstance(DateFormat.SHORT, Locale.getDefault()).format(date)
        }
        cal.get(Calendar.YEAR) == today.get(Calendar.YEAR) &&
                cal.get(Calendar.DAY_OF_YEAR) == today.get(Calendar.DAY_OF_YEAR) - 1 -> {
            "Yesterday"
        }
        else -> {
            DateFormat.getDateInstance(DateFormat.SHORT, Locale.getDefault()).format(date)
        }
    }
}
