package com.freeq.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.filled.Logout
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.NotificationsOff
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Tag
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.freeq.model.AppState
import com.freeq.model.AvatarCache
import com.freeq.model.ChannelState
import com.freeq.ui.theme.FreeqColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChannelSettingsSheet(
    channelState: ChannelState,
    appState: AppState,
    onDismiss: () -> Unit,
    onLeave: () -> Unit,
    onShowPinnedMessages: () -> Unit
) {
    val topic by channelState.topic
    var editingTopic by remember { mutableStateOf(false) }
    var topicDraft by remember { mutableStateOf(topic) }
    val myNick = appState.nick.value
    val isOp = channelState.members.any {
        it.nick.equals(myNick, ignoreCase = true) && it.isOp
    }
    val ops = channelState.members.filter { it.isOp }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = false),
        containerColor = MaterialTheme.colorScheme.background,
        dragHandle = { BottomSheetDefaults.DragHandle() }
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 32.dp)
        ) {
            // ── Channel Header ──
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = FreeqColors.accent.copy(alpha = 0.15f),
                    modifier = Modifier.size(48.dp)
                ) {
                    Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxSize()) {
                        Icon(
                            Icons.Default.Tag,
                            contentDescription = null,
                            tint = FreeqColors.accent,
                            modifier = Modifier.size(24.dp)
                        )
                    }
                }
                Column {
                    Text(
                        text = channelState.name,
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onBackground
                    )
                    Text(
                        text = "${channelState.members.size} members",
                        fontSize = 13.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // ── Topic Section ──
            Card(
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            "TOPIC",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                            letterSpacing = 1.sp
                        )
                        if (isOp && !editingTopic) {
                            IconButton(
                                onClick = {
                                    topicDraft = topic
                                    editingTopic = true
                                },
                                modifier = Modifier.size(28.dp)
                            ) {
                                Icon(
                                    Icons.Default.Edit,
                                    contentDescription = "Edit topic",
                                    modifier = Modifier.size(16.dp),
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    if (editingTopic) {
                        OutlinedTextField(
                            value = topicDraft,
                            onValueChange = { topicDraft = it },
                            modifier = Modifier.fillMaxWidth(),
                            minLines = 1,
                            maxLines = 5,
                            textStyle = LocalTextStyle.current.copy(fontSize = 14.sp)
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.End
                        ) {
                            TextButton(onClick = { editingTopic = false }) {
                                Text("Cancel")
                            }
                            Spacer(modifier = Modifier.width(8.dp))
                            Button(
                                onClick = {
                                    appState.sendRaw("TOPIC ${channelState.name} :$topicDraft")
                                    editingTopic = false
                                },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = FreeqColors.accent
                                )
                            ) {
                                Text("Save")
                            }
                        }
                    } else {
                        Text(
                            text = topic.ifEmpty { "No topic set" },
                            fontSize = 14.sp,
                            color = if (topic.isEmpty())
                                MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)
                            else MaterialTheme.colorScheme.onBackground
                        )
                    }
                }
            }

            // ── Operators Section ──
            if (ops.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                Card(
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            "OPERATORS (${ops.size})",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                            letterSpacing = 1.sp
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        ops.forEach { op ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                UserAvatar(nick = op.nick, size = 28.dp)
                                Text(
                                    text = op.nick,
                                    fontSize = 14.sp,
                                    color = MaterialTheme.colorScheme.onBackground,
                                    modifier = Modifier.weight(1f)
                                )
                                if (AvatarCache.avatarUrl(op.nick) != null) {
                                    Icon(
                                        Icons.Default.CheckCircle,
                                        contentDescription = "AT Protocol identity",
                                        tint = FreeqColors.accent,
                                        modifier = Modifier.size(14.dp)
                                    )
                                }
                                Icon(
                                    Icons.Default.Shield,
                                    contentDescription = "Operator",
                                    tint = FreeqColors.warning,
                                    modifier = Modifier.size(14.dp)
                                )
                            }
                        }
                    }
                }
            }

            // ── Notifications ──
            Spacer(modifier = Modifier.height(12.dp))
            Card(
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        val isMuted = appState.isMuted(channelState.name)
                        Icon(
                            if (isMuted) Icons.Default.NotificationsOff else Icons.Default.Notifications,
                            contentDescription = null,
                            tint = if (isMuted) MaterialTheme.colorScheme.onSurfaceVariant else FreeqColors.accent,
                            modifier = Modifier.size(20.dp)
                        )
                        Text(
                            "Mute Notifications",
                            fontSize = 15.sp,
                            color = MaterialTheme.colorScheme.onBackground
                        )
                    }
                    Switch(
                        checked = appState.isMuted(channelState.name),
                        onCheckedChange = { appState.toggleMute(channelState.name) },
                        colors = SwitchDefaults.colors(checkedTrackColor = FreeqColors.accent)
                    )
                }
            }

            // ── Pinned Messages ──
            Spacer(modifier = Modifier.height(12.dp))
            Card(
                onClick = onShowPinnedMessages,
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Icon(
                            Icons.Default.PushPin,
                            contentDescription = null,
                            tint = FreeqColors.warning,
                            modifier = Modifier.size(20.dp)
                        )
                        Text(
                            "Pinned Messages",
                            fontSize = 15.sp,
                            color = MaterialTheme.colorScheme.onBackground
                        )
                    }
                    Icon(
                        Icons.AutoMirrored.Filled.KeyboardArrowRight,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(20.dp)
                    )
                }
            }

            // ── Leave Channel ──
            Spacer(modifier = Modifier.height(16.dp))
            Button(
                onClick = {
                    appState.partChannel(channelState.name)
                    onDismiss()
                    onLeave()
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = FreeqColors.danger),
                contentPadding = PaddingValues(vertical = 14.dp)
            ) {
                Icon(
                    Icons.AutoMirrored.Filled.Logout,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    "Leave Channel",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
    }
}
