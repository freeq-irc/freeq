package com.freeq.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Reply
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.freeq.model.AppState
import com.freeq.model.ChannelState
import com.freeq.model.ChatMessage
import com.freeq.ui.theme.FreeqColors
import com.freeq.ui.theme.Theme
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreadSheet(
    rootMessage: ChatMessage,
    channelState: ChannelState,
    appState: AppState,
    onDismiss: () -> Unit
) {
    val thread = buildThread(rootMessage, channelState)

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = false),
        containerColor = MaterialTheme.colorScheme.background
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            // Header
            Text(
                text = "Thread",
                fontSize = 17.sp,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
            )

            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f))

            // Thread messages
            LazyColumn(
                modifier = Modifier.weight(1f, fill = false),
                contentPadding = PaddingValues(top = 8.dp, bottom = 8.dp)
            ) {
                itemsIndexed(thread, key = { _, msg -> msg.id }) { index, msg ->
                    val isRoot = msg.id == rootMessage.id

                    Column {
                        // Connector line above (between messages)
                        if (index > 0) {
                            Box(
                                modifier = Modifier
                                    .padding(start = 33.dp)
                                    .width(2.dp)
                                    .height(16.dp)
                                    .background(FreeqColors.accent.copy(alpha = 0.3f))
                            )
                        }

                        // Message row
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(
                                    if (isRoot) FreeqColors.accent.copy(alpha = 0.05f)
                                    else MaterialTheme.colorScheme.background
                                )
                                .padding(horizontal = 16.dp, vertical = 6.dp),
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            // Avatar with thread line below
                            Column(
                                horizontalAlignment = Alignment.CenterHorizontally,
                                modifier = Modifier.width(36.dp)
                            ) {
                                UserAvatar(nick = msg.from, size = 36.dp)

                                if (index < thread.size - 1) {
                                    Box(
                                        modifier = Modifier
                                            .width(2.dp)
                                            .weight(1f)
                                            .background(FreeqColors.accent.copy(alpha = 0.3f))
                                    )
                                }
                            }

                            // Message content
                            Column(
                                modifier = Modifier.weight(1f),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                // Nick + time
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    Text(
                                        text = msg.from,
                                        fontSize = 14.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Theme.nickColor(msg.from)
                                    )
                                    Text(
                                        text = formatThreadTime(msg.timestamp),
                                        fontSize = 11.sp,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                                    )
                                }

                                // Text
                                MessageContent(
                                    text = msg.text,
                                    isAction = msg.isAction,
                                    fromNick = msg.from,
                                    onImageClick = null
                                )

                                if (msg.isEdited) {
                                    Text(
                                        text = "(edited)",
                                        fontSize = 11.sp,
                                        fontStyle = FontStyle.Italic,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                                    )
                                }

                                // Reactions
                                if (msg.reactions.isNotEmpty()) {
                                    Row(
                                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                                    ) {
                                        msg.reactions.forEach { (emoji, nicks) ->
                                            Surface(
                                                shape = RoundedCornerShape(4.dp),
                                                color = MaterialTheme.colorScheme.surfaceVariant
                                            ) {
                                                Row(
                                                    modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp),
                                                    horizontalArrangement = Arrangement.spacedBy(2.dp),
                                                    verticalAlignment = Alignment.CenterVertically
                                                ) {
                                                    Text(emoji, fontSize = 13.sp)
                                                    if (nicks.size > 1) {
                                                        Text(
                                                            "${nicks.size}",
                                                            fontSize = 10.sp,
                                                            fontWeight = FontWeight.Medium,
                                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                                        )
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Reply to thread button
            Button(
                onClick = {
                    appState.replyingTo.value = rootMessage
                    onDismiss()
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 16.dp),
                shape = RoundedCornerShape(10.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = FreeqColors.accent,
                    contentColor = MaterialTheme.colorScheme.onPrimary
                )
            ) {
                Icon(
                    Icons.AutoMirrored.Filled.Reply,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    "Reply to thread",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}

/**
 * Build the thread chain: walk up via replyTo, add root, then all direct replies.
 */
private fun buildThread(rootMessage: ChatMessage, channelState: ChannelState): List<ChatMessage> {
    val chain = mutableListOf<ChatMessage>()

    // Walk up the parent chain
    var current: ChatMessage? = rootMessage
    while (current?.replyTo != null) {
        val parentIdx = channelState.findMessage(current.replyTo!!)
        if (parentIdx != null) {
            current = channelState.messages[parentIdx]
            chain.add(0, current)
        } else {
            break
        }
    }

    // Add the root message itself
    chain.add(rootMessage)

    // Find all direct replies to the root message
    val rootId = rootMessage.id
    val replies = channelState.messages.filter { it.replyTo == rootId && it.id != rootId }
    chain.addAll(replies)

    return chain
}

private fun formatThreadTime(date: Date): String {
    val cal = Calendar.getInstance()
    val today = Calendar.getInstance()
    cal.time = date

    return if (cal.get(Calendar.YEAR) == today.get(Calendar.YEAR) &&
        cal.get(Calendar.DAY_OF_YEAR) == today.get(Calendar.DAY_OF_YEAR)
    ) {
        SimpleDateFormat("h:mm a", Locale.getDefault()).format(date)
    } else {
        SimpleDateFormat("MMM d, h:mm a", Locale.getDefault()).format(date)
    }
}
