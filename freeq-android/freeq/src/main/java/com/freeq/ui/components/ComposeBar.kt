package com.freeq.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Reply
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalView
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import android.net.Uri
import com.freeq.model.AppState
import com.freeq.model.SlashCommand
import com.freeq.model.SlashCommandParser
import com.freeq.ui.theme.FreeqColors
import com.freeq.ui.theme.Theme

@Composable
fun ComposeBar(
    appState: AppState,
    modifier: Modifier = Modifier
) {
    var text by remember { mutableStateOf("") }
    var completions by remember { mutableStateOf<List<String>>(emptyList()) }
    var photoUri by remember { mutableStateOf<Uri?>(null) }
    val haptic = LocalHapticFeedback.current
    val view = LocalView.current

    val replyingTo by appState.replyingTo
    val editingMessage by appState.editingMessage
    val activeChannel = appState.activeChannel.value

    // Pre-fill text when entering edit mode; dismiss keyboard when leaving.
    //
    // Compose's `LocalSoftwareKeyboardController.hide()` is documented as
    // best-effort and unreliable when called from a coroutine / state-change
    // context (the focus token may be stale by the time it dispatches to
    // InputMethodManager). Going through the view + WindowInsetsController
    // is the official Android API for IME visibility and works regardless
    // of who calls it.
    var wasEditingAState by remember { mutableStateOf(false) }
    LaunchedEffect(editingMessage) {
        if (editingMessage != null) {
            text = editingMessage!!.text
            wasEditingAState = true
        } else if (wasEditingAState) {
            wasEditingAState = false
            view.clearFocus()
            ViewCompat.getWindowInsetsController(view)?.hide(WindowInsetsCompat.Type.ime())
        }
    }

    val canSend = text.isNotBlank()

    Column(modifier = modifier) {
        // Top border
        HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f))

        // Autocomplete suggestions (nicks and emoji)
        if (completions.isNotEmpty()) {
            LazyRow(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surface)
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                items(completions) { item ->
                    val isEmoji = item.contains(" :") && !item.startsWith("@")
                    Surface(
                        shape = RoundedCornerShape(16.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        modifier = Modifier.clickable { applyCompletion(item, text) { text = it; completions = emptyList() } }
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                            horizontalArrangement = Arrangement.spacedBy(4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            if (isEmoji) {
                                Text(
                                    item.split(" ")[0],
                                    fontSize = 18.sp
                                )
                                Text(
                                    item.split(" :").last().trimEnd(':'),
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = MaterialTheme.colorScheme.onBackground
                                )
                            } else {
                                UserAvatar(nick = item, size = 20.dp)
                                Text(
                                    item,
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = MaterialTheme.colorScheme.onBackground
                                )
                            }
                        }
                    }
                }
            }
        }

        // Reply context bar
        if (replyingTo != null) {
            ContextBar(
                icon = Icons.AutoMirrored.Filled.Reply,
                label = "Replying to ${replyingTo!!.from}",
                preview = replyingTo!!.text,
                color = FreeqColors.accent,
                onDismiss = { appState.replyingTo.value = null }
            )
        }

        // Edit context bar
        if (editingMessage != null) {
            ContextBar(
                icon = Icons.Default.Edit,
                label = "Editing message",
                preview = editingMessage!!.text,
                color = FreeqColors.warning,
                onDismiss = {
                    appState.editingMessage.value = null
                    text = ""
                }
            )
        }

        // Input area
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surface)
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.Bottom,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // Text field
            OutlinedTextField(
                value = text,
                onValueChange = { newText ->
                    // Intercept Enter when completions are showing
                    if (completions.isNotEmpty() && newText.contains("\n")) {
                        applyCompletion(completions.first(), text) { text = it; completions = emptyList() }
                        return@OutlinedTextField
                    }
                    text = replaceEmojiShortcodes(newText)
                    completions = updateCompletions(text, appState)
                    if (newText.isNotEmpty()) {
                        activeChannel?.let { appState.sendTyping(it) }
                    }
                },
                modifier = Modifier.weight(1f),
                placeholder = {
                    val placeholder = when {
                        replyingTo != null -> "Reply..."
                        editingMessage != null -> "Edit message..."
                        else -> "Message ${activeChannel?.let { appState.displayNameForKey(it) } ?: ""}"
                    }
                    Text(placeholder, fontSize = 15.sp)
                },
                leadingIcon = {
                    // Photo picker inside text field
                    PhotoPickerButton(
                        appState = appState,
                        onPhotoPicked = { uri -> photoUri = uri }
                    )
                },
                maxLines = 6,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                keyboardActions = KeyboardActions(
                    onSend = {
                        if (canSend) {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            send(text.trim(), appState) { text = ""; completions = emptyList() }
                        }
                    }
                ),
                shape = RoundedCornerShape(22.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.5f),
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
                    focusedContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                ),
                textStyle = LocalTextStyle.current.copy(fontSize = 15.sp)
            )

            // Send button
            IconButton(
                onClick = {
                    if (canSend) {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        send(text.trim(), appState) { text = ""; completions = emptyList() }
                    }
                },
                enabled = canSend,
                modifier = Modifier
                    .size(40.dp)
                    .clip(CircleShape)
                    .background(
                        if (canSend) FreeqColors.accent
                        else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.2f)
                    )
            ) {
                Icon(
                    imageVector = if (editingMessage != null) Icons.Default.Check else Icons.Default.ArrowUpward,
                    contentDescription = "Send",
                    tint = MaterialTheme.colorScheme.onPrimary,
                    modifier = Modifier.size(20.dp)
                )
            }
        }
    }

    // Photo preview sheet
    photoUri?.let { uri ->
        ImagePreviewSheet(
            uri = uri,
            appState = appState,
            onDismiss = { photoUri = null },
            onSent = { photoUri = null }
        )
    }
}

@Composable
private fun ContextBar(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    preview: String,
    color: androidx.compose.ui.graphics.Color,
    onDismiss: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Box(
            modifier = Modifier
                .width(3.dp)
                .height(32.dp)
                .background(color, shape = RoundedCornerShape(2.dp))
        )

        Icon(
            icon,
            contentDescription = null,
            modifier = Modifier.size(14.dp),
            tint = color
        )

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = label,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = color
            )
            Text(
                text = preview,
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }

        IconButton(onClick = onDismiss, modifier = Modifier.size(24.dp)) {
            Icon(
                Icons.Default.Close,
                contentDescription = "Dismiss",
                modifier = Modifier.size(18.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

private fun updateCompletions(text: String, appState: AppState): List<String> {
    val lastWord = text.split(" ").lastOrNull() ?: return emptyList()

    // @mention autocomplete
    if (lastWord.startsWith("@") && lastWord.length > 1) {
        val prefix = lastWord.drop(1).lowercase()
        val members = appState.activeChannelState?.members ?: return emptyList()
        return members
            .map { it.nick }
            .filter { it.lowercase().startsWith(prefix) && !it.equals(appState.nick.value, ignoreCase = true) }
            .sorted()
            .take(5)
    }

    // :emoji autocomplete
    if (lastWord.startsWith(":") && lastWord.length > 1 && !lastWord.drop(1).contains(":")) {
        val partial = lastWord.drop(1).lowercase()
        return EMOJI_MAP.entries
            .filter { it.key.startsWith(partial) || it.key.contains(partial) }
            .sortedBy { if (it.key.startsWith(partial)) 0 else 1 }
            .take(8)
            .map { "${it.value} :${it.key}:" }
    }

    return emptyList()
}

private fun applyCompletion(item: String, currentText: String, setText: (String) -> Unit) {
    val words = currentText.split(" ").toMutableList()
    if (words.isEmpty()) return
    val lastWord = words.last()
    if (lastWord.startsWith("@")) {
        words[words.lastIndex] = "@$item"
    } else if (lastWord.startsWith(":") && item.contains(" :")) {
        // Emoji completion: item is "🔥 :fire:", extract just the emoji
        val emoji = item.split(" ")[0]
        words[words.lastIndex] = emoji
    }
    setText(words.joinToString(" ") + " ")
}

private fun send(text: String, appState: AppState, onSent: () -> Unit) {
    val target = appState.activeChannel.value ?: return
    if (text.isEmpty()) return

    if (text.startsWith("/")) {
        handleCommand(text, appState)
    } else {
        appState.sendMessage(target, text)
    }
    onSent()
}

private fun handleCommand(input: String, appState: AppState) {
    when (val parsed = SlashCommandParser.parse(input)) {
        is SlashCommand.Join -> appState.joinChannel(parsed.channel)
        SlashCommand.PartActive -> appState.activeChannel.value?.let { appState.partChannel(it) }
        is SlashCommand.Nick -> appState.sendRaw("NICK ${parsed.newNick}")
        is SlashCommand.Me -> appState.activeChannel.value?.let { target ->
            appState.sendAction(target, parsed.text)
        }
        is SlashCommand.Msg -> appState.sendMessage(parsed.target, parsed.text)
        is SlashCommand.Topic -> appState.activeChannel.value?.let { target ->
            appState.sendRaw("TOPIC $target :${parsed.text}")
        }
        is SlashCommand.Raw -> appState.sendRaw(parsed.line)
        SlashCommand.Empty -> {} // recognized but missing arg — silent no-op
    }
}
