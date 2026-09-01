package com.freeq.ui.components

import android.view.ContextThemeWrapper
import androidx.compose.foundation.background
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Reply
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.freeq.model.AppState
import com.freeq.model.ChannelState
import com.freeq.model.UnreadBoundary
import com.freeq.model.PinCache
import com.freeq.model.SenderIdentity
import com.freeq.model.SignatureVerdict
import com.freeq.model.ChatMessage
import com.freeq.model.MemberInfo
import com.freeq.ui.theme.FreeqColors
import com.freeq.ui.theme.Theme
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun MessageList(
    appState: AppState,
    channelState: ChannelState,
    onProfileClick: ((String, String?, ChatMessage?) -> Unit)? = null,
    scrollToMessageId: String? = null,
    onJumpToMessage: ((String) -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    // Safety: hide blocked users' messages at render time. Messages stay in
    // the buffer so unblocking restores history. System messages (empty
    // `from`) always render.
    val messages = channelState.messages.filter { msg ->
        msg.from.isEmpty() || !appState.isBlocked(msg.from, appState.didForNick(msg.from))
    }
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()
    val clipboardManager = LocalClipboardManager.current
    var lightboxUrl by remember { mutableStateOf<String?>(null) }
    var highlightedMessageId by remember { mutableStateOf<String?>(null) }
    var threadMessage by remember { mutableStateOf<ChatMessage?>(null) }

    // Snapshot last-read position from before this screen visit
    val lastReadId = remember(channelState.name) {
        appState.lastReadMessageIds[channelState.name]
    }
    val lastReadTimestamp = remember(channelState.name) {
        appState.lastReadTimestamps[channelState.name] ?: 0L
    }

    // Scroll to specific message (from search)
    LaunchedEffect(scrollToMessageId) {
        val targetId = scrollToMessageId ?: return@LaunchedEffect
        val idx = messages.indexOfFirst { it.id == targetId }
        if (idx >= 0) {
            listState.animateScrollToItem(idx + 1)
            highlightedMessageId = targetId
        }
    }

    // Track whether the user is near the bottom of the list
    val isNearBottom by remember {
        derivedStateOf {
            val layoutInfo = listState.layoutInfo
            val lastVisible = layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
            val totalItems = layoutInfo.totalItemsCount
            totalItems == 0 || lastVisible >= totalItems - 3
        }
    }

    // On first load, scroll to last-read position (or bottom if none).
    //
    // The LazyColumn has a `__load_older__` header at slot 0, so message i
    // lives at LazyColumn slot i + 1. Forgetting this offset lands one
    // short of the bottom and leaves the scroll-to-bottom FAB visible.
    var initialScrollDone by remember { mutableStateOf(false) }
    LaunchedEffect(messages.size) {
        if (!initialScrollDone && messages.isNotEmpty()) {
            val msgIdx = if (lastReadId != null) {
                val idx = messages.indexOfFirst { it.id == lastReadId }
                if (idx >= 0) idx else messages.size - 1
            } else if (lastReadTimestamp > 0) {
                val idx = messages.indexOfLast { it.timestamp.time <= lastReadTimestamp }
                if (idx >= 0) idx else messages.size - 1
            } else {
                messages.size - 1
            }
            listState.scrollToItem(msgIdx + 1)
            initialScrollDone = true
        } else if (initialScrollDone && messages.isNotEmpty() && scrollToMessageId == null) {
            val lastMsg = messages.lastOrNull()
            val isOwnMessage = lastMsg?.from?.equals(appState.nick.value, ignoreCase = true) == true
            if (isOwnMessage || (isNearBottom && !listState.isScrollInProgress)) {
                listState.animateScrollToItem(messages.size)
            }
        }
    }

    // Pagination state — driven by hasMoreHistory on ChannelState
    val hasMore by channelState.hasMoreHistory
    var loadingOlder by remember { mutableStateOf(false) }
    var countBeforeLoad by remember { mutableIntStateOf(0) }

    // Clear spinner when hasMoreHistory flips (empty batch)
    LaunchedEffect(hasMore) {
        if (!hasMore) loadingOlder = false
    }

    // When older messages arrive, maintain scroll position
    LaunchedEffect(messages.size) {
        if (loadingOlder) {
            loadingOlder = false
            val added = messages.size - countBeforeLoad
            if (added > 0) {
                listState.scrollToItem(listState.firstVisibleItemIndex + added)
            }
        }
    }

    fun loadOlder() {
        if (messages.isEmpty() || loadingOlder || !hasMore) return
        countBeforeLoad = messages.size
        loadingOlder = true
        val oldest = messages.first()
        val target = appState.activeChannel.value ?: return
        val iso = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", java.util.Locale.US)
            .apply { timeZone = java.util.TimeZone.getTimeZone("UTC") }
            .format(oldest.timestamp)
        appState.sendRaw("CHATHISTORY BEFORE $target timestamp=$iso 100")
    }


    Box(modifier = modifier.fillMaxSize()) {
        // Skeleton loading while messages haven't arrived (channels only — empty DMs are valid)
        if (messages.isEmpty() && channelState.name.startsWith("#")) {
            SkeletonLoading()
        }

        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(vertical = 8.dp)
        ) {
            // Top of list: spinner, load button, or beginning-of-history marker
            if (messages.isNotEmpty()) {
                item(key = "__load_older__") {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 12.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        if (loadingOlder) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                strokeWidth = 2.dp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        } else if (hasMore) {
                            TextButton(onClick = { loadOlder() }) {
                                Icon(
                                    Icons.Default.KeyboardArrowUp,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp),
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                                Text(
                                    "Load older messages",
                                    fontSize = 13.sp,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        } else {
                            Text(
                                "Beginning of conversation",
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                            )
                        }
                    }
                }
            }

            val unreadSeparatorMsgId = UnreadBoundary.find(
                messages, lastReadId, lastReadTimestamp, appState.nick.value
            )

            itemsIndexed(messages, key = { _, msg -> msg.id }) { index, msg ->
                val prevMsg = if (index > 0) messages[index - 1] else null
                val currentDate = formatDate(msg.timestamp)
                val prevDate = prevMsg?.let { formatDate(it.timestamp) }
                val timeDiff = if (prevMsg != null) msg.timestamp.time - prevMsg.timestamp.time else Long.MAX_VALUE

                // Unread separator — show before the first unread message
                val showingUnread = msg.id == unreadSeparatorMsgId
                if (showingUnread) {
                    UnreadSeparator()
                }

                // Date separator (skip if unread separator already shown at this boundary)
                if (prevDate == null || currentDate != prevDate) {
                    if (!showingUnread) {
                        DateSeparator(currentDate)
                    }
                }

                // System message (join/part/kick — from is empty)
                if (msg.from.isEmpty()) {
                    SystemMessage(msg.text)
                    return@itemsIndexed
                }

                // Deleted message
                if (msg.isDeleted) {
                    DeletedMessage(msg.from)
                    return@itemsIndexed
                }

                // Show header if sender changes, >5 min gap, or after date/system/deleted boundary.
                // Also break across a provenance boundary: a federated message (msg.origin
                // set) must not collapse under a local sender's header, or it loses its
                // "via {origin}" and inherits the local verified/signed context.
                val showHeader = prevMsg == null
                    || msg.from != prevMsg.from
                    || prevMsg.from.isEmpty()
                    || prevMsg.isDeleted
                    || msg.origin != prevMsg.origin
                    || timeDiff > 5 * 60 * 1000
                    || currentDate != prevDate

                MessageBubble(
                    msg = msg,
                    showHeader = showHeader,
                    isHighlighted = msg.id == highlightedMessageId,
                    appState = appState,
                    channelState = channelState,
                    clipboardManager = clipboardManager,
                    onNickClick = onProfileClick,
                    onImageClick = { url -> lightboxUrl = url },
                    onThreadClick = { threadMsg -> threadMessage = threadMsg },
                    onJumpToMessage = onJumpToMessage
                )
            }

            // Typing indicator
            val typers = channelState.activeTypers
            if (typers.isNotEmpty()) {
                item {
                    TypingIndicator(typers)
                }
            }
        }

        // Scroll-to-bottom FAB — only when newer content has arrived from
        // someone else. If the latest message is the user's own, the auto-
        // scroll on send already puts them at the bottom; surfacing their
        // own message here would just occlude the message they're reading
        // or editing.
        val ownIsLatest by remember {
            derivedStateOf {
                messages.lastOrNull { it.from.isNotEmpty() }
                    ?.from?.equals(appState.nick.value, ignoreCase = true) == true
            }
        }
        AnimatedVisibility(
            visible = !isNearBottom && messages.isNotEmpty() && !ownIsLatest,
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(bottom = 12.dp),
            enter = slideInVertically { it } + fadeIn(),
            exit = slideOutVertically { it } + fadeOut()
        ) {
            val lastMsg = messages.lastOrNull { it.from.isNotEmpty() }
            Surface(
                onClick = {
                    scope.launch {
                        listState.animateScrollToItem(messages.size)
                    }
                },
                shape = RoundedCornerShape(14.dp),
                color = MaterialTheme.colorScheme.surface,
                shadowElevation = 4.dp,
                modifier = Modifier
                    .padding(horizontal = 16.dp)
                    .fillMaxWidth()
            ) {
                if (lastMsg != null) {
                    Row(
                        modifier = Modifier.padding(10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        UserAvatar(nick = lastMsg.from, size = 28.dp)
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = lastMsg.from,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = Theme.nickColor(lastMsg.from),
                                maxLines = 1
                            )
                            Text(
                                text = lastMsg.text.take(60),
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        Icon(
                            Icons.Default.KeyboardArrowDown,
                            contentDescription = "Scroll to bottom",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                } else {
                    Row(
                        modifier = Modifier
                            .padding(10.dp)
                            .fillMaxWidth(),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.KeyboardArrowDown,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            "Scroll to bottom",
                            fontSize = 13.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }

        // Image lightbox overlay
        lightboxUrl?.let { url ->
            ImageLightbox(url = url, onDismiss = { lightboxUrl = null })
        }
    }

    // Thread sheet
    threadMessage?.let { msg ->
        ThreadSheet(
            rootMessage = msg,
            channelState = channelState,
            appState = appState,
            onDismiss = { threadMessage = null }
        )
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun MessageBubble(
    msg: ChatMessage,
    showHeader: Boolean,
    isHighlighted: Boolean = false,
    appState: AppState,
    channelState: ChannelState,
    clipboardManager: androidx.compose.ui.platform.ClipboardManager,
    onNickClick: ((String, String?, ChatMessage?) -> Unit)? = null,
    onImageClick: ((String) -> Unit)? = null,
    onThreadClick: ((ChatMessage) -> Unit)? = null,
    onJumpToMessage: ((String) -> Unit)? = null
) {
    var showMenu by remember { mutableStateOf(false) }
    var showEmojiPicker by remember { mutableStateOf(false) }
    var showReportDialog by remember { mutableStateOf(false) }
    var showMessageProof by remember { mutableStateOf(false) }
    var showIdentityProof by remember { mutableStateOf(false) }
    val haptic = LocalHapticFeedback.current
    val isOwn = msg.from.equals(appState.nick.value, ignoreCase = true)
    // Sender identity: the server-bound DID from the channel member entry
    // (same source UserProfileSheet uses), with the account-tag map as
    // fallback for DMs where the buffer has no member list.
    val senderMember = channelState.members
        .firstOrNull { it.nick.equals(msg.from, ignoreCase = true) }
    val senderDid = senderMember?.did ?: appState.didForNick(msg.from)
    // What this row can honestly claim about its sender — computed by the SDK
    // from the row's own tags and the live room, never from a stored cache.
    val rowClaim = com.freeq.ffi.claimForMessage(
        com.freeq.ffi.MessageClaimInput(
            account = msg.account,
            origin = msg.origin,
            senderPresent = senderMember != null,
            senderLiveDid = senderMember?.did,
            rowTimeUnix = (msg.timestamp.time / 1000).toULong(),
        )
    )
    val isMention = !isOwn && appState.nick.value.isNotEmpty() &&
            msg.text.contains(appState.nick.value, ignoreCase = true)
    // Read directly from pins map so Compose tracks the state change
    val isPinned = PinCache.pins[channelState.name.lowercase()]?.contains(msg.id) == true

    val bgModifier = when {
        isHighlighted -> Modifier.background(FreeqColors.accent.copy(alpha = 0.12f))
        isPinned -> Modifier.background(MaterialTheme.colorScheme.primary.copy(alpha = 0.08f))
        isMention -> Modifier.background(MaterialTheme.colorScheme.primary.copy(alpha = 0.08f))
        else -> Modifier
    }

    val accentColor = FreeqColors.accent

    // Swipe-to-reply gesture state
    val swipeOffset = remember { Animatable(0f) }
    val swipeScope = rememberCoroutineScope()
    val density = LocalDensity.current
    val swipeThresholdPx = with(density) { 60.dp.toPx() }
    var hasTriggered by remember { mutableStateOf(false) }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .pointerInput(msg.id) {
                detectHorizontalDragGestures(
                    onDragStart = { hasTriggered = false },
                    onDragEnd = {
                        if (swipeOffset.value >= swipeThresholdPx) {
                            appState.replyingTo.value = msg
                        }
                        swipeScope.launch { swipeOffset.animateTo(0f) }
                    },
                    onDragCancel = {
                        swipeScope.launch { swipeOffset.animateTo(0f) }
                    },
                    onHorizontalDrag = { _, dragAmount ->
                        val newValue = (swipeOffset.value + dragAmount).coerceIn(0f, swipeThresholdPx * 1.2f)
                        swipeScope.launch { swipeOffset.snapTo(newValue) }
                        if (!hasTriggered && newValue >= swipeThresholdPx) {
                            hasTriggered = true
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        }
                    }
                )
            }
    ) {
        // Reply icon behind the message
        Icon(
            Icons.AutoMirrored.Filled.Reply,
            contentDescription = "Reply",
            tint = FreeqColors.accent,
            modifier = Modifier
                .align(Alignment.CenterStart)
                .padding(start = 12.dp)
                .size(20.dp)
                .alpha((swipeOffset.value / swipeThresholdPx).coerceIn(0f, 1f))
        )

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .offset { IntOffset(swipeOffset.value.toInt(), 0) }
            .then(bgModifier)
            .then(
                when {
                    isPinned -> Modifier.drawBehind {
                        drawRect(
                            color = Color(0xFFFF9800),
                            topLeft = androidx.compose.ui.geometry.Offset.Zero,
                            size = androidx.compose.ui.geometry.Size(3.dp.toPx(), size.height)
                        )
                    }
                    isMention -> Modifier.drawBehind {
                        drawRect(
                            color = accentColor,
                            topLeft = androidx.compose.ui.geometry.Offset.Zero,
                            size = androidx.compose.ui.geometry.Size(3.dp.toPx(), size.height)
                        )
                    }
                    else -> Modifier
                }
            )
            .padding(
                start = 16.dp,
                end = 16.dp,
                top = if (showHeader) 8.dp else 1.dp
            )
    ) {
        // Reply context — tap to open thread view
        if (msg.replyTo != null) {
            val parentMsg = channelState.messages.firstOrNull { it.id == msg.replyTo }
            if (parentMsg != null) {
                Row(
                    modifier = Modifier
                        .padding(start = 48.dp, bottom = 2.dp)
                        .clickable { onThreadClick?.invoke(msg) },
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .width(2.dp)
                            .height(16.dp)
                            .background(MaterialTheme.colorScheme.primary)
                    )
                    Text(
                        text = "${parentMsg.from}: ${parentMsg.text}",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.padding(start = 4.dp)
                    )
                }
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // Avatar (only on header rows)
            if (showHeader) {
                UserAvatar(
                    nick = msg.from,
                    size = 36.dp,
                    modifier = Modifier.clickable { onNickClick?.invoke(msg.from, msg.origin, msg) }
                )
            } else {
                Spacer(modifier = Modifier.width(36.dp))
            }

            Column(
                modifier = Modifier
                    .weight(1f)
                    .combinedClickable(
                        onClick = { showMenu = true },
                        onDoubleClick = {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            appState.activeChannel.value?.let { target ->
                                appState.sendReaction(target, msg.id, "\u2764\uFE0F")
                            }
                        }
                    )
            ) {
                // Header: nick + time
                if (showHeader) {
                    val memberPrefix = senderMember?.prefix ?: ""
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = memberPrefix + msg.from,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = Theme.nickColor(msg.from),
                            modifier = Modifier.clickable { onNickClick?.invoke(msg.from, msg.origin, msg) }
                        )
                        // Only an identity the AT Protocol resolves earns a
                        // mark. The mark IS the claim, so tapping it opens the
                        // proof behind the claim — the identity side of the
                        // proof sheet, with this message's verdict when the
                        // message is signed. The name opens the profile.
                        if (rowClaim.showsMark) {
                            Icon(
                                Icons.Default.CheckCircle,
                                contentDescription = "AT Protocol identity — tap for proof",
                                tint = FreeqColors.accent,
                                modifier = Modifier
                                    .size(14.dp)
                                    .clickable { showIdentityProof = true }
                            )
                        }

                        // Federated: relayed from another server — peer-vouched,
                        // not verified here. Show provenance instead of the local
                        // verified/signed badges (which would overstate trust).
                        if (msg.origin != null) {
                            Text(
                                text = "via ${msg.origin}",
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                            )
                        }
                        Text(
                            text = formatTime(msg.timestamp),
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                        )
                        // Signing is the default state of a message, so a
                        // signed row wears nothing. The one mark a signature
                        // ever leaves here is this: a check the user asked for
                        // came back saying the signature does not match the
                        // key it names. Never speculative — only after
                        // evidence.
                        if (SignatureVerdict.checked[msg.id]?.marksTheRow == true) {
                            Icon(
                                Icons.Default.Warning,
                                contentDescription = "Signature does not match its key",
                                tint = FreeqColors.danger,
                                modifier = Modifier
                                    .size(12.dp)
                                    .clickable { showMessageProof = true }
                            )
                        }
                        if (msg.isEdited) {
                            Text(
                                text = "(edited)",
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                            )
                        }
                    }
                }

                // A task event's companion line is that event's card, and
                // stays one: every event keeps a card of its own.
                val actCard = channelState.actCards[msg.id]
                val coordination = msg.coordination
                if (actCard != null) {
                    ActEventCard(actCard, msg.timestamp, onJumpToMessage)
                } else if (coordination != null) {
                    // Every event-tagged message is a card, whatever its type
                    // says (parity with the other three clients).
                    CoordinationEventCard(coordination, msg.text, msg.timestamp)
                } else {
                    // Message text + inline embeds
                    MessageContent(
                        text = msg.text,
                        isAction = msg.isAction,
                        fromNick = msg.from,
                        onImageClick = onImageClick
                    )
                }

                // Reactions
                if (msg.reactions.isNotEmpty()) {
                    Row(
                        modifier = Modifier.padding(top = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        msg.reactions.forEach { (emoji, nicks) ->
                            val isSelfReacted = nicks.any {
                                it.equals(appState.nick.value, ignoreCase = true)
                            }
                            Surface(
                                shape = RoundedCornerShape(12.dp),
                                color = if (isSelfReacted)
                                    MaterialTheme.colorScheme.primary.copy(alpha = 0.2f)
                                else
                                    MaterialTheme.colorScheme.surfaceVariant,
                                modifier = Modifier.clickable {
                                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                    appState.activeChannel.value?.let { target ->
                                        appState.sendReaction(target, msg.id, emoji)
                                    }
                                }
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(emoji, fontSize = 14.sp)
                                    Text(
                                        "${nicks.size}",
                                        fontSize = 12.sp,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        // Context menu
        DropdownMenu(
            expanded = showMenu,
            onDismissRequest = { showMenu = false }
        ) {
            // Quick-react emoji row
            Row(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                // Trailing four (dancers, notes, sax) are freeq's music/dance brand.
                listOf("\uD83D\uDC4D", "\u2764\uFE0F", "\uD83D\uDE02", "\uD83D\uDE2E", "\uD83D\uDE22", "\uD83D\uDC4E", "\uD83D\uDD7A", "\uD83D\uDC83", "\uD83C\uDFB6", "\uD83C\uDFB7").forEach { emoji ->
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        modifier = Modifier.clickable {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            appState.activeChannel.value?.let { target ->
                                appState.sendReaction(target, msg.id, emoji)
                            }
                            showMenu = false
                        }
                    ) {
                        Text(
                            emoji,
                            fontSize = 20.sp,
                            modifier = Modifier.padding(8.dp)
                        )
                    }
                }
            }
            HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
            DropdownMenuItem(
                text = { Text("Reply") },
                onClick = {
                    appState.replyingTo.value = msg
                    showMenu = false
                },
                leadingIcon = { Icon(Icons.AutoMirrored.Filled.Reply, contentDescription = null) }
            )
            val hasThread = msg.replyTo != null ||
                channelState.messages.any { it.replyTo == msg.id }
            if (hasThread) {
                DropdownMenuItem(
                    text = { Text("View Thread") },
                    onClick = {
                        onThreadClick?.invoke(msg)
                        showMenu = false
                    },
                    leadingIcon = { Icon(Icons.Default.Forum, contentDescription = null) }
                )
            }
            DropdownMenuItem(
                text = { Text("Copy") },
                onClick = {
                    clipboardManager.setText(AnnotatedString(msg.text))
                    showMenu = false
                },
                leadingIcon = { Icon(Icons.Default.ContentCopy, contentDescription = null) }
            )
            DropdownMenuItem(
                text = { Text("Add Reaction") },
                onClick = {
                    showMenu = false
                    showEmojiPicker = true
                },
                leadingIcon = { Icon(Icons.Default.AddReaction, contentDescription = null) }
            )
            // Checking a signature is something the user asks for, not
            // something a row claims on its own.
            DropdownMenuItem(
                text = { Text("Verify Signature") },
                onClick = {
                    showMenu = false
                    showMessageProof = true
                },
                leadingIcon = { Icon(Icons.Default.VerifiedUser, contentDescription = null) }
            )
            // Pin/Unpin - only for ops in channels
            if (channelState.name.startsWith("#")) {
                val myNick = appState.nick.value
                val isOp = channelState.members.any {
                    it.nick.equals(myNick, ignoreCase = true) && it.isOp
                }
                if (isOp) {
                    DropdownMenuItem(
                        text = { Text(if (isPinned) "Unpin Message" else "Pin Message") },
                        onClick = {
                            if (isPinned) {
                                appState.unpinMessage(channelState.name, msg.id)
                            } else {
                                appState.pinMessage(channelState.name, msg.id)
                            }
                            showMenu = false
                        },
                        leadingIcon = { Icon(Icons.Default.PushPin, contentDescription = null) }
                    )
                }
            }
            if (isOwn) {
                DropdownMenuItem(
                    text = { Text("Edit") },
                    onClick = {
                        appState.editingMessage.value = msg
                        showMenu = false
                    },
                    leadingIcon = { Icon(Icons.Default.Edit, contentDescription = null) }
                )
                DropdownMenuItem(
                    text = { Text("Delete") },
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        appState.activeChannel.value?.let { target ->
                            appState.deleteMessage(target, msg.id)
                        }
                        showMenu = false
                    },
                    leadingIcon = {
                        Icon(
                            Icons.Default.Delete,
                            contentDescription = null,
                            tint = FreeqColors.danger
                        )
                    }
                )
            }
            if (!isOwn) {
                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                DropdownMenuItem(
                    text = { Text("Report…") },
                    onClick = {
                        showMenu = false
                        showReportDialog = true
                    },
                    leadingIcon = {
                        Icon(
                            Icons.Default.Flag,
                            contentDescription = null,
                            tint = FreeqColors.danger
                        )
                    }
                )
                DropdownMenuItem(
                    text = { Text("Block ${msg.from}") },
                    onClick = {
                        appState.blockUser(msg.from, senderDid)
                        appState.errorMessage.value = "Blocked ${msg.from}"
                        showMenu = false
                    },
                    leadingIcon = {
                        Icon(
                            Icons.Default.Block,
                            contentDescription = null,
                            tint = FreeqColors.danger
                        )
                    }
                )
            }
        }

        // The check the user asked for, about this message and nothing else.
        // Who sent it is a separate question with its own surface, so this one
        // neither claims nor disowns an identity.
        if (showMessageProof) {
            VerifiedProofSheet(
                request = ProofRequest.Message(msg.id, signed = msg.isSigned),
                onDismiss = { showMessageProof = false }
            )
        }

        // The proof behind the row's identity mark: who the sender is, and —
        // because the mark sits on a message — that message's own verdict
        // when it carries a signature. One sheet, content follows the message.
        if (showIdentityProof) {
            VerifiedProofSheet(
                request = ProofRequest.Identity(
                    did = rowClaim.did,
                    nick = msg.from,
                    origin = msg.origin,
                    account = msg.account,
                    rowTimeUnix = (msg.timestamp.time / 1000).toULong(),
                    senderPresent = senderMember != null,
                    senderLiveDid = senderMember?.did,
                    msgId = msg.id,
                    signed = msg.isSigned,
                ),
                onDismiss = { showIdentityProof = false },
                appState = appState
            )
        }

        if (showReportDialog) {
            ReportReasonDialog(
                nick = msg.from,
                onReport = { reason ->
                    appState.reportUser(msg.from, senderDid, reason)
                    appState.errorMessage.value = "Reported ${msg.from} — user blocked"
                    showReportDialog = false
                },
                onDismiss = { showReportDialog = false }
            )
        }

        // Emoji picker dialog
        if (showEmojiPicker) {
            AlertDialog(
                onDismissRequest = { showEmojiPicker = false },
                confirmButton = {},
                title = { Text("Add Reaction") },
                containerColor = MaterialTheme.colorScheme.surface,
                text = {
                    AndroidView(
                        factory = { context ->
                            val darkContext = ContextThemeWrapper(
                                context,
                                android.R.style.Theme_DeviceDefault
                            )
                            androidx.emoji2.emojipicker.EmojiPickerView(darkContext).apply {
                                setOnEmojiPickedListener { emojiViewItem ->
                                    appState.activeChannel.value?.let { target ->
                                        appState.sendReaction(target, msg.id, emojiViewItem.emoji)
                                    }
                                    showEmojiPicker = false
                                }
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(350.dp)
                    )
                }
            )
        }
    } // Column
    } // Box (swipe-to-reply)
}

@Composable
private fun SkeletonLoading() {
    val transition = rememberInfiniteTransition(label = "shimmer")
    val shimmerX by transition.animateFloat(
        initialValue = -1f,
        targetValue = 2f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1500),
            repeatMode = RepeatMode.Restart
        ),
        label = "shimmerX"
    )

    val shimmerBrush = Brush.linearGradient(
        colors = listOf(Color.Transparent, Color.White.copy(alpha = 0.08f), Color.Transparent),
        start = Offset(shimmerX * 400f, 0f),
        end = Offset(shimmerX * 400f + 250f, 0f)
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(vertical = 8.dp),
        verticalArrangement = Arrangement.Bottom
    ) {
        repeat(5) { i ->
            SkeletonRow(short = i % 3 == 1, shimmerBrush = shimmerBrush)
        }
    }
}

@Composable
private fun SkeletonRow(short: Boolean, shimmerBrush: Brush) {
    val bgColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top
    ) {
        // Avatar placeholder
        Box(
            modifier = Modifier
                .size(36.dp)
                .background(bgColor, CircleShape)
                .then(Modifier.background(shimmerBrush, CircleShape))
        )

        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            // Nick + timestamp
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Box(
                    modifier = Modifier
                        .size(80.dp, 14.dp)
                        .background(bgColor, RoundedCornerShape(4.dp))
                        .then(Modifier.background(shimmerBrush, RoundedCornerShape(4.dp)))
                )
                Box(
                    modifier = Modifier
                        .size(40.dp, 10.dp)
                        .background(bgColor, RoundedCornerShape(4.dp))
                        .then(Modifier.background(shimmerBrush, RoundedCornerShape(4.dp)))
                )
            }
            // Text line 1
            Box(
                modifier = Modifier
                    .size(if (short) 120.dp else 220.dp, 14.dp)
                    .background(bgColor, RoundedCornerShape(4.dp))
                    .then(Modifier.background(shimmerBrush, RoundedCornerShape(4.dp)))
            )
            // Text line 2 (only for non-short)
            if (!short) {
                Box(
                    modifier = Modifier
                        .size(160.dp, 14.dp)
                        .background(bgColor, RoundedCornerShape(4.dp))
                        .then(Modifier.background(shimmerBrush, RoundedCornerShape(4.dp)))
                )
            }
        }
    }
}

@Composable
private fun UnreadSeparator() {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically
    ) {
        HorizontalDivider(
            modifier = Modifier.weight(1f),
            color = FreeqColors.accent
        )
        Text(
            text = "New messages",
            modifier = Modifier.padding(horizontal = 12.dp),
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            color = FreeqColors.accent
        )
        HorizontalDivider(
            modifier = Modifier.weight(1f),
            color = FreeqColors.accent
        )
    }
}

@Composable
private fun DateSeparator(date: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 12.dp),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically
    ) {
        HorizontalDivider(
            modifier = Modifier.weight(1f),
            color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f)
        )
        Text(
            text = date,
            modifier = Modifier.padding(horizontal = 12.dp),
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
        )
        HorizontalDivider(
            modifier = Modifier.weight(1f),
            color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f)
        )
    }
}

@Composable
private fun SystemMessage(text: String) {
    Text(
        text = text,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp),
        fontSize = 12.sp,
        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
        fontStyle = FontStyle.Italic
    )
}

@Composable
private fun DeletedMessage(from: String) {
    Text(
        text = "Message from $from deleted",
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 64.dp, vertical = 2.dp),
        fontSize = 13.sp,
        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f),
        fontStyle = FontStyle.Italic
    )
}

@Composable
private fun TypingIndicator(typers: List<String>) {
    val text = when {
        typers.size == 1 -> "${typers[0]} is typing..."
        typers.size == 2 -> "${typers[0]} and ${typers[1]} are typing..."
        else -> "${typers[0]} and ${typers.size - 1} others are typing..."
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        // Animated dots
        Text(
            text = "...",
            fontSize = 16.sp,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.primary
        )
        Text(
            text = text,
            fontSize = 12.sp,
            fontStyle = FontStyle.Italic,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
        )
    }
}

private fun formatTime(date: Date): String {
    return SimpleDateFormat("HH:mm", Locale.getDefault()).format(date)
}

private fun formatDate(date: Date): String {
    val cal = Calendar.getInstance()
    val today = Calendar.getInstance()
    cal.time = date

    return when {
        cal.get(Calendar.YEAR) == today.get(Calendar.YEAR) &&
                cal.get(Calendar.DAY_OF_YEAR) == today.get(Calendar.DAY_OF_YEAR) -> "Today"
        cal.get(Calendar.YEAR) == today.get(Calendar.YEAR) &&
                cal.get(Calendar.DAY_OF_YEAR) == today.get(Calendar.DAY_OF_YEAR) - 1 -> "Yesterday"
        else -> SimpleDateFormat("MMMM d, yyyy", Locale.getDefault()).format(date)
    }
}
