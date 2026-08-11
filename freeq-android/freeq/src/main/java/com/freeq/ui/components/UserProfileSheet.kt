package com.freeq.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Flag
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.automirrored.filled.Chat
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.freeq.model.ChatMessage
import com.freeq.model.AppState
import com.freeq.model.AvatarCache
import com.freeq.model.BlueskyProfile
import com.freeq.model.SenderIdentity
import com.freeq.ui.theme.FreeqColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UserProfileSheet(
    nick: String,
    appState: AppState,
    origin: String? = null,
    /** The message this sheet was opened from, when there is one. Its own
     *  tags are evidence: when live identity can't answer, the row does —
     *  the SDK owns that precedence. */
    anchor: ChatMessage? = null,
    onDismiss: () -> Unit,
    onNavigateToDM: (String) -> Unit
) {
    var profile by remember { mutableStateOf<BlueskyProfile?>(null) }
    var loading by remember { mutableStateOf(true) }
    var showReportDialog by remember { mutableStateOf(false) }
    var showIdentityProof by remember { mutableStateOf(false) }
    val uriHandler = LocalUriHandler.current
    val isOwnProfile = nick.equals(appState.nick.value, ignoreCase = true)
    // Identity is the server-bound DID, never the nick. Resolve the DID
    // from our own session (self) or a channel member entry / account-tag
    // map; with no DID there is no Bluesky profile to show (no
    // nick-as-handle guessing).
    val resolvedDid = if (isOwnProfile) {
        appState.authenticatedDID.value
    } else {
        appState.didForNick(nick)
    }
    val isBlocked = appState.isBlocked(nick, resolvedDid)
    // The SDK owns the precedence: live identity first, then the anchoring
    // row's evidence, then the lookup machine. A binding remembered from an
    // earlier session never votes — that hole is how the same absent sender
    // used to read differently here than on web.
    val claim = com.freeq.ffi.claimForSender(
        com.freeq.ffi.MessageClaimInput(
            account = anchor?.account,
            origin = origin,
            senderPresent = appState.isNickPresent(nick),
            senderLiveDid = if (isOwnProfile) appState.authenticatedDID.value else appState.liveDidForNick(nick),
            rowTimeUnix = anchor?.timestamp?.let { (it.time / 1000).toULong() },
        ),
        appState.personLookup(nick),
    )

    LaunchedEffect(nick) {
        // Ask who this is, and let the card say an ask is out — so "unknown"
        // is only ever shown after an answer, never before one.
        if (origin == null && !isOwnProfile) appState.lookUpIdentity(nick)
        profile = withContext(Dispatchers.IO) {
            AvatarCache.fetchProfileIfNeeded(nick, resolvedDid)
        }
        loading = false
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = false),
        containerColor = MaterialTheme.colorScheme.background,
        dragHandle = { BottomSheetDefaults.DragHandle() }
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Avatar
            UserAvatar(nick = nick, size = 80.dp)

            Spacer(modifier = Modifier.height(16.dp))

            // Nick + verified badge
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text(
                    text = nick,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onBackground
                )
                // The mark follows the identifier, not the avatar fetch, and
                // it is the same rule the message row applies.
                if (claim.showsMark) {
                    Icon(
                        Icons.Default.CheckCircle,
                        contentDescription = "AT Protocol identity — tap for the proof",
                        tint = FreeqColors.accent,
                        modifier = Modifier
                            .size(18.dp)
                            .clickable { showIdentityProof = true }
                    )
                }
            }

            // What this client can honestly say about who this is — the same
            // claim rule and language as every other surface. An ask that is
            // out shows as motion, not as a sentence nobody can finish reading
            // before it is replaced.
            if (claim.isPending) {
                Spacer(modifier = Modifier.height(4.dp))
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    strokeWidth = 2.dp
                )
            }
            claim.label?.let { label ->
                Text(
                    text = label,
                    fontSize = 12.sp,
                    color = if (claim.showsMark) FreeqColors.accent
                    else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            // The proof sheet is where the explanation lives; this card
            // carries the sentence only for someone with no DID, where there
            // is no sheet to open and the card is the whole answer.
            if (claim.did.isNullOrEmpty()) {
                claim.line?.let { line ->
                    Text(
                        text = line,
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(horizontal = 32.dp)
                    )
                }
            }

            // Away status
            appState.awayMessage(nick)?.let { awayMsg ->
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .background(FreeqColors.warning, CircleShape)
                    )
                    Text(
                        text = "Away",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = FreeqColors.warning
                    )
                }
                if (awayMsg.isNotEmpty()) {
                    Text(
                        text = awayMsg,
                        fontSize = 13.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // Display name
            profile?.displayName?.takeIf { it.isNotEmpty() }?.let { displayName ->
                Text(
                    text = displayName,
                    fontSize = 15.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // Handle
            profile?.let { p ->
                Text(
                    text = "@${p.handle}",
                    fontSize = 13.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                )
            }

            // Bio
            profile?.description?.takeIf { it.isNotEmpty() }?.let { bio ->
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = bio,
                    fontSize = 14.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 32.dp)
                )
            }

            // Stats
            profile?.let { p ->
                Spacer(modifier = Modifier.height(16.dp))
                Row(
                    horizontalArrangement = Arrangement.spacedBy(24.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    StatItem(count = p.followersCount ?: 0, label = "Followers")
                    StatItem(count = p.followsCount ?: 0, label = "Following")
                    StatItem(count = p.postsCount ?: 0, label = "Posts")
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Action buttons
            Column(
                modifier = Modifier.padding(horizontal = 24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // Message button (hidden for own profile)
                if (!isOwnProfile) {
                    Button(
                        onClick = {
                            onDismiss()
                            onNavigateToDM(nick)
                        },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = FreeqColors.accent,
                            contentColor = MaterialTheme.colorScheme.onPrimary
                        )
                    ) {
                        Icon(
                            Icons.AutoMirrored.Filled.Chat,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Message", fontWeight = FontWeight.SemiBold)
                    }
                }

                // View on Bluesky button
                profile?.let { p ->
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                uriHandler.openUri("https://bsky.app/profile/${p.handle}")
                            },
                        shape = RoundedCornerShape(10.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 12.dp),
                            horizontalArrangement = Arrangement.Center,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                Icons.AutoMirrored.Filled.OpenInNew,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                                tint = MaterialTheme.colorScheme.onBackground
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                "View on Bluesky",
                                fontWeight = FontWeight.Medium,
                                color = MaterialTheme.colorScheme.onBackground
                            )
                        }
                    }
                }

                // The identity claim's evidence: this person's DID and the key
                // they sign with. Reachable for everyone we hold a DID for,
                // including the senders who carry no ✓ — a did:key bot and a
                // relayed stranger have a proof view too, and it says what it
                // can support rather than nothing at all.
                if (!resolvedDid.isNullOrEmpty()) {
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { showIdentityProof = true },
                        shape = RoundedCornerShape(10.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 12.dp),
                            horizontalArrangement = Arrangement.Center,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                Icons.Default.VerifiedUser,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                                tint = MaterialTheme.colorScheme.onBackground
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                "Identity proof",
                                fontWeight = FontWeight.Medium,
                                color = MaterialTheme.colorScheme.onBackground
                            )
                        }
                    }
                }

                // Safety actions (hidden for own profile)
                if (!isOwnProfile) {
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        OutlinedButton(
                            onClick = { showReportDialog = true },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(10.dp),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = FreeqColors.danger
                            )
                        ) {
                            Icon(
                                Icons.Default.Flag,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Report", fontWeight = FontWeight.Medium)
                        }
                        OutlinedButton(
                            onClick = {
                                if (isBlocked) {
                                    appState.unblockUser(nick, resolvedDid)
                                } else {
                                    appState.blockUser(nick, resolvedDid)
                                    appState.errorMessage.value = "Blocked $nick"
                                }
                            },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(10.dp),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = FreeqColors.danger
                            )
                        ) {
                            Icon(
                                Icons.Default.Block,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                if (isBlocked) "Unblock" else "Block",
                                fontWeight = FontWeight.Medium
                            )
                        }
                    }
                }
            }

            // Loading indicator
            if (loading) {
                Spacer(modifier = Modifier.height(16.dp))
                CircularProgressIndicator(
                    modifier = Modifier.size(24.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                    strokeWidth = 2.dp
                )
            }
        }
    }

    // The proof behind the identity claim this card makes — opened from the
    // card's own mark, over the card, so the person stays the subject.
    if (showIdentityProof) {
        VerifiedProofSheet(
            request = ProofRequest.Identity(
                did = claim.did,
                nick = nick,
                handle = profile?.handle,
                displayName = profile?.displayName?.takeIf { it.isNotEmpty() },
                origin = origin,
                account = anchor?.account,
                rowTimeUnix = anchor?.timestamp?.let { (it.time / 1000).toULong() },
                senderPresent = appState.isNickPresent(nick),
                senderLiveDid = if (isOwnProfile) appState.authenticatedDID.value else appState.liveDidForNick(nick),
            ),
            onDismiss = { showIdentityProof = false },
            appState = appState
        )
    }

    // Report reason picker — on choice: report (log) + block + snackbar
    if (showReportDialog) {
        ReportReasonDialog(
            nick = nick,
            onReport = { reason ->
                appState.reportUser(nick, resolvedDid, reason)
                appState.errorMessage.value = "Reported $nick — user blocked"
                showReportDialog = false
            },
            onDismiss = { showReportDialog = false }
        )
    }
}

@Composable
private fun StatItem(count: Int, label: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = formatCount(count),
            fontSize = 16.sp,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onBackground
        )
        Text(
            text = label,
            fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
        )
    }
}

private fun formatCount(n: Int): String {
    if (n >= 1_000_000) return "${n / 1_000_000}M"
    if (n >= 1_000) return "${n / 1_000}K"
    return "$n"
}
