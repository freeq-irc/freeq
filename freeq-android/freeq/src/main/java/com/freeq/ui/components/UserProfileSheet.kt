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
import androidx.compose.material.icons.filled.Warning
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
import com.freeq.model.AppState
import com.freeq.model.AvatarCache
import com.freeq.model.BlueskyProfile
import com.freeq.ui.theme.FreeqColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UserProfileSheet(
    nick: String,
    appState: AppState,
    origin: String? = null,
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

    LaunchedEffect(nick) {
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
            // Federated provenance warning — opened from a relayed message.
            // The sender is peer-vouched by {origin}, not verified here, so we
            // warn and suppress the local verified badge below.
            origin?.let { o ->
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    color = FreeqColors.warning.copy(alpha = 0.15f)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 10.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Icon(
                            Icons.Default.Warning,
                            contentDescription = null,
                            tint = FreeqColors.warning,
                            modifier = Modifier.size(16.dp)
                        )
                        Text(
                            text = "Relayed via $o — this server did not verify this identity.",
                            fontSize = 12.sp,
                            color = FreeqColors.warning
                        )
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
            }

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
                if (profile != null && origin == null) {
                    Icon(
                        Icons.Default.CheckCircle,
                        contentDescription = "Verified — tap for the proof",
                        tint = FreeqColors.accent,
                        modifier = Modifier
                            .size(18.dp)
                            .clickable { showIdentityProof = true }
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
                did = resolvedDid,
                handle = profile?.handle,
                displayName = profile?.displayName?.takeIf { it.isNotEmpty() },
                origin = origin
            ),
            onDismiss = { showIdentityProof = false }
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
