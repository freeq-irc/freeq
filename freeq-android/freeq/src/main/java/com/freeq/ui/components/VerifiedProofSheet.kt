package com.freeq.ui.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.freeq.ffi.VerdictState
import com.freeq.model.AppState
import com.freeq.model.FfiVerdict
import com.freeq.model.SenderIdentity
import com.freeq.model.SignatureVerdict
import com.freeq.model.VerdictTone
import com.freeq.ui.theme.FreeqColors
import kotlinx.coroutines.delay

/**
 * What the sheet was opened to answer. Who a person is and whether one message
 * was signed are claims about different subjects, so they never share a
 * surface: each gesture says which of the two it is asking about, and the sheet
 * shows that one and nothing else.
 */
sealed interface ProofRequest {
    /** Who this person is: the DID that identifies them and the key they sign
     *  with. Says nothing about any particular message. */
    data class Identity(
        val did: String?,
        val nick: String? = null,
        val handle: String? = null,
        val displayName: String? = null,
        /** Set when we only know this person through a relaying peer. */
        val origin: String? = null,
        /** The anchoring message's evidence, when opened from a row. */
        val account: String? = null,
        val rowTimeUnix: ULong? = null,
        val senderPresent: Boolean = false,
        val senderLiveDid: String? = null,
        /** When the sheet was opened from a message row, that message's own
         *  verdict renders below the identity — one sheet, content follows
         *  the message. */
        val msgId: String? = null,
        val signed: Boolean = false,
        /** That message's verdict, as the SDK settled it. */
        val verdict: FfiVerdict? = null,
    ) : ProofRequest

    /** Whether this one message's signature holds up. Says nothing about who
     *  the sender is — that question has its own surface. */
    data class Message(
        val msgId: String,
        /** A signature was on the wire. Without one there was nothing to
         *  check, which is a fact and not a fault. */
        val signed: Boolean,
        /** What the SDK made of it, checked on this device. */
        val verdict: FfiVerdict? = null,
    ) : ProofRequest
}

/**
 * The differentiator, made tangible: the DID that IS this person and the key
 * they sign with, or the server's real ed25519 check of one message's
 * signature — whichever was asked for. Mirrors iOS VerifiedProofSheet against
 * the same REST endpoints.
 *
 * The verdict says only what the server supported. A check that could not be
 * made is a fact, never a warning, and only a signature the server found and
 * rejected is spoken about in red.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VerifiedProofSheet(
    request: ProofRequest,
    onDismiss: () -> Unit,
    /** Needed only by the identity question, and only so this sheet can ask
     *  who someone is when nothing is on file yet — and say that an ask is out
     *  rather than declaring them unknown before anyone asked. */
    appState: AppState? = null,
) {
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp)
                .padding(bottom = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            when (request) {
                is ProofRequest.Identity -> IdentityProof(request, appState)
                is ProofRequest.Message ->
                    MessageProof(request.msgId, request.signed, request.verdict)
            }
        }
    }
}

/**
 * Who this person is — never a word about any single message.
 *
 * The claim it draws is the one the message row already draws, from the same
 * rule: a mark only for an identity the AT Protocol resolves, nothing claimed
 * for a sender we know only through a relaying peer, and no AT-Protocol claim
 * over a self-issued key. Accent, never success — green belongs to proof that
 * a sender's own device signed something.
 */
@Composable
private fun IdentityProof(request: ProofRequest.Identity, appState: AppState?) {
    val lookup = request.nick?.let { appState?.personLookup(it) }
        ?: com.freeq.ffi.PersonLookup.NOT_ASKED
    val claim = com.freeq.ffi.claimForSender(
        com.freeq.ffi.MessageClaimInput(
            account = request.account,
            origin = request.origin,
            senderPresent = request.senderPresent,
            senderLiveDid = request.senderLiveDid ?: request.did,
            rowTimeUnix = request.rowTimeUnix,
        ),
        lookup,
    )
    val did = claim.did

    // If we can't name them yet, ask — otherwise this sheet would answer
    // "unknown" without anyone having asked anything.
    LaunchedEffect(request.nick, did, request.origin) {
        if (did == null && request.origin == null) {
            request.nick?.let { appState?.lookUpIdentity(it) }
        }
    }

    val name = SenderIdentity.title(request.displayName, request.handle, request.nick)

    if (claim.showsMark) {
        Icon(
            Icons.Default.CheckCircle,
            contentDescription = null,
            tint = FreeqColors.accent,
            modifier = Modifier.size(64.dp),
        )
    }
    Spacer(Modifier.height(12.dp))

    Text(
        text = name,
        fontSize = 20.sp,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.onSurface,
    )

    // Every state that has words names itself. Only the resolvable claim wears
    // the accent; the rest are ordinary facts and are coloured like ones. An
    // ask still out shows as motion instead — no words at all.
    if (claim.isPending) {
        Spacer(Modifier.height(8.dp))
        CircularProgressIndicator(
            modifier = Modifier.size(20.dp),
            strokeWidth = 2.dp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    claim.label?.let { label ->
        Text(
            text = label,
            fontSize = 13.sp,
            color = if (claim.showsMark) FreeqColors.accent
            else MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    claim.line?.let { line ->
        Spacer(Modifier.height(16.dp))
        Text(
            text = line,
            fontSize = 14.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }

    if (did != null) {
        Spacer(Modifier.height(20.dp))
        ProofCard(
            label = "DECENTRALIZED IDENTIFIER",
            value = did,
            detail = request.handle?.let { "resolves to @$it" },
            copyable = true,
        )
    } else {
        Spacer(Modifier.height(8.dp))
    }

    // Opened from a message row: that message's own verdict, below the
    // identity it anchors.
    if (request.msgId != null) {
        Spacer(Modifier.height(20.dp))
        MessageProof(request.msgId, request.signed, request.verdict)
    }
}

/**
 * One message's signature, and nothing else. Whoever sent it is a separate
 * question with a separate surface, so nothing here identifies them — a sender
 * this client knows perfectly well is neither claimed nor disowned.
 */
@Composable
private fun MessageProof(msgId: String, signed: Boolean, verdict: FfiVerdict?) {
    // Nothing is fetched here. The check was made on this device when the line
    // landed; a verdict that took a moment to settle replaces it in place, so
    // the later of the two is the answer.
    val settled = SignatureVerdict.checked[msgId] ?: verdict
    val quiet = MaterialTheme.colorScheme.onSurfaceVariant
    val checking = settled?.state == VerdictState.PENDING || (settled == null && signed)
    val tint = when (settled?.let { SignatureVerdict.tone(it.state) }) {
        VerdictTone.GOOD -> FreeqColors.success
        VerdictTone.BAD -> FreeqColors.danger
        else -> quiet
    }

    // The same shape the identity side uses, so the two read as one family:
    // the glyph carries the answer, the heading names it, one line says what
    // it means.
    if (checking) {
        CircularProgressIndicator(
            modifier = Modifier.size(48.dp),
            strokeWidth = 4.dp,
            color = quiet,
        )
    } else {
        Icon(
            when (settled?.state) {
                VerdictState.DEVICE -> Icons.Default.CheckCircle
                VerdictState.INVALID, VerdictState.RETIRED -> Icons.Default.Warning
                else -> Icons.Default.Info
            },
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(64.dp),
        )
    }
    Spacer(Modifier.height(12.dp))
    Text(
        text = when {
            settled != null -> SignatureVerdict.heading(settled.state)
            signed -> "Checking signature…"
            else -> SignatureVerdict.heading(VerdictState.UNSIGNED)
        },
        fontSize = 20.sp,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.onSurface,
    )
    // The sentence is the SDK's — the same words every freeq client shows for
    // this state.
    if (settled != null) {
        Spacer(Modifier.height(16.dp))
        Text(
            text = settled.sentence,
            fontSize = 14.sp,
            color = tint,
        )
    }
    Spacer(Modifier.height(8.dp))
}

@Composable
private fun ProofCard(
    label: String,
    value: String,
    detail: String?,
    copyable: Boolean,
) {
    val clipboard = LocalClipboardManager.current
    var copied by remember { mutableStateOf(false) }
    LaunchedEffect(copied) {
        if (copied) {
            delay(1400)
            copied = false
        }
    }

    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = label,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.weight(1f))
                if (copyable) {
                    Text(
                        text = if (copied) "Copied" else "Copy",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = if (copied) FreeqColors.success else FreeqColors.accent,
                        modifier = Modifier.clickable {
                            clipboard.setText(AnnotatedString(value))
                            copied = true
                        },
                    )
                }
            }
            Spacer(Modifier.height(8.dp))
            Text(
                text = value,
                fontSize = 13.sp,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            if (detail != null) {
                Spacer(Modifier.height(4.dp))
                Text(
                    text = detail,
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
