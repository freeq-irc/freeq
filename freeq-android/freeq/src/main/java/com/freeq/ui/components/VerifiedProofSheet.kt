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
import com.freeq.model.IdentityClaim
import com.freeq.model.SenderIdentity
import com.freeq.model.SignatureVerdict
import com.freeq.model.SigningKeyInfo
import com.freeq.model.VerdictTone
import com.freeq.model.VerificationService
import com.freeq.model.VerifyAnswer
import com.freeq.model.VerifyOutcome
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
    ) : ProofRequest

    /** Whether this one message's signature holds up. Says nothing about who
     *  the sender is — that question has its own surface. */
    data class Message(
        val msgId: String,
        /** A signature was on the wire. Without one there is nothing to ask
         *  the server, and asking anyway returns a can't-check that reads
         *  like a fault where there is none. */
        val signed: Boolean,
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
                is ProofRequest.Identity -> IdentityProof(request)
                is ProofRequest.Message -> MessageProof(request.msgId, request.signed)
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
private fun IdentityProof(request: ProofRequest.Identity) {
    val did = request.did
    val claim = SenderIdentity.claim(did, request.origin)
    var key by remember { mutableStateOf<SigningKeyInfo?>(null) }
    var keyLoading by remember { mutableStateOf(did != null) }

    LaunchedEffect(did) {
        val d = did ?: return@LaunchedEffect
        keyLoading = true
        key = VerificationService.fetchSigningKey(d)
        keyLoading = false
    }

    val name = SenderIdentity.title(request.displayName, request.handle, request.nick)

    if (claim == IdentityClaim.AT_PROTOCOL) {
        Icon(
            Icons.Default.CheckCircle,
            contentDescription = null,
            tint = FreeqColors.accent,
            modifier = Modifier.size(64.dp),
        )
        Spacer(Modifier.height(12.dp))
    } else {
        Spacer(Modifier.height(12.dp))
    }

    Text(
        text = name,
        fontSize = 20.sp,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.onSurface,
    )

    when (claim) {
        IdentityClaim.AT_PROTOCOL -> {
            Text(
                text = "AT Protocol identity",
                fontSize = 13.sp,
                color = FreeqColors.accent,
            )
            Spacer(Modifier.height(16.dp))
            Text(
                text = "This identifier is theirs, not this server's to grant or " +
                    "revoke, and it resolves to the same person anywhere on the " +
                    "network.",
                fontSize = 14.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        IdentityClaim.SELF_ISSUED_KEY -> {
            Spacer(Modifier.height(8.dp))
            Text(
                text = "A key its holder issued to itself. Nothing on the AT " +
                    "Protocol stands behind it, so this is an identifier and not " +
                    "an identity.",
                fontSize = 14.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        IdentityClaim.NONE -> {
            Spacer(Modifier.height(8.dp))
            Text(
                text = request.origin?.let {
                    "Relayed via $it — this server did not verify this identity."
                } ?: "No decentralized identifier is on file for this sender here.",
                fontSize = 14.sp,
                color = if (request.origin != null) FreeqColors.warning
                else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }

    if (did != null) {
        Spacer(Modifier.height(20.dp))
        ProofCard(
            label = "DECENTRALIZED IDENTIFIER",
            value = did,
            detail = request.handle?.let { "resolves to @$it" },
            copyable = true,
        )
        Spacer(Modifier.height(12.dp))
        if (key != null) {
            ProofCard(
                label = "MESSAGE SIGNING KEY",
                value = key!!.publicKey,
                detail = "${key!!.algorithm.uppercase()} · ${key!!.sourceLabel}",
                copyable = false,
            )
        } else if (keyLoading) {
            CircularProgressIndicator(
                modifier = Modifier.size(20.dp),
                strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    } else {
        Spacer(Modifier.height(8.dp))
    }
}

/**
 * One message's signature, and nothing else. Whoever sent it is a separate
 * question with a separate surface, so nothing here identifies them — a sender
 * this client knows perfectly well is neither claimed nor disowned.
 */
@Composable
private fun MessageProof(msgId: String, signed: Boolean) {
    var verify by remember { mutableStateOf<VerifyAnswer?>(null) }
    var retrying by remember { mutableStateOf(false) }

    LaunchedEffect(msgId) {
        if (!signed) return@LaunchedEffect
        var answer = VerificationService.verifyMessage(msgId)
        // The server starts fetching the signer's key by answering, so this
        // one flavour of can't-check is worth waiting out — briefly. It reads
        // as in-progress only while we are actually going to ask again; after
        // that it is an ordinary can't-check.
        var attempts = 0
        while (answer.transient && attempts < 2) {
            attempts++
            retrying = true
            verify = answer
            delay(1200)
            answer = VerificationService.verifyMessage(msgId)
        }
        retrying = false
        verify = answer
    }

    val answer = verify
    val quiet = MaterialTheme.colorScheme.onSurfaceVariant
    val copy = when {
        !signed -> SignatureVerdict.UNSIGNED
        answer == null -> null
        else -> SignatureVerdict.copy(answer, retrying)
    }
    val tint = when {
        answer == null || retrying -> quiet
        else -> when (SignatureVerdict.tone(answer.outcome)) {
            VerdictTone.GOOD -> FreeqColors.success
            VerdictTone.BAD -> FreeqColors.danger
            VerdictTone.QUIET -> quiet
        }
    }

    // The same shape the identity side uses, so the two read as one family:
    // the glyph carries the answer, the heading names it, one line says what
    // it means.
    if (signed && (answer == null || retrying)) {
        CircularProgressIndicator(
            modifier = Modifier.size(48.dp),
            strokeWidth = 4.dp,
            color = quiet,
        )
    } else {
        Icon(
            when {
                !signed -> Icons.Default.Info
                answer?.outcome == VerifyOutcome.DEVICE -> Icons.Default.CheckCircle
                answer?.outcome == VerifyOutcome.INVALID -> Icons.Default.Warning
                else -> Icons.Default.Info
            },
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(64.dp),
        )
    }
    Spacer(Modifier.height(12.dp))
    Text(
        text = copy?.heading ?: "Checking signature…",
        fontSize = 20.sp,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.onSurface,
    )
    if (copy != null) {
        Spacer(Modifier.height(16.dp))
        Text(
            text = copy.line,
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
