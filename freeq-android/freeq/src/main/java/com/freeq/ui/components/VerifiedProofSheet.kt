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
import com.freeq.model.SignatureVerdict
import com.freeq.model.SigningKeyInfo
import com.freeq.model.VerdictTone
import com.freeq.model.VerificationService
import com.freeq.model.VerifyAnswer
import com.freeq.model.VerifyOutcome
import com.freeq.ui.theme.FreeqColors
import kotlinx.coroutines.delay

/**
 * The differentiator, made tangible. Ask for a signature to be checked and see
 * the actual proof: the DID that IS this person, the key they sign every
 * message with, and the server's real ed25519 check of the message's
 * signature. Mirrors iOS VerifiedProofSheet against the same REST endpoints.
 *
 * The verdict says only what the server supported. A check that could not be
 * made is a fact, never a warning, and only a signature the server found and
 * rejected is spoken about in red.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VerifiedProofSheet(
    /** The sender's DID, when they have one. Guests don't, and the sheet
     *  claims no identity for them. */
    did: String?,
    handle: String? = null,
    displayName: String? = null,
    /** When set, check this specific message's signature. */
    msgId: String? = null,
    onDismiss: () -> Unit,
) {
    var key by remember { mutableStateOf<SigningKeyInfo?>(null) }
    var keyLoading by remember { mutableStateOf(did != null) }
    var verify by remember { mutableStateOf<VerifyAnswer?>(null) }
    var verifying by remember { mutableStateOf(msgId != null) }

    LaunchedEffect(did) {
        val d = did ?: return@LaunchedEffect
        keyLoading = true
        key = VerificationService.fetchSigningKey(d)
        keyLoading = false
    }
    LaunchedEffect(msgId) {
        val id = msgId ?: return@LaunchedEffect
        verifying = true
        var answer = VerificationService.verifyMessage(id)
        // The server starts fetching the signer's key by answering, so this
        // one flavour of can't-check is worth waiting out — briefly.
        var attempts = 0
        while (answer.transient && attempts < 2) {
            attempts++
            delay(1200)
            answer = VerificationService.verifyMessage(id)
        }
        verify = answer
        verifying = false
    }

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp)
                .padding(bottom = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            if (did != null) {
                Icon(
                    Icons.Default.CheckCircle,
                    contentDescription = null,
                    tint = FreeqColors.success,
                    modifier = Modifier.size(64.dp),
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    text = displayName ?: handle?.let { "@$it" } ?: "Verified identity",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    text = "Verified via the AT Protocol",
                    fontSize = 13.sp,
                    color = FreeqColors.success,
                )
                Spacer(Modifier.height(16.dp))
                Text(
                    text = "This is a real, self-owned identity. Its owner holds the key " +
                        "below and signs everything they send — so no one can impersonate " +
                        "them, on freeq or anywhere else on the network.",
                    fontSize = 14.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(20.dp))

                ProofCard(
                    label = "DECENTRALIZED IDENTIFIER",
                    value = did,
                    detail = handle?.let { "resolves to @$it" },
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
                // No DID to speak of — a guest, or someone whose binding this
                // client never learned. The message's signature is still worth
                // asking about; this person's identity is not ours to assert.
                Spacer(Modifier.height(12.dp))
                Text(
                    text = handle?.let { "@$it" } ?: "Unidentified sender",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "No decentralized identity is on file for this sender here.",
                    fontSize = 14.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))
            }

            if (msgId != null) {
                Spacer(Modifier.height(12.dp))
                MessageVerdict(verifying = verifying, verify = verify)
            }
        }
    }
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

/**
 * The checked result for a specific message.
 *
 * Each verdict wears its own weight: green once the server confirmed the
 * signature, red once it found the key and the signature didn't match it, and
 * a plain grey statement for everything it could not determine — including a
 * message nobody signed, which is a fact about a guest and not a complaint.
 */
@Composable
private fun MessageVerdict(verifying: Boolean, verify: VerifyAnswer?) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (verifying || verify == null) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = "Checking this message's signature…",
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                val quiet = MaterialTheme.colorScheme.onSurfaceVariant
                val tint = when (SignatureVerdict.tone(verify.outcome)) {
                    VerdictTone.GOOD -> FreeqColors.success
                    VerdictTone.BAD -> FreeqColors.danger
                    VerdictTone.QUIET -> quiet
                }
                Icon(
                    when (verify.outcome) {
                        VerifyOutcome.DEVICE, VerifyOutcome.SERVER -> Icons.Default.CheckCircle
                        VerifyOutcome.INVALID -> Icons.Default.Warning
                        else -> Icons.Default.Info
                    },
                    contentDescription = null,
                    tint = tint,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = SignatureVerdict.label(verify),
                    fontSize = 12.sp,
                    color = if (verify.isVerified) MaterialTheme.colorScheme.onSurface else tint,
                )
            }
        }
    }
}
