package com.freeq.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.freeq.ffi.CoordinationEvent
import com.freeq.model.ActRegister
import com.freeq.model.ActCard
import com.freeq.model.ActVerbs
import com.freeq.model.EventCardPayload
import com.freeq.model.SealPanelCopy
import com.freeq.model.actCardNeighbours
import com.freeq.ui.theme.Theme
import java.util.Date

/**
 * One task event, as the line its sender wrote beside it.
 *
 * The event itself rides as a TAGMSG the message list never shows; this card
 * is the line beside it. The headline is the word for the verb that event
 * carried, never one read off the task's state, so a progress report never
 * reads as a claim.
 *
 * An act card is the coloured class: one hue, taken from the register of the
 * state its step lands the action in, on the headline word, a left edge every
 * act card carries, and the border. The generic event card wears neither, and
 * the edge is how a reader tells the two apart.
 */
@Composable
fun ActEventCard(card: ActCard, at: Date? = null, onJumpToMessage: ((String) -> Unit)? = null) {
    val uriHandler = LocalUriHandler.current
    val neighbours = actCardNeighbours(card.task, card.event)
    val note = card.event.fields["act-note"]
    val ctx = card.event.fields["act-ctx"]
    val ctxHash = card.event.fields["act-ctx-h"]
    val kind = card.event.fields["act"] ?: card.task.kind
    val dim = MaterialTheme.colorScheme.onSurfaceVariant
    // A system verb draws no card at all, so the fallback is only ever reached
    // by a verb the rules file has not been taught.
    val hue = registerColor(ActVerbs.register(card.event.verb) ?: ActRegister.NEUTRAL_END)
    var sealOpen by remember { mutableStateOf(false) }
    val edge = 3.dp

    Column(
        modifier = Modifier
            .padding(top = 4.dp)
            .clip(RoundedCornerShape(8.dp))
            // Painted over the content, so the header's own tint does not wash
            // the edge out where the two overlap.
            .drawWithContent {
                drawContent()
                drawRect(hue, size = Size(edge.toPx(), size.height))
            }
            .border(1.dp, hue.copy(alpha = 0.3f), RoundedCornerShape(8.dp)),
    ) {
        // Header strip — the card's only filled band.
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
                .padding(horizontal = 10.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(ActVerbs.emoji(card.event.verb), fontSize = 12.sp)
            Text(
                text = ActVerbs.headline(card.event.verb).uppercase(),
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = hue,
            )
            Text(
                text = shortTaskId(card.task.taskId),
                fontSize = 10.sp,
                fontFamily = FontFamily.Monospace,
                color = dim.copy(alpha = 0.6f),
            )
            // The seal: monochrome always, never the card's hue — a seal that
            // borrowed the hue would read as part of the outcome rather than
            // as a statement about the rules.
            Icon(
                imageVector = Icons.Filled.Verified,
                contentDescription = "What the server enforced",
                tint = dim,
                modifier = Modifier
                    .size(14.dp)
                    .clickable { sealOpen = !sealOpen },
            )
            Spacer(modifier = Modifier.weight(1f))
            if (at != null) {
                Text(text = formatCardTime(at), fontSize = 10.sp, color = dim.copy(alpha = 0.5f))
            }
        }


        // Body.
        Column(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(3.dp),
        ) {
            if (card.task.title.isNotEmpty()) {
                Text(
                    text = card.task.title,
                    fontSize = 14.sp,
                    color = MaterialTheme.colorScheme.onBackground,
                )
            }
            if (!note.isNullOrEmpty()) {
                Text(text = note, fontSize = 14.sp, color = dim)
            }
            if (!ctx.isNullOrEmpty()) {
                Text(
                    text = ctx,
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.clickable { uriHandler.openUri(ctx) },
                )
                // The hash is what the signature covers, so it rides along for
                // anyone checking the bytes they fetched.
                if (!ctxHash.isNullOrEmpty()) {
                    Text(
                        text = ctxHash,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = dim.copy(alpha = 0.6f),
                    )
                }
            }
        }

        if (sealOpen) {
            SealPanel(kind = kind, verb = card.event.verb)
        }

        // Footer, behind a hairline, absent when there is nowhere to go.
        val prev = neighbours.prev
        val next = neighbours.next
        if (onJumpToMessage != null && (prev != null || next != null)) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.5f))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 10.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (prev != null) {
                    Text(
                        text = "← prev",
                        fontSize = 11.sp,
                        color = dim.copy(alpha = 0.7f),
                        modifier = Modifier.clickable { onJumpToMessage(prev) },
                    )
                }
                Spacer(modifier = Modifier.weight(1f))
                if (next != null) {
                    Text(
                        text = "next →",
                        fontSize = 11.sp,
                        color = dim.copy(alpha = 0.7f),
                        modifier = Modifier.clickable { onJumpToMessage(next) },
                    )
                }
            }
        }
    }
}

/**
 * The disclosure behind the seal: what the server enforced on this one step.
 *
 * An expandable panel inside the card rather than a bottom sheet, so the words
 * stay beside the step they are about. The sentence is picked off the role the
 * rules file gives the verb, never off the verb's name and never off the kind;
 * a verb the rules file does not name has no rule about a person to state, so
 * the panel states none.
 *
 * There is no link to a full history here: this client has no task timeline
 * surface to open.
 */
@Composable
private fun SealPanel(kind: String, verb: String) {
    val dim = MaterialTheme.colorScheme.onSurfaceVariant
    HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.5f))
    Column(
        modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            text = SealPanelCopy.header(kind),
            fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold,
            color = dim,
        )
        SealPanelCopy.sentence(verb)?.let { sentence ->
            Text(text = sentence, fontSize = 11.sp, color = dim.copy(alpha = 0.8f))
        }
    }
}

/**
 * A coordination event as a card — one card for every event type there is.
 *
 * There is no list of types that card and no per-type face, so an event this
 * client has never been taught reads exactly like one it knows. Grayscale and
 * edgeless throughout: colour and a left edge belong to the act cards, and are
 * how a reader tells the two classes apart.
 */
@Composable
fun CoordinationEventCard(ev: CoordinationEvent, text: String, at: Date? = null) {
    val dim = MaterialTheme.colorScheme.onSurfaceVariant
    val rows = EventCardPayload.rows(ev.payload)

    Column(
        modifier = Modifier
            .padding(top = 4.dp)
            .clip(RoundedCornerShape(8.dp))
            .border(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.5f), RoundedCornerShape(8.dp)),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
                .padding(horizontal = 10.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text("\u25C7", fontSize = 12.sp, color = dim)
            Text(
                text = ev.eventType.lowercase(),
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace,
                color = dim,
            )
            Spacer(modifier = Modifier.weight(1f))
            if (at != null) {
                Text(text = formatCardTime(at), fontSize = 10.sp, color = dim.copy(alpha = 0.5f))
            }
        }

        Column(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(3.dp),
        ) {
            if (text.isNotEmpty()) {
                Text(text = text, fontSize = 14.sp, color = dim)
            }
            for (row in rows) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = row.key,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace,
                        color = dim.copy(alpha = 0.7f),
                    )
                    Text(
                        text = row.value,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace,
                        color = dim,
                        // A long value scrolls inside its own row rather than
                        // growing the card without bound.
                        maxLines = 6,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f).heightIn(max = 96.dp),
                    )
                }
            }
        }
    }
}

/** The hue each register wears, in this client's own tokens. */
private fun registerColor(register: ActRegister): Color = when (register) {
    ActRegister.NEW -> Theme.accent
    ActRegister.IN_PROGRESS -> Theme.blue
    ActRegister.ENDED_WELL -> Theme.success
    ActRegister.DID_NOT_END_WELL -> Theme.danger
    ActRegister.NEUTRAL_END -> Theme.warning
}

/** The task id, shortened the way the web's badge shortens it. */
private fun shortTaskId(id: String): String = if (id.length > 10) id.take(10) + "…" else id

private fun formatCardTime(at: Date): String =
    java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault()).format(at)
