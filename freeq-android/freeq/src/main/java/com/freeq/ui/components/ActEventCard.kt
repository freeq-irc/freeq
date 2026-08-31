package com.freeq.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.freeq.model.ActAccent
import com.freeq.model.ActCard
import com.freeq.model.ActVerbs
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
 * Laid out like the web client's card (`freeq-app/src/components/ActCards.tsx`
 * and its `CardFrame`): a header strip carrying the icon, the headline, the
 * shortened task id and the time, over a body of title, note and context link.
 * Same structure and spacing; the colours are this app's own.
 */
@Composable
fun ActEventCard(card: ActCard, at: Date? = null, onJumpToMessage: ((String) -> Unit)? = null) {
    val uriHandler = LocalUriHandler.current
    val neighbours = actCardNeighbours(card.task, card.event)
    val note = card.event.fields["act-note"]
    val ctx = card.event.fields["act-ctx"]
    val ctxHash = card.event.fields["act-ctx-h"]
    val dim = MaterialTheme.colorScheme.onSurfaceVariant
    // Only the moves that put work on a plate, end well, or fail carry an
    // edge — an edge on every card is an edge that says nothing.
    val accent: Color? = when (ActVerbs.accent(card.event.verb)) {
        ActAccent.HANDOFF -> Theme.accent
        ActAccent.SUCCESS -> Theme.success
        ActAccent.FAILURE -> Theme.danger
        ActAccent.NONE -> null
    }
    val edge = 2.dp

    Column(
        modifier = Modifier
            .padding(top = 4.dp)
            .clip(RoundedCornerShape(8.dp))
            // Painted over the content, so the header's own tint does not
            // wash the edge out where the two overlap.
            .drawWithContent {
                drawContent()
                accent?.let { drawRect(it, size = Size(edge.toPx(), size.height)) }
            }
            .border(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.5f), RoundedCornerShape(8.dp)),
    ) {
        // Header strip.
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
                color = dim,
            )
            Text(
                text = shortTaskId(card.task.taskId),
                fontSize = 10.sp,
                fontFamily = FontFamily.Monospace,
                color = dim.copy(alpha = 0.6f),
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

        // The cards either side of this one on the same task, absent at each
        // end. Nothing is offered for a move the server signed: it wrote no
        // line, so there is no card to land on. They sit under the body behind
        // a hairline, so the header stays the card's only filled strip.
        if (onJumpToMessage != null && (neighbours.prev != null || neighbours.next != null)) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.5f))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 10.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                neighbours.prev?.let { prev ->
                    Text(
                        text = "← prev",
                        fontSize = 11.sp,
                        color = dim.copy(alpha = 0.7f),
                        modifier = Modifier.clickable { onJumpToMessage(prev) },
                    )
                }
                Spacer(modifier = Modifier.weight(1f))
                neighbours.next?.let { next ->
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

/** The task id, shortened the way the web's badge shortens it. */
private fun shortTaskId(id: String): String = if (id.length > 10) id.take(10) + "…" else id

private fun formatCardTime(at: Date): String =
    java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault()).format(at)
