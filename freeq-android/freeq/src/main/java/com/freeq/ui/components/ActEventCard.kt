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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.freeq.ffi.CoordinationEvent
import com.freeq.model.ActAccent
import com.freeq.model.ActCard
import com.freeq.model.ActVerbs
import com.freeq.model.CoordinationCardStyle
import com.freeq.model.actCardNeighbours
import com.freeq.ui.theme.Theme
import java.util.Date

/**
 * The one layout every event card renders through — the web `CardFrame`
 * arrangement: a header strip over a padded body, an optional prev/next
 * footer behind a hairline, an accent edge for marked events, a hairline
 * border and clip. Both the act and coordination families use it; layout
 * decisions live here and nowhere else.
 */
@Composable
fun EventCardFrame(
    icon: String,
    label: String,
    detail: String? = null,
    time: String? = null,
    accent: Color? = null,
    onPrev: (() -> Unit)? = null,
    onNext: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    val dim = MaterialTheme.colorScheme.onSurfaceVariant
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
        // Header strip — the card's only filled band.
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
                .padding(horizontal = 10.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(icon, fontSize = 12.sp)
            Text(
                text = label.uppercase(),
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = dim,
            )
            if (detail != null) {
                Text(
                    text = detail,
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = dim.copy(alpha = 0.6f),
                )
            }
            Spacer(modifier = Modifier.weight(1f))
            if (time != null) {
                Text(text = time, fontSize = 10.sp, color = dim.copy(alpha = 0.5f))
            }
        }

        // Body.
        Column(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(3.dp),
            content = content,
        )

        // Footer, behind a hairline, absent when there is nowhere to go.
        if (onPrev != null || onNext != null) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.5f))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 10.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (onPrev != null) {
                    Text(
                        text = "← prev",
                        fontSize = 11.sp,
                        color = dim.copy(alpha = 0.7f),
                        modifier = Modifier.clickable { onPrev() },
                    )
                }
                Spacer(modifier = Modifier.weight(1f))
                if (onNext != null) {
                    Text(
                        text = "next →",
                        fontSize = 11.sp,
                        color = dim.copy(alpha = 0.7f),
                        modifier = Modifier.clickable { onNext() },
                    )
                }
            }
        }
    }
}

/**
 * One task event, as the line its sender wrote beside it.
 *
 * The event itself rides as a TAGMSG the message list never shows; this card
 * is the line beside it. The headline is the word for the verb that event
 * carried, never one read off the task's state, so a progress report never
 * reads as a claim.
 */
@Composable
fun ActEventCard(card: ActCard, at: Date? = null, onJumpToMessage: ((String) -> Unit)? = null) {
    val uriHandler = LocalUriHandler.current
    val neighbours = actCardNeighbours(card.task, card.event)
    val note = card.event.fields["act-note"]
    val ctx = card.event.fields["act-ctx"]
    val ctxHash = card.event.fields["act-ctx-h"]
    val dim = MaterialTheme.colorScheme.onSurfaceVariant

    EventCardFrame(
        icon = ActVerbs.emoji(card.event.verb),
        label = ActVerbs.headline(card.event.verb),
        detail = shortTaskId(card.task.taskId),
        time = at?.let { formatCardTime(it) },
        accent = accentColor(ActVerbs.accent(card.event.verb)),
        onPrev = neighbours.prev?.let { prev -> onJumpToMessage?.let { jump -> { jump(prev) } } },
        onNext = neighbours.next?.let { next -> onJumpToMessage?.let { jump -> { jump(next) } } },
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
}

/**
 * An agent coordination event (`+freeq.at/event` family) as a card — the
 * Android twin of the other three clients' coordination cards, rendered
 * through the same frame as the act cards.
 */
@Composable
fun CoordinationEventCard(ev: CoordinationEvent, text: String) {
    val style = CoordinationCardStyle.style(ev)
    val dim = MaterialTheme.colorScheme.onSurfaceVariant
    var expanded by remember { mutableStateOf(false) }
    val payload = if (style.expandablePayload) CoordinationCardStyle.prettyPayload(ev.payload) else null

    EventCardFrame(
        icon = style.icon,
        label = style.label,
        detail = ev.taskId?.let { shortTaskId(it) },
        accent = accentColor(style.accent),
    ) {
        if (text.isNotEmpty()) {
            Text(
                text = text,
                fontSize = 14.sp,
                color = when (style.accent) {
                    ActAccent.SUCCESS -> Theme.success
                    ActAccent.FAILURE -> Theme.danger
                    else -> dim
                },
            )
        }
        if (payload != null) {
            Text(
                text = if (expanded) "Hide payload" else "Show payload",
                fontSize = 11.sp,
                color = dim.copy(alpha = 0.7f),
                modifier = Modifier.clickable { expanded = !expanded },
            )
            if (expanded) {
                Text(
                    text = payload,
                    fontSize = 12.sp,
                    fontFamily = FontFamily.Monospace,
                    color = dim,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(5.dp))
                        .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
                        .padding(8.dp),
                )
            }
        }
    }
}

/** Only the moves that put work on a plate, end well, or fail carry an
 *  edge — an edge on every card is an edge that says nothing. */
private fun accentColor(accent: ActAccent): Color? = when (accent) {
    ActAccent.HANDOFF -> Theme.accent
    ActAccent.SUCCESS -> Theme.success
    ActAccent.FAILURE -> Theme.danger
    ActAccent.NONE -> null
}

/** The task id, shortened the way the web's badge shortens it. */
private fun shortTaskId(id: String): String = if (id.length > 10) id.take(10) + "…" else id

private fun formatCardTime(at: Date): String =
    java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault()).format(at)
