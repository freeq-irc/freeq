package com.freeq.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Assignment
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.freeq.model.ActCard
import com.freeq.model.ActVerbs
import com.freeq.model.actCardNeighbours

/**
 * One task event, as the line its sender wrote beside it.
 *
 * A task event rides as a TAGMSG the message list never shows; the line
 * beside it is what a reader sees, and that line becomes this card. Every
 * event keeps a card of its own — the headline is the word for the verb that
 * event carried, never a word read off the task's state, so a progress report
 * never reads as a claim.
 */
@Composable
fun ActEventCard(card: ActCard, onJumpToMessage: ((String) -> Unit)? = null) {
    val uriHandler = LocalUriHandler.current
    val neighbours = actCardNeighbours(card.task, card.event)
    val note = card.event.fields["act-note"]
    val ctx = card.event.fields["act-ctx"]
    val ctxHash = card.event.fields["act-ctx-h"]

    Column(
        modifier = Modifier
            .padding(top = 4.dp)
            .clip(RoundedCornerShape(10.dp))
            .border(
                1.dp,
                MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
                RoundedCornerShape(10.dp),
            )
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(10.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(
                Icons.Default.Assignment,
                contentDescription = null,
                modifier = Modifier.size(14.dp),
                tint = MaterialTheme.colorScheme.primary,
            )
            Text(
                text = ActVerbs.headline(card.event.verb),
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        if (card.task.title.isNotEmpty()) {
            Text(
                text = card.task.title,
                fontSize = 15.sp,
                color = MaterialTheme.colorScheme.onBackground,
            )
        }

        if (!note.isNullOrEmpty()) {
            Text(
                text = note,
                fontSize = 14.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        // The cards either side of this one on the same task, absent at each
        // end. Nothing is offered for a move the home signed: it wrote no
        // line, so there is no card to land on.
        if (onJumpToMessage != null && (neighbours.prev != null || neighbours.next != null)) {
            Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                neighbours.prev?.let { prev ->
                    Text(
                        text = "← prev",
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.clickable { onJumpToMessage(prev) },
                    )
                }
                neighbours.next?.let { next ->
                    Text(
                        text = "next →",
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.clickable { onJumpToMessage(next) },
                    )
                }
            }
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
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                )
            }
        }
    }
}
