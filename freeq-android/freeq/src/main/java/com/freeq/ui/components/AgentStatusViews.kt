package com.freeq.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.freeq.model.AgentStatus
import com.freeq.ui.theme.FreeqColors

/** "AGENT" pill beside a name, so a bot never passes for a person at a
 *  glance. Only shown when the server said so — unlabelled stays a person. */
@Composable
fun AgentBadge(actorClass: String?, modifier: Modifier = Modifier) {
    val external = actorClass == "external_agent"
    Row(
        modifier = modifier
            .background(FreeqColors.accent.copy(alpha = 0.14f), RoundedCornerShape(4.dp))
            .padding(horizontal = 5.dp, vertical = 1.dp)
            .semantics { contentDescription = if (external) "External agent" else "Agent" },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(2.dp)
    ) {
        Icon(
            Icons.Outlined.Memory,
            contentDescription = null,
            tint = FreeqColors.accent,
            modifier = Modifier.size(10.dp)
        )
        Text(
            text = if (external) "EXT AGENT" else "AGENT",
            fontSize = 9.sp,
            fontWeight = FontWeight.Bold,
            color = FreeqColors.accent,
            letterSpacing = 0.4.sp,
            maxLines = 1
        )
    }
}

/** What an agent is doing, as a sentence, then where — wrapped, never cut
 *  off, selectable so a long branch can be copied. Draws nothing when the
 *  status says neither. */
@Composable
fun AgentActivityCard(status: AgentStatus, modifier: Modifier = Modifier) {
    val facts = status.facts
    if (status.doing == null && facts.isEmpty()) return
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(FreeqColors.accent.copy(alpha = 0.07f), RoundedCornerShape(10.dp))
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(
            text = AgentStatus.label(status.state)?.let { "Activity · $it" } ?: "Activity",
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            color = FreeqColors.accent
        )
        SelectionContainer {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                status.doing?.let {
                    Text(
                        text = it,
                        fontSize = 14.sp,
                        color = MaterialTheme.colorScheme.onBackground
                    )
                }
                for ((label, value) in facts) {
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text(
                            text = label,
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                            modifier = Modifier.width(56.dp)
                        )
                        Text(
                            text = value,
                            fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }
        }
    }
}
