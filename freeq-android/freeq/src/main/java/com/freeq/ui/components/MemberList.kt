package com.freeq.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.freeq.model.AvatarCache
import com.freeq.model.MemberInfo
import com.freeq.ui.theme.FreeqColors

@Composable
fun MemberList(
    members: List<MemberInfo>,
    onMemberClick: ((String) -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    val ops = members.filter { it.isOp }
    val voiced = members.filter { it.isVoiced && !it.isOp }
    val regular = members.filter { !it.isOp && !it.isVoiced }

    LazyColumn(
        modifier = modifier.fillMaxHeight(),
        contentPadding = PaddingValues(vertical = 8.dp)
    ) {
        if (ops.isNotEmpty()) {
            item {
                SectionHeader("Operators", ops.size)
            }
            items(ops, key = { "op-${it.nick}" }) { member ->
                MemberRow(member, onMemberClick)
            }
        }

        if (voiced.isNotEmpty()) {
            item {
                SectionHeader("Voiced", voiced.size)
            }
            items(voiced, key = { "v-${it.nick}" }) { member ->
                MemberRow(member, onMemberClick)
            }
        }

        if (regular.isNotEmpty()) {
            item {
                SectionHeader("Members", regular.size)
            }
            items(regular, key = { "m-${it.nick}" }) { member ->
                MemberRow(member, onMemberClick)
            }
        }
    }
}

@Composable
private fun SectionHeader(title: String, count: Int) {
    Text(
        text = "$title — $count",
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
        fontSize = 12.sp,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
        letterSpacing = 0.5.sp
    )
}

@Composable
private fun MemberRow(member: MemberInfo, onMemberClick: ((String) -> Unit)? = null) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .let { if (onMemberClick != null) it.clickable { onMemberClick(member.nick) } else it }
            .padding(horizontal = 16.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        val isAway = member.isAway
        val awayText = member.awayText

        // Presence dot — yellow if away, green if available
        Box(
            modifier = Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(if (isAway) FreeqColors.warning else FreeqColors.success)
        )

        UserAvatar(nick = member.nick, size = 32.dp)

        Column {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                if (member.prefix.isNotEmpty()) {
                    Text(
                        text = member.prefix,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (member.isOp) FreeqColors.warning else FreeqColors.accent
                    )
                }
                Text(
                    text = member.nick,
                    fontSize = 14.sp,
                    color = if (isAway) MaterialTheme.colorScheme.onSurfaceVariant
                        else MaterialTheme.colorScheme.onBackground
                )
                if (AvatarCache.avatarUrl(member.nick) != null) {
                    Icon(
                        Icons.Default.CheckCircle,
                        contentDescription = "AT Protocol identity",
                        tint = FreeqColors.accent,
                        modifier = Modifier.size(13.dp)
                    )
                }
                // Only when the server said so; unlabelled stays a person.
                if (member.isAgent) {
                    Icon(
                        Icons.Outlined.Memory,
                        contentDescription = "Agent",
                        tint = FreeqColors.accent,
                        modifier = Modifier.size(13.dp)
                    )
                }
                if (isAway) {
                    Surface(
                        shape = RoundedCornerShape(4.dp),
                        color = FreeqColors.warning.copy(alpha = 0.15f)
                    ) {
                        Text(
                            text = "Away",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = FreeqColors.warning,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 1.dp)
                        )
                    }
                }
            }
            // What it is doing right now, if it says. An idle agent shows nothing.
            member.activityLabel?.let {
                Text(
                    text = it,
                    fontSize = 12.sp,
                    color = FreeqColors.accent,
                    maxLines = 1
                )
            }
            // Away message text
            if (!awayText.isNullOrEmpty()) {
                Text(
                    text = awayText,
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                    maxLines = 1
                )
            }
        }
    }
}
