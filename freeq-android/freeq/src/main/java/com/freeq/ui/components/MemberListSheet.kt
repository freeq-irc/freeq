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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MemberListSheet(
    members: List<MemberInfo>,
    onDismiss: () -> Unit,
    onMemberClick: (String) -> Unit
) {
    val ops = members.filter { it.isOp }
    val voiced = members.filter { it.isVoiced && !it.isOp }
    val regular = members.filter { !it.isOp && !it.isVoiced }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = false),
        containerColor = MaterialTheme.colorScheme.background,
        dragHandle = { BottomSheetDefaults.DragHandle() }
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 32.dp)
        ) {
            // Header
            Text(
                text = "Members — ${members.size}",
                fontSize = 17.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onBackground,
                modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp)
            )

            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 400.dp),
                contentPadding = PaddingValues(vertical = 8.dp)
            ) {
                if (ops.isNotEmpty()) {
                    item {
                        SheetSectionHeader("Operators", ops.size)
                    }
                    items(ops, key = { "op-${it.nick}" }) { member ->
                        SheetMemberRow(member, onMemberClick)
                    }
                }

                if (voiced.isNotEmpty()) {
                    item {
                        SheetSectionHeader("Voiced", voiced.size)
                    }
                    items(voiced, key = { "v-${it.nick}" }) { member ->
                        SheetMemberRow(member, onMemberClick)
                    }
                }

                if (regular.isNotEmpty()) {
                    item {
                        SheetSectionHeader("Members", regular.size)
                    }
                    items(regular, key = { "m-${it.nick}" }) { member ->
                        SheetMemberRow(member, onMemberClick)
                    }
                }
            }
        }
    }
}

@Composable
private fun SheetSectionHeader(title: String, count: Int) {
    Text(
        text = "$title — $count",
        modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp),
        fontSize = 11.sp,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
        letterSpacing = 1.sp
    )
}

@Composable
private fun SheetMemberRow(member: MemberInfo, onMemberClick: (String) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onMemberClick(member.nick) }
            .padding(horizontal = 24.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        val isAway = member.awayMsg != null

        // Presence dot
        Box(
            modifier = Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(if (isAway) FreeqColors.warning else FreeqColors.success)
        )

        UserAvatar(nick = member.nick, size = 36.dp)

        Column(modifier = Modifier.weight(1f)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                if (member.prefix.isNotEmpty()) {
                    Text(
                        text = member.prefix,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (member.isOp) FreeqColors.warning else FreeqColors.accent
                    )
                }
                Text(
                    text = member.nick,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Medium,
                    color = if (isAway) MaterialTheme.colorScheme.onSurfaceVariant
                        else MaterialTheme.colorScheme.onBackground
                )
                if (AvatarCache.avatarUrl(member.nick) != null) {
                    Icon(
                        Icons.Default.CheckCircle,
                        contentDescription = "AT Protocol identity",
                        tint = FreeqColors.accent,
                        modifier = Modifier.size(14.dp)
                    )
                }
            }
            if (isAway) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
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
                    if (!member.awayMsg.isNullOrEmpty()) {
                        Text(
                            text = member.awayMsg,
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                            maxLines = 1
                        )
                    }
                }
            }
        }
    }
}
