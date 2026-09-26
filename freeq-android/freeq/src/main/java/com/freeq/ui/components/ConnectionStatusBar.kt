package com.freeq.ui.components

import android.os.SystemClock
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.WifiOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.freeq.model.AppState
import com.freeq.model.ConnectionState
import com.freeq.model.ConnectionStatus
import com.freeq.model.DropTimer
import com.freeq.ui.theme.Theme
import kotlinx.coroutines.delay

/**
 * The bar [ConnectionStatus] says to show right now, or null. Counts from
 * each drop (or launch) and ticks only while not registered.
 */
@Composable
internal fun rememberConnectionStatusBar(appState: AppState): ConnectionStatus.Bar? {
    val state by appState.connectionState
    val networkConnected by appState.networkMonitor.isConnected
    val timer = remember { DropTimer() }
    timer.update(state, SystemClock.elapsedRealtime())

    val registered = state == ConnectionState.Registered
    var nowMs by remember { mutableLongStateOf(SystemClock.elapsedRealtime()) }
    LaunchedEffect(registered) {
        while (!registered) {
            nowMs = SystemClock.elapsedRealtime()
            delay(500)
        }
    }

    val seconds = timer.secondsSinceDrop(nowMs) ?: return null
    return ConnectionStatus.bar(state, networkConnected, seconds)
}

/** The slim status bar at the top of the main screen, as on the iPhone, in
 *  the iPhone chat-screen bar's colours: danger offline, warning otherwise,
 *  white text and icons. */
@Composable
internal fun ConnectionStatusBar(
    bar: ConnectionStatus.Bar,
    onSignInAgain: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val background = when (bar.tone) {
        ConnectionStatus.Tone.Danger -> Theme.danger
        ConnectionStatus.Tone.Warning -> Theme.warning
    }
    Surface(color = background, contentColor = Color.White, modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .statusBarsPadding()
                .padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Box(modifier = Modifier.size(14.dp), contentAlignment = Alignment.Center) {
                when (bar.icon) {
                    ConnectionStatus.Icon.Spinner -> CircularProgressIndicator(
                        color = Color.White,
                        modifier = Modifier.size(12.dp),
                        strokeWidth = 1.5.dp
                    )
                    ConnectionStatus.Icon.Offline -> Icon(
                        Icons.Default.WifiOff,
                        contentDescription = null,
                        tint = Color.White
                    )
                    ConnectionStatus.Icon.Retry -> Icon(
                        Icons.Default.Sync,
                        contentDescription = null,
                        tint = Color.White
                    )
                }
            }
            Text(
                bar.text,
                fontSize = 12.sp,
                fontWeight = FontWeight.Medium,
                color = Color.White,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )
            if (bar.signInAgain) {
                TextButton(
                    onClick = onSignInAgain,
                    contentPadding = PaddingValues(horizontal = 8.dp),
                    modifier = Modifier.height(28.dp)
                ) {
                    Text(
                        "Sign in again",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = Color.White
                    )
                }
            }
        }
    }
}
