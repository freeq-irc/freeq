package com.freeq.ui.screens

import android.net.Uri
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.foundation.Image
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.browser.customtabs.CustomTabsIntent
import com.freeq.model.AppState
import com.freeq.model.ConnectionState
import com.freeq.model.ServerConfig
import com.freeq.ui.theme.FreeqColors
import com.freeq.ui.theme.Theme
import java.net.URLEncoder

@Composable
fun ConnectScreen(appState: AppState) {
    var handle by remember { mutableStateOf("") }
    var showGuestLogin by remember { mutableStateOf(false) }
    var guestNick by remember { mutableStateOf("") }
    var guestServer by remember { mutableStateOf(ServerConfig.ircServer) }
    var localError by remember { mutableStateOf<String?>(null) }

    val connectionState by appState.connectionState
    val errorMessage by appState.errorMessage
    val focusManager = LocalFocusManager.current
    val keyboardController = LocalSoftwareKeyboardController.current
    val context = LocalContext.current

    val isLoading = connectionState == ConnectionState.Connecting

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(FreeqColors.bgPrimaryDark, Color(0xFF0F0F1E))
                )
            )
            .clickable(
                indication = null,
                interactionSource = remember { MutableInteractionSource() }
            ) {
                focusManager.clearFocus()
                keyboardController?.hide()
            }
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(80.dp))

            // Logo
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.animateContentSize()
            ) {
                Box(contentAlignment = Alignment.Center) {
                    // Glow
                    Box(
                        modifier = Modifier
                            .size(140.dp)
                            .clip(CircleShape)
                            .background(FreeqColors.accent.copy(alpha = 0.15f))
                            .blur(30.dp)
                    )
                    // Logo
                    Image(
                        painter = painterResource(id = com.freeq.R.drawable.freeq_logo),
                        contentDescription = "freeq logo",
                        modifier = Modifier
                            .size(100.dp)
                            .clip(CircleShape)
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "freeq",
                    fontSize = 36.sp,
                    fontWeight = FontWeight.Bold,
                    color = FreeqColors.textPrimaryDark
                )

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = "Decentralized chat",
                    fontSize = 15.sp,
                    color = FreeqColors.textSecondaryDark
                )
            }

            Spacer(modifier = Modifier.height(40.dp))

            // Card
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = FreeqColors.bgSecondaryDark),
                border = CardDefaults.outlinedCardBorder().copy(
                    brush = Brush.linearGradient(
                        listOf(FreeqColors.borderDark, FreeqColors.borderDark)
                    )
                )
            ) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    verticalArrangement = Arrangement.spacedBy(20.dp)
                ) {
                    if (!showGuestLogin) {
                        // ── Bluesky Login ──
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                text = "BLUESKY HANDLE",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = FreeqColors.textMutedDark,
                                letterSpacing = 1.sp
                            )

                            OutlinedTextField(
                                value = handle,
                                onValueChange = { handle = it },
                                modifier = Modifier.fillMaxWidth(),
                                placeholder = {
                                    Text(
                                        "yourname.bsky.social",
                                        color = FreeqColors.textMutedDark
                                    )
                                },
                                prefix = {
                                    Text(
                                        "@",
                                        color = FreeqColors.textMutedDark,
                                        fontSize = 18.sp,
                                        fontWeight = FontWeight.Medium
                                    )
                                },
                                singleLine = true,
                                keyboardOptions = KeyboardOptions(
                                    keyboardType = KeyboardType.Uri,
                                    imeAction = ImeAction.Go
                                ),
                                keyboardActions = KeyboardActions(
                                    onGo = { startBlueskyLogin(context, handle) }
                                ),
                                colors = OutlinedTextFieldDefaults.colors(
                                    focusedTextColor = FreeqColors.textPrimaryDark,
                                    unfocusedTextColor = FreeqColors.textPrimaryDark,
                                    focusedBorderColor = FreeqColors.accent,
                                    unfocusedBorderColor = FreeqColors.borderDark,
                                    focusedContainerColor = FreeqColors.bgPrimaryDark,
                                    unfocusedContainerColor = FreeqColors.bgPrimaryDark,
                                    cursorColor = FreeqColors.accent,
                                ),
                                shape = RoundedCornerShape(10.dp)
                            )
                        }

                        // Error display
                        localError?.let { ErrorBanner(it) }
                        errorMessage?.let { ErrorBanner(it) }

                        // Sign in button
                        Button(
                            onClick = { startBlueskyLogin(context, handle) },
                            modifier = Modifier.fillMaxWidth(),
                            enabled = handle.isNotEmpty() && !isLoading,
                            shape = RoundedCornerShape(10.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = FreeqColors.accent,
                                disabledContainerColor = FreeqColors.textMutedDark.copy(alpha = 0.3f)
                            ),
                            contentPadding = PaddingValues(vertical = 14.dp)
                        ) {
                            if (isLoading) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(18.dp),
                                    color = Color.White,
                                    strokeWidth = 2.dp
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    "Connecting...",
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.SemiBold
                                )
                            } else {
                                Icon(
                                    Icons.Default.Key,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    "Sign in with Bluesky",
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                        }
                    } else {
                        // ── Guest Login ──
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                text = "NICKNAME",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = FreeqColors.textMutedDark,
                                letterSpacing = 1.sp
                            )

                            OutlinedTextField(
                                value = guestNick,
                                onValueChange = { guestNick = it },
                                modifier = Modifier.fillMaxWidth(),
                                placeholder = {
                                    Text(
                                        "Choose a nickname",
                                        color = FreeqColors.textMutedDark
                                    )
                                },
                                leadingIcon = {
                                    Icon(
                                        Icons.Default.Person,
                                        contentDescription = null,
                                        tint = FreeqColors.textMutedDark,
                                        modifier = Modifier.size(18.dp)
                                    )
                                },
                                singleLine = true,
                                keyboardOptions = KeyboardOptions(
                                    keyboardType = KeyboardType.Text,
                                    imeAction = ImeAction.Go
                                ),
                                keyboardActions = KeyboardActions(
                                    onGo = {
                                        if (guestNick.isNotEmpty()) {
                                            appState.serverAddress.value = guestServer
                                            appState.connect(guestNick)
                                        }
                                    }
                                ),
                                colors = OutlinedTextFieldDefaults.colors(
                                    focusedTextColor = FreeqColors.textPrimaryDark,
                                    unfocusedTextColor = FreeqColors.textPrimaryDark,
                                    focusedBorderColor = FreeqColors.accent,
                                    unfocusedBorderColor = FreeqColors.borderDark,
                                    focusedContainerColor = FreeqColors.bgPrimaryDark,
                                    unfocusedContainerColor = FreeqColors.bgPrimaryDark,
                                    cursorColor = FreeqColors.accent,
                                ),
                                shape = RoundedCornerShape(10.dp)
                            )
                        }

                        errorMessage?.let { ErrorBanner(it) }

                        Button(
                            onClick = {
                                appState.serverAddress.value = guestServer
                                appState.connect(guestNick)
                            },
                            modifier = Modifier.fillMaxWidth(),
                            enabled = guestNick.isNotEmpty() && !isLoading,
                            shape = RoundedCornerShape(10.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = FreeqColors.accent,
                                disabledContainerColor = FreeqColors.textMutedDark.copy(alpha = 0.3f)
                            ),
                            contentPadding = PaddingValues(vertical = 14.dp)
                        ) {
                            if (isLoading) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(18.dp),
                                    color = Color.White,
                                    strokeWidth = 2.dp
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    "Connecting...",
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.SemiBold
                                )
                            } else {
                                Text(
                                    "Connect as Guest",
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Toggle link
            if (!showGuestLogin) {
                TextButton(onClick = { showGuestLogin = true }) {
                    Text(
                        "Continue as guest",
                        color = FreeqColors.textMutedDark,
                        fontSize = 14.sp
                    )
                }
            } else {
                TextButton(onClick = { showGuestLogin = false }) {
                    Icon(
                        Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = null,
                        modifier = Modifier.size(14.dp),
                        tint = FreeqColors.accent
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        "Sign in with Bluesky instead",
                        color = FreeqColors.accent,
                        fontSize = 14.sp
                    )
                }
            }

            Spacer(modifier = Modifier.weight(1f))

            // Footer
            Text(
                text = "Open source \u00B7 IRC compatible \u00B7 AT Protocol identity",
                fontSize = 11.sp,
                color = FreeqColors.textMutedDark,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(bottom = 24.dp)
            )
        }
    }
}

@Composable
private fun ErrorBanner(text: String) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Icon(
            Icons.Default.Warning,
            contentDescription = null,
            tint = FreeqColors.danger,
            modifier = Modifier.size(14.dp)
        )
        Text(
            text = text,
            fontSize = 13.sp,
            color = FreeqColors.danger
        )
    }
}

private fun startBlueskyLogin(context: android.content.Context, handle: String) {
    if (handle.isEmpty()) return
    val encoded = URLEncoder.encode(handle, "UTF-8")
    // `intent=enroll` asks the account for permission to write this device's
    // key records, on top of the identity-only default.
    val url = "${ServerConfig.authBrokerBase}/auth/login?handle=$encoded&mobile=1&intent=enroll"
    val customTabsIntent = CustomTabsIntent.Builder()
        .setShowTitle(true)
        .build()
    customTabsIntent.launchUrl(context, Uri.parse(url))
}
