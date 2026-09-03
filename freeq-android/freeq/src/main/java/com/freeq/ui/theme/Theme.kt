package com.freeq.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import kotlin.math.abs

// ── Color palette matching iOS Theme.swift ──

object FreeqColors {
    // Backgrounds — dark
    val bgPrimaryDark = Color(0xFF1A1A2E)
    val bgSecondaryDark = Color(0xFF16162A)
    val bgTertiaryDark = Color(0xFF1E1E3A)
    val bgHoverDark = Color(0xFF252545)

    // Backgrounds — light
    val bgPrimaryLight = Color(0xFFFFFFFF)
    val bgSecondaryLight = Color(0xFFF5F5F7)
    val bgTertiaryLight = Color(0xFFEBEBF0)
    val bgHoverLight = Color(0xFFE0E0E8)

    // Text — dark
    val textPrimaryDark = Color(0xFFE8E8F0)
    val textSecondaryDark = Color(0xFFA0A0B8)
    val textMutedDark = Color(0xFF606078)

    // Text — light
    val textPrimaryLight = Color(0xFF1A1A2E)
    val textSecondaryLight = Color(0xFF505068)
    val textMutedLight = Color(0xFF909098)

    // Accent — same in both themes
    val accent = Color(0xFF6C63FF)
    val accentLight = Color(0xFF8B83FF)
    /// In-progress register on act cards; the web token's value (--color-blue).
    val blue = Color(0xFF5C9EFF)

    // Status — same in both themes
    val success = Color(0xFF43B581)
    val warning = Color(0xFFFAA61A)
    val danger = Color(0xFFF04747)

    // Borders
    val borderDark = Color(0xFF2A2A48)
    val borderLight = Color(0xFFD0D0D8)

    // Nick colors (deterministic by name) — same in both themes
    val nickColors = listOf(
        Color(0xFF6C63FF),
        Color(0xFF43B581),
        Color(0xFFFAA61A),
        Color(0xFFF04747),
        Color(0xFFE91E8C),
        Color(0xFF1ABC9C),
        Color(0xFFE67E22),
        Color(0xFF3498DB),
        Color(0xFF9B59B6),
        Color(0xFF2ECC71),
    )

    fun nickColor(nick: String): Color {
        val hash = nick.fold(0) { acc, c -> acc + c.code }
        return nickColors[abs(hash) % nickColors.count()]
    }
}

// ── Material 3 color schemes ──

private val DarkColorScheme = darkColorScheme(
    primary = FreeqColors.accent,
    onPrimary = Color.White,
    primaryContainer = FreeqColors.accent,
    secondary = FreeqColors.accentLight,
    background = FreeqColors.bgPrimaryDark,
    onBackground = FreeqColors.textPrimaryDark,
    surface = FreeqColors.bgSecondaryDark,
    onSurface = FreeqColors.textPrimaryDark,
    surfaceVariant = FreeqColors.bgTertiaryDark,
    onSurfaceVariant = FreeqColors.textSecondaryDark,
    outline = FreeqColors.borderDark,
    error = FreeqColors.danger,
    onError = Color.White,
)

private val LightColorScheme = lightColorScheme(
    primary = FreeqColors.accent,
    onPrimary = Color.White,
    primaryContainer = FreeqColors.accent,
    secondary = FreeqColors.accentLight,
    background = FreeqColors.bgPrimaryLight,
    onBackground = FreeqColors.textPrimaryLight,
    surface = FreeqColors.bgSecondaryLight,
    onSurface = FreeqColors.textPrimaryLight,
    surfaceVariant = FreeqColors.bgTertiaryLight,
    onSurfaceVariant = FreeqColors.textSecondaryLight,
    outline = FreeqColors.borderLight,
    error = FreeqColors.danger,
    onError = Color.White,
)

@Composable
fun FreeqTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme

    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}

// ── Helper: current theme-aware colors ──

object Theme {
    @Composable
    fun bgPrimary() = MaterialTheme.colorScheme.background

    @Composable
    fun bgSecondary() = MaterialTheme.colorScheme.surface

    @Composable
    fun bgTertiary() = MaterialTheme.colorScheme.surfaceVariant

    @Composable
    fun textPrimary() = MaterialTheme.colorScheme.onBackground

    @Composable
    fun textSecondary() = MaterialTheme.colorScheme.onSurfaceVariant

    @Composable
    fun textMuted(): Color {
        return if (MaterialTheme.colorScheme.background == FreeqColors.bgPrimaryDark)
            FreeqColors.textMutedDark
        else
            FreeqColors.textMutedLight
    }

    @Composable
    fun border() = MaterialTheme.colorScheme.outline

    val accent = FreeqColors.accent
    val accentLight = FreeqColors.accentLight
    val blue = FreeqColors.blue
    val success = FreeqColors.success
    val warning = FreeqColors.warning
    val danger = FreeqColors.danger

    fun nickColor(nick: String) = FreeqColors.nickColor(nick)
}
