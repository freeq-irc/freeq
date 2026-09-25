package com.freeq.model

/**
 * Classifies the server notice that refuses this device's signing key
 * (FAIL MSGSIG KEY_RETIRED or KEY_EXPIRED, which the FFI hands on as
 * `MSGSIG KEY_RETIRED <reason>`) and says what follows. Either way the saved
 * login goes: a reconnect on it is not a fresh sign-in, so it would present
 * the same key, and only a fresh sign-in replaces an expired one.
 *
 * Lives outside `AppState` so the rule can be unit-tested without an
 * Android runtime; the notice handler only applies the result. Mirrors the
 * iOS and macOS `RefusedKeyNotice`.
 */
internal object RefusedKeyNotice {
    data class Refusal(
        /** The sentence the sign-in screen shows. */
        val line: String,
        /** The saved login is cleared, the way sign-out clears it. */
        val clearsSavedLogin: Boolean,
        /** Whether the disconnect that follows may reconnect. */
        val schedulesReconnect: Boolean,
    )

    const val LINE = "This device was signed out from another device. Sign in again to continue."
    const val EXPIRED_LINE = "This device's signing key has expired. Sign in again to continue."

    /** The refusal a notice carries; null for any other notice. */
    fun parse(text: String): Refusal? {
        val line = when {
            text.startsWith("MSGSIG KEY_RETIRED") -> LINE
            text.startsWith("MSGSIG KEY_EXPIRED") -> EXPIRED_LINE
            else -> return null
        }
        return Refusal(line = line, clearsSavedLogin = true, schedulesReconnect = false)
    }
}
