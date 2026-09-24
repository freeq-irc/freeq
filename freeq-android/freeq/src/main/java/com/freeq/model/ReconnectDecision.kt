package com.freeq.model

/**
 * What to do when the app finds itself disconnected and wants to be back
 * online (foreground, network restored, a dropped connection). Lives
 * outside AppState so it can be unit-tested without an Android `ViewModel`.
 */
internal object ReconnectDecision {
    enum class Action {
        /** A broker token is saved: restore the account's session. */
        ReconnectSavedSession,
        /** The last session was a guest's: connect as a guest again. */
        ConnectAsGuest,
        /** Neither: stay disconnected, so the connect screen shows. */
        None,
    }

    /**
     * [lastSessionWasGuest] is null when the flag was never written (an
     * install that predates it); that is treated like an account, never as
     * a guest. An account whose token is gone (the encrypted prefs were
     * rebuilt, or the broker refused it) must sign in again rather than
     * come back as a guest under its saved nick.
     */
    fun decide(
        hasSavedSession: Boolean,
        lastSessionWasGuest: Boolean?,
        savedNick: String,
    ): Action = when {
        hasSavedSession -> Action.ReconnectSavedSession
        lastSessionWasGuest == true && savedNick.isNotEmpty() -> Action.ConnectAsGuest
        else -> Action.None
    }
}
