package com.freeq.model

/**
 * The app's root screen: the main screen, or the sign-in screen. As on the
 * iPhone (`ContentView`), a saved session keeps the main screen whatever the
 * connection is doing; the status bar says what it is doing. Sign-in shows
 * only with no saved session and no live connection, or after signing out.
 *
 * Lives outside the Compose code so the rule can be unit-tested without an
 * Android runtime.
 */
internal object RootScreen {
    enum class Screen { Main, Connect }

    fun decide(state: ConnectionState, hasSavedSession: Boolean, loggedOut: Boolean): Screen = when {
        state == ConnectionState.Connected || state == ConnectionState.Registered -> Screen.Main
        hasSavedSession && !loggedOut -> Screen.Main
        else -> Screen.Connect
    }
}
