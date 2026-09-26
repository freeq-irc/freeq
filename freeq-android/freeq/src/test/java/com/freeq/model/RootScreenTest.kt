package com.freeq.model

import com.freeq.model.RootScreen.Screen
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pure-JVM tests for the app's root choice: the main screen or the sign-in
 * screen. A saved session keeps the main screen whatever the connection is
 * doing, as the iPhone's `ContentView` does.
 */
class RootScreenTest {

    @Test fun a_saved_session_keeps_the_main_screen_while_disconnected() {
        assertEquals(Screen.Main, RootScreen.decide(ConnectionState.Disconnected, hasSavedSession = true, loggedOut = false))
    }

    @Test fun a_saved_session_keeps_the_main_screen_while_connecting() {
        assertEquals(Screen.Main, RootScreen.decide(ConnectionState.Connecting, hasSavedSession = true, loggedOut = false))
        assertEquals(Screen.Main, RootScreen.decide(ConnectionState.Connected, hasSavedSession = true, loggedOut = false))
    }

    @Test fun no_saved_session_and_no_connection_shows_sign_in() {
        assertEquals(Screen.Connect, RootScreen.decide(ConnectionState.Disconnected, hasSavedSession = false, loggedOut = false))
        assertEquals(Screen.Connect, RootScreen.decide(ConnectionState.Connecting, hasSavedSession = false, loggedOut = false))
    }

    @Test fun signed_out_shows_sign_in() {
        assertEquals(Screen.Connect, RootScreen.decide(ConnectionState.Disconnected, hasSavedSession = true, loggedOut = true))
    }

    @Test fun a_live_connection_without_a_saved_session_shows_the_main_screen() {
        assertEquals(Screen.Main, RootScreen.decide(ConnectionState.Registered, hasSavedSession = false, loggedOut = false))
        assertEquals(Screen.Main, RootScreen.decide(ConnectionState.Connected, hasSavedSession = false, loggedOut = false))
    }
}
