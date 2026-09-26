package com.freeq.model

/**
 * The status bar at the top of the main screen while the connection is not
 * registered, with the iPhone's rules (`ConnectionStatusBanner` in
 * freeq-ios/freeq/ContentView.swift): hidden for the first seconds of a drop
 * so a quick reconnect shows nothing, then the same words, and a way to sign
 * in again once it has been stuck a while.
 *
 * Whether the bar shows follows the connection alone. The network monitor
 * only picks the offline words and the danger colour: a VPN can keep the
 * device's network up while the real one is gone, and the bar must still show.
 *
 * Lives outside the Compose code so the rule can be unit-tested without an
 * Android runtime.
 */
internal object ConnectionStatus {
    /** Seconds hidden after a drop or a launch. */
    const val GRACE_SECONDS = 4
    /** Seconds before the words say it is taking long. */
    const val SLOW_SECONDS = 12
    /** Seconds not connected before "Sign in again" shows. */
    const val SIGN_IN_AGAIN_SECONDS = 20

    enum class Icon { Spinner, Offline, Retry }

    /** The bar's colour, as the iPhone's chat-screen bar: danger when the
     *  network monitor says there is no network, warning otherwise. */
    enum class Tone { Danger, Warning }

    data class Bar(val text: String, val icon: Icon, val signInAgain: Boolean, val tone: Tone)

    /** The bar to show, or null for none. */
    fun bar(state: ConnectionState, networkConnected: Boolean, secondsSinceDrop: Int): Bar? {
        if (state == ConnectionState.Registered) return null
        if (secondsSinceDrop < GRACE_SECONDS) return null
        val slow = secondsSinceDrop >= SLOW_SECONDS
        val text = when (state) {
            ConnectionState.Disconnected -> when {
                !networkConnected -> "Offline — messages will sync when you reconnect"
                slow -> "Still trying — network looks slow"
                else -> "Signing in…"
            }
            ConnectionState.Connecting -> if (slow) "Still signing in…" else "Signing in…"
            else -> "Almost there…"
        }
        val icon = when {
            state != ConnectionState.Disconnected -> Icon.Spinner
            !networkConnected -> Icon.Offline
            else -> Icon.Retry
        }
        val notConnected = state == ConnectionState.Disconnected || state == ConnectionState.Connecting
        val tone = if (networkConnected) Tone.Warning else Tone.Danger
        return Bar(text, icon, notConnected && secondsSinceDrop >= SIGN_IN_AGAIN_SECONDS, tone)
    }
}

/**
 * The seconds [ConnectionStatus] counts: from the moment the connection left
 * registered (or from launch), across every attempt of that drop, and started
 * again on the next drop.
 */
internal class DropTimer {
    private var droppedAtMs: Long? = null

    /** Feed the current state; safe to call on every recomposition. */
    fun update(state: ConnectionState, nowMs: Long) {
        if (state == ConnectionState.Registered) droppedAtMs = null
        else if (droppedAtMs == null) droppedAtMs = nowMs
    }

    /** Whole seconds since the drop, or null while registered. */
    fun secondsSinceDrop(nowMs: Long): Int? {
        val at = droppedAtMs ?: return null
        return (maxOf(0L, nowMs - at) / 1000).toInt()
    }
}
