package com.freeq.model

/**
 * Whether a `Disconnected` event shows its "Disconnected: …" message. Once per
 * drop: the first disconnect after the app registered shows it; the failed
 * reconnect attempts that follow, each its own `Disconnected`, do not, until
 * the app registers again. The status bar says the rest. A drop that follows
 * the server's try-again shows nothing either: the try-again's sentence is
 * already shown, as on iOS and macOS.
 *
 * Lives outside the event handler so the rule can be unit-tested without an
 * Android runtime.
 */
internal class DisconnectNotice {
    private var armed = false

    /** The connection registered: the next drop shows. */
    fun onRegistered() {
        armed = true
    }

    /** The server could not check this account just now, and its sentence
     *  is shown: the drop that follows does not replace it. */
    fun onTryAgain() {
        armed = false
    }

    /** A `Disconnected` event arrived; whether this one shows the message. */
    fun onDisconnected(): Boolean {
        val show = armed
        armed = false
        return show
    }
}
