package com.freeq.model

/**
 * A signed-in session that registers under a guest nick: the server did not
 * take its token. On any connect, the first included, it signs out as logout
 * does, rather than carry on as a guest or retry (the web's sign-out and
 * line, freeq-app/src/irc/client.ts, 83cede93). A guest's own session carries
 * on.
 *
 * Lives outside the event handler so the rule can be unit-tested without an
 * Android runtime.
 */
internal object GuestReturn {
    enum class Outcome { Registered, SignOut }

    /** A registration arrived; [signedInDid] is the account this app is
     *  signed in as, or null for a guest. */
    fun onRegistered(signedInDid: String?, nick: String): Outcome {
        if (signedInDid != null && nick.startsWith("Guest", ignoreCase = true)) return Outcome.SignOut
        return Outcome.Registered
    }
}
