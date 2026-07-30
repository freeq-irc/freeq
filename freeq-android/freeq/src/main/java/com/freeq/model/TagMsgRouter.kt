package com.freeq.model

/**
 * Routing predicate for IRCv3 TAGMSG dispatch (typing, edit, delete,
 * react). Pulled out of `AndroidEventHandler.onEvent` so the
 * channel-vs-DM resolution rule lives in one place.
 */
internal object TagMsgRouter {
    /**
     * Resolves which buffer a TAGMSG should be applied to.
     *
     * A TAGMSG whose sender is our own nick is NOT necessarily our echo:
     * the same DID signed in on another device sends events under the
     * same nick, and the server fans them out to sibling sessions that
     * never applied anything optimistically. Dropping those left deletes
     * and reactions from your own other device invisible until a history
     * refetch. So self events route like any other — delete/react apply
     * is idempotent, making a true echo harmless — and the one consumer
     * where self must not render (typing) skips self at its own dispatch
     * site.
     *
     * Rules:
     * - `target` starts with `#` ⇒ channel TAGMSG; route to that channel.
     * - Otherwise it's a DM: prefer the SDK's canonical conversation key
     *   (`dmKey`, the peer DID when known). Without one, the buffer is
     *   named after the peer — the sender (`from`), unless the sender is
     *   us, in which case the peer is the wire `target`.
     */
    fun routeTo(
        target: String,
        from: String,
        selfNick: String,
        dmKey: String? = null,
    ): String {
        if (target.startsWith("#")) return target
        if (dmKey != null) return dmKey
        return if (from.equals(selfNick, ignoreCase = true)) target else from
    }
}
