package com.freeq.model

/**
 * Authorship check for inbound edit/delete events.
 *
 * Only the original sender may edit or delete a message. The server
 * enforces this for persisted threads; for unpersisted (guest) DMs it
 * relays without a row to check, so the client is the authority.
 *
 * DID comparison when both sides are known, else nick. A missing original
 * passes — the apply is a no-op anyway.
 */
internal object MessageAuthorship {
    /**
     * @param didForNick resolves a nick to its server-bound DID (`AppState.didForNick`)
     * @param actorAccount the actor's DID from the message account-tag, if any
     */
    fun actorIsAuthor(
        buffer: ChannelState,
        originalId: String,
        actorNick: String,
        actorAccount: String?,
        didForNick: (String) -> String?,
    ): Boolean {
        val idx = buffer.findMessage(originalId) ?: return true
        val originalFrom = buffer.messages[idx].from
        val originalDid = didForNick(originalFrom)
        if (actorAccount != null && originalDid != null) {
            return actorAccount == originalDid
        }
        return actorNick.equals(originalFrom, ignoreCase = true)
    }
}
