package com.freeq.model

/**
 * Reacting or un-reacting to a message.
 *
 * A reaction is two explicit operations, not one toggle: adding puts the
 * sender among an emoji's reactors and removing takes them out. Only the
 * *sender's* intent is a toggle — which of the two to send is decided here
 * from whether they've already reacted — and receivers apply whichever op
 * arrives, so a re-delivered add is a no-op rather than an accidental removal.
 *
 * Pure so the decision is assertable without an `AppState`; the dispatch site
 * owns the SDK call and the local optimistic apply. (Removing used to update
 * the screen and send nothing at all, so an un-react never left the device.)
 *
 * `msgId` needs no resolution: the server has sent root ids on reaction fan-out
 * since it began keying by them, and this client has never re-keyed a message
 * on edit, so the id held here is already the one the server files under.
 */
internal sealed interface ReactionSend {
    val target: String
    val msgId: String
    val emoji: String

    data class Add(
        override val target: String,
        override val msgId: String,
        override val emoji: String,
    ) : ReactionSend

    data class Remove(
        override val target: String,
        override val msgId: String,
        override val emoji: String,
    ) : ReactionSend
}

internal object ReactionOp {
    fun plan(target: String, msgId: String, emoji: String, alreadyReacted: Boolean): ReactionSend =
        if (alreadyReacted) {
            ReactionSend.Remove(target, msgId, emoji)
        } else {
            ReactionSend.Add(target, msgId, emoji)
        }
}
