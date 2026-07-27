package com.freeq.model

/**
 * The wire line for reacting or un-reacting to a message.
 *
 * A reaction is two explicit operations, not one toggle: `+react` adds the
 * sender to an emoji's reactors and `+freeq.at/unreact` removes them. Only the
 * *sender's* intent is a toggle — which of the two to send is decided here from
 * whether they've already reacted — and receivers apply whichever op arrives,
 * so a re-delivered `+react` is a no-op rather than an accidental removal.
 *
 * Pure so the outbound line is assertable without an `AppState`; the dispatch
 * site owns the local optimistic apply. (Removing used to update the screen and
 * send nothing at all, so an un-react never left the device.)
 *
 * `msgId` needs no resolution: the server has sent root ids on reaction fan-out
 * since it began keying by them, and this client has never re-keyed a message
 * on edit, so the id held here is already the one the server files under.
 */
internal object ReactionOp {
    fun line(target: String, msgId: String, emoji: String, alreadyReacted: Boolean): String =
        if (alreadyReacted) {
            "@+freeq.at/unreact=$emoji;+reply=$msgId TAGMSG $target"
        } else {
            "@+react=$emoji;+reply=$msgId TAGMSG $target"
        }
}
