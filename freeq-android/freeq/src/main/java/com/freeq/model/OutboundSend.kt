package com.freeq.model

/**
 * What a composed message becomes when it leaves this device.
 *
 * The three kinds map onto the SDK's typed senders — `send_message`,
 * `edit_message`, `reply` — each of which signs what it sends and files an
 * event id for it. Deciding here, purely, keeps that choice assertable without
 * an `AppState`; the dispatch site owns the FFI call and the local optimistic
 * apply.
 */
internal sealed interface OutboundSend {
    val target: String

    data class Plain(override val target: String, val text: String) : OutboundSend
    data class Edit(override val target: String, val msgId: String, val text: String) : OutboundSend
    data class Reply(override val target: String, val msgId: String, val text: String) : OutboundSend
}

internal object ComposeSend {
    /**
     * Resolve the compose bar's state into one send, or null when there is
     * nothing to send.
     *
     * Newlines survive: the SDK routes a multi-line body into a
     * `draft/multiline` batch and signs the assembled result. Escaping them to
     * a literal `\n` here — which is what building the line by hand used to
     * do — would have the signature cover bytes no receiver ever holds.
     */
    fun plan(
        target: String,
        text: String,
        editingId: String?,
        replyToId: String?,
    ): OutboundSend? {
        val cleaned = text.replace("\r", "")
        if (cleaned.isEmpty()) return null
        return when {
            editingId != null -> OutboundSend.Edit(target, editingId, cleaned)
            replyToId != null -> OutboundSend.Reply(target, replyToId, cleaned)
            else -> OutboundSend.Plain(target, cleaned)
        }
    }
}
