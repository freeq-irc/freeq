package com.freeq.model

/** How join/part/quit lines show in a channel. Hidden unless the user asks. */
enum class JoinPartDisplay(val key: String) {
    HIDDEN("hidden"), GROUPED("grouped"), ALL("all");

    companion object {
        fun fromKey(key: String?): JoinPartDisplay =
            entries.firstOrNull { it.key == key } ?: HIDDEN
    }
}

/**
 * Applies the join/part display policy to a channel's lines. Only presence
 * lines (someone joined, left or quit) are touched — kicks and other
 * moderation lines always pass through.
 */
object PresenceLines {
    private val PRESENCE = Regex("""^(\S+) (joined|left|quit)( \(.*\))?$""")

    fun isPresence(msg: ChatMessage): Boolean =
        msg.from.isEmpty() && !msg.isDeleted && PRESENCE.matches(msg.text)

    fun apply(messages: List<ChatMessage>, mode: JoinPartDisplay): List<ChatMessage> = when (mode) {
        JoinPartDisplay.ALL -> messages
        JoinPartDisplay.HIDDEN -> messages.filterNot(::isPresence)
        JoinPartDisplay.GROUPED -> grouped(messages)
    }

    private fun grouped(messages: List<ChatMessage>): List<ChatMessage> {
        val out = ArrayList<ChatMessage>(messages.size)
        var i = 0
        while (i < messages.size) {
            val msg = messages[i]
            if (!isPresence(msg)) { out.add(msg); i++; continue }
            var j = i
            while (j < messages.size && isPresence(messages[j])) j++
            val run = messages.subList(i, j)
            // A lone line stays as it is; a run folds into one summary line.
            out.add(if (run.size == 1) msg else msg.copy(text = summary(run)))
            i = j
        }
        return out
    }

    /** "nap reconnected 2×" for one person's churn, else "a, b joined · c left". */
    fun summary(run: List<ChatMessage>): String {
        val joins = mutableListOf<String>()
        val leaves = mutableListOf<String>()
        for (m in run) {
            val match = PRESENCE.matchEntire(m.text) ?: continue
            val nick = match.groupValues[1]
            if (match.groupValues[2] == "joined") joins.add(nick) else leaves.add(nick)
        }
        val nicks = (joins + leaves).distinctBy { it.lowercase() }
        if (nicks.size == 1) {
            val nick = nicks[0]
            return when {
                joins.isNotEmpty() && leaves.isNotEmpty() -> "$nick reconnected ${minOf(joins.size, leaves.size)}×"
                joins.isNotEmpty() -> "$nick joined ${joins.size}×"
                else -> "$nick left ${leaves.size}×"
            }
        }
        val parts = mutableListOf<String>()
        if (joins.isNotEmpty()) parts.add("${names(joins)} joined")
        if (leaves.isNotEmpty()) parts.add("${names(leaves)} left")
        return parts.joinToString(" · ")
    }

    private fun names(nicks: List<String>): String {
        val unique = nicks.distinctBy { it.lowercase() }
        val shown = unique.take(3).joinToString(", ")
        return if (unique.size > 3) "$shown and ${unique.size - 3} more" else shown
    }
}
