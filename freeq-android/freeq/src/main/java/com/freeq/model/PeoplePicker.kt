package com.freeq.model

/**
 * Model for the New-message people picker — the Android port of macOS's
 * `NewDMSheet`. Candidates are everyone you share a channel with (online)
 * plus everyone you have a DM thread with (labels resolved, DID keys kept
 * for opening); filtering is case-insensitive substring with prefix
 * matches first; a free-form entry covers a name nobody matches, so you
 * can still DM someone you share nothing with. Pure — the dialog renders
 * what this returns.
 */
internal object PeoplePicker {

    data class Person(
        /** What to open the DM with (nick, or the DM thread's key — may be a DID). */
        val key: String,
        /** What to render. */
        val label: String,
        /** Currently visible in a shared channel. */
        val online: Boolean,
    )

    fun candidates(
        memberNicks: List<String>,
        dmThreads: List<String>,
        selfNick: String,
        nickToDid: (String) -> String?,
        displayName: (String) -> String,
    ): List<Person> {
        // Canonical identity → person; members claim the slot first so a
        // person with both a shared channel and a DM thread lists once,
        // online, under their live nick.
        val byId = LinkedHashMap<String, Person>()
        val selfDid = nickToDid(selfNick)

        for (nick in memberNicks) {
            if (nick.equals(selfNick, ignoreCase = true)) continue
            val id = nickToDid(nick) ?: nick.lowercase()
            byId.putIfAbsent(id, Person(key = nick, label = nick, online = true))
        }
        for (threadKey in dmThreads) {
            if (threadKey.equals(selfNick, ignoreCase = true) || threadKey == selfDid) continue
            val id = if (DidDisplay.isDid(threadKey)) threadKey
            else nickToDid(threadKey) ?: threadKey.lowercase()
            byId.putIfAbsent(id, Person(key = threadKey, label = displayName(threadKey), online = false))
        }
        return byId.values.sortedBy { it.label.lowercase() }
    }

    /** Case-insensitive substring filter, prefix matches first, then
     *  alphabetical. A blank query returns everyone. */
    fun filter(candidates: List<Person>, query: String): List<Person> {
        val q = query.trim().lowercase()
        if (q.isEmpty()) return candidates
        return candidates
            .filter { it.label.lowercase().contains(q) }
            .sortedWith(
                compareByDescending<Person> { it.label.lowercase().startsWith(q) }
                    .thenBy { it.label.lowercase() }
            )
    }

    /** The typed text, when it deserves its own "send a new message" row:
     *  non-blank, not a channel name, and not already an exact candidate
     *  label (any case). */
    fun freeform(query: String, candidates: List<Person>): String? {
        val typed = query.trim()
        if (typed.isEmpty() || typed.startsWith("#")) return null
        if (candidates.any { it.label.equals(typed, ignoreCase = true) }) return null
        return typed
    }
}
