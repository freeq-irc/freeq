package com.freeq.model

/**
 * DID display + DM-thread identity helpers (Android reference impl of the
 * DID-keyed DM model; mirrors the web client's identity.ts).
 *
 * DM buffers are keyed by the SDK's `dm_key` — the peer's DID when known,
 * else their nick — so one person is one thread. These helpers keep a raw
 * `did:plc:…` / `did:key:…` key from ever being *rendered*: resolve to a
 * human name where possible, compact the DID as a last resort.
 */
internal object DidDisplay {

    /** A syntactic DID: `did:<method>:<id>`. No network, no id validation. */
    fun isDid(s: String): Boolean =
        Regex("^did:[a-z0-9]+:.+", RegexOption.IGNORE_CASE).matches(s)

    /**
     * Canonical DM thread key for a typed or tapped target: a DID passes
     * through; a nick resolves to its DID when known, else stays a nick.
     * Opening threads by this key stops a typed nick from forking a
     * second, empty thread beside the DID-keyed one the same person
     * already has (mirrors iOS `canonicalDmKey`).
     */
    fun canonicalDmKey(raw: String, nickToDid: (String) -> String?): String {
        val trimmed = raw.trim()
        if (isDid(trimmed)) return trimmed
        return nickToDid(trimmed) ?: trimmed
    }

    /** Compact a DID for display: `did:plc:k2n3e2vsihf3farequ44t5j7` →
     *  `plc:k2n3…t5j7`. Non-DIDs pass through unchanged. */
    fun shorten(s: String): String {
        if (!isDid(s)) return s
        val parts = s.split(":", limit = 3)
        val method = parts[1]
        val id = parts[2]
        return if (id.length <= 12) "$method:$id"
        else "$method:${id.take(4)}…${id.takeLast(4)}"
    }

    /**
     * Human name for a thread key or identifier that may be a raw DID:
     * the display binding (DID→nick, from the conversation list / learned
     * bindings), then a reverse scan of the nick→DID map, then the
     * compacted DID. Plain nicks pass through unchanged.
     */
    fun displayName(
        key: String,
        didToNick: Map<String, String>,
        nickToDid: Map<String, String>,
    ): String {
        if (!isDid(key)) return key
        didToNick[key]?.let { return it }
        nickToDid.entries.firstOrNull { it.value == key }?.let { return it.key }
        return shorten(key)
    }

    /**
     * Fold a nick-keyed DM buffer into the DID-keyed one after the peer's
     * DID is learned (a cold first DM keys by nick until then — without the
     * merge, one person becomes two threads). Messages dedupe by id and
     * stay time-ordered via [ChannelState.appendIfNew]; unread counts carry
     * over. Returns true when a merge happened (the caller repoints any
     * active-thread state from `nick` to `did`).
     */
    fun mergeDmBuffers(
        dmBuffers: MutableList<ChannelState>,
        unreadCounts: MutableMap<String, Int>,
        nick: String,
        did: String,
    ): Boolean {
        if (!isDid(did) || nick.equals(did, ignoreCase = true)) return false
        if (nick.startsWith("#") || nick.startsWith("&")) return false // never a channel
        val nickIdx = dmBuffers.indexOfFirst { it.name.equals(nick, ignoreCase = true) }
        if (nickIdx < 0) return false
        val nickBuf = dmBuffers[nickIdx]

        val didBuf = dmBuffers.firstOrNull { it.name == did }
        if (didBuf != null) {
            for (m in nickBuf.messages) didBuf.appendIfNew(m)
            if (didBuf.lastActivityTime.value < nickBuf.lastActivityTime.value) {
                didBuf.lastActivityTime.value = nickBuf.lastActivityTime.value
            }
            dmBuffers.removeAt(nickIdx)
        } else {
            // Only the nick thread exists → re-key it (rename-in-place,
            // same shape as the nick-change rebuild).
            val rekeyed = ChannelState(did)
            for (m in nickBuf.messages) rekeyed.appendIfNew(m)
            rekeyed.members.addAll(nickBuf.members)
            rekeyed.lastActivityTime.value = nickBuf.lastActivityTime.value
            dmBuffers.removeAt(nickIdx)
            dmBuffers.add(rekeyed)
        }
        unreadCounts.remove(nickBuf.name)?.let { moved ->
            unreadCounts[did] = (unreadCounts[did] ?: 0) + moved
        }
        return true
    }
}

/**
 * Binding logic for our OWN echoed DMs. The server echoes a sent DM back
 * with the wire `target` = the recipient's nick and `dmKey` = their
 * canonical DID (when resolved). Without adopting that binding, a thread
 * the sender opened by nick and the DID-keyed thread the echo lands in
 * stay split — the sender never sees their own message until the peer
 * replies. Pure; mirrors iOS/macOS DmEcho (12e1a655).
 */
internal object DmEcho {
    fun recipientBinding(isSelf: Boolean, target: String, dmKey: String?): Pair<String, String>? {
        if (!isSelf) return null
        val did = dmKey ?: return null
        if (!DidDisplay.isDid(did)) return null
        if (target.startsWith("#") || target.startsWith("&")) return null
        if (DidDisplay.isDid(target)) return null
        if (target.equals(did, ignoreCase = true)) return null
        return target to did
    }
}
