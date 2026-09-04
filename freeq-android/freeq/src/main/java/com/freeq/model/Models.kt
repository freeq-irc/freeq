package com.freeq.model

import android.app.Application
import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.AndroidViewModel
import com.freeq.ffi.*
import kotlinx.coroutines.*
import java.io.File
import java.util.*

// ── Data models ──

data class ChatMessage(
    val id: String,
    val from: String,
    var text: String,
    val isAction: Boolean,
    val timestamp: Date,
    val replyTo: String? = null,
    var isEdited: Boolean = false,
    var isDeleted: Boolean = false,
    // A signature tag was present on the wire. Not a verification result, and
    // deliberately not rendered: whether a signature holds up is a question
    // only a check can answer, and only when the user asks it.
    val isSigned: Boolean = false,
    // The DID the sending server attributes this message to (`account`). A
    // statement about the sender that travels on the message itself, so a
    // signature check still has an identity to name when the sender has left
    // and the member list no longer holds them.
    val account: String? = null,
    // Origin server name when relayed from a federated peer (+freeq.at/origin).
    // null = locally-originated. Drives "via {origin}" + suppresses the local
    // verified/signed badges, which would overstate trust for a peer-vouched msg.
    val origin: String? = null,
    // The task this line was written beside (+freeq.at/ref), for a companion
    // line. The only thing joining a line to the work it is about; null on an
    // ordinary message.
    val actRef: String? = null,
    // A parsed +freeq.at/event coordination event riding on this message.
    // When set, the row renders as a coordination card.
    val coordination: com.freeq.ffi.CoordinationEvent? = null,
    val reactions: MutableMap<String, MutableSet<String>> = mutableMapOf()
) {
    companion object {
        /** Order for rows arriving in bulk — a history batch, or the buffer
         *  cache. The server's replay `time` tag is second-precision, so
         *  same-second rows need a second key: msgids are ULIDs, so id order
         *  is mint order. */
        val replayOrder: Comparator<ChatMessage> = compareBy({ it.timestamp }, { it.id })
    }
}

data class MemberInfo(
    val nick: String,
    val isOp: Boolean,
    val isHalfop: Boolean = false,
    val isVoiced: Boolean,
    val awayMsg: String? = null,
    val did: String? = null,
    /** `agent` | `external_agent` | `human`, when the server has told us.
     *  Null means "not stated", which reads as human — the server reports
     *  only the exceptions. */
    val actorClass: String? = null,
    /** Live agent state and what it is doing. Only agents publish these. */
    val presenceState: String? = null,
    val presenceStatus: String? = null
) {
    val prefix: String
        get() = when {
            isOp -> "@"
            isHalfop -> "%"
            isVoiced -> "+"
            else -> ""
        }

    val isAgent: Boolean
        get() = actorClass == "agent" || actorClass == "external_agent"

    /** What to show beside an agent's name: what it is doing, else its state.
     *  An idle agent says nothing — a row that always carries a label teaches
     *  people to stop reading it. */
    val activityLabel: String?
        get() {
            if (!isAgent) return null
            if (!presenceStatus.isNullOrEmpty()) return presenceStatus
            return when (presenceState) {
                null, "online", "active", "idle" -> null
                "executing" -> "working"
                "waiting_for_input" -> "waiting for input"
                "blocked_on_permission" -> "needs approval"
                "paused" -> "paused"
                "degraded" -> "degraded"
                "rate_limited" -> "rate limited"
                else -> presenceState.replace('_', ' ')
            }
        }

    val isAway: Boolean
        get() = awayMsg != null

    /** The line under the name: the activity label wins, the away text
     *  shows only when there is no label. Same as the macOS member row. */
    val awayText: String?
        get() = if (activityLabel == null) awayMsg else null
}

// ── Channel state ──

/**
 * Parse an IRCv3 `time`-tag value (ISO-8601 UTC, e.g.
 * `2011-10-19T16:40:51.620Z`) to epoch millis. Returns null on
 * blank/unparseable input so callers can no-op safely.
 */
internal fun parseServerTimeMillis(raw: String?): Long? {
    val s = raw?.trim().orEmpty()
    if (s.isEmpty()) return null
    return try {
        java.time.Instant.parse(s).toEpochMilli()
    } catch (_: Exception) {
        null
    }
}

class ChannelState(val name: String) {
    val messages = mutableStateListOf<ChatMessage>()
    val members = mutableStateListOf<MemberInfo>()
    /** The tasks this channel has seen, keyed by each opener's event id. */
    val actTasks = ActTaskStore()
    /** The card each companion line draws, keyed by that line's id. Compose
     *  state, so a line already on screen becomes its card the moment its
     *  event lands. */
    val actCards = mutableStateMapOf<String, ActCard>()
    var topic = mutableStateOf("")
    val typingUsers = mutableStateMapOf<String, Date>()
    var lastActivityTime = mutableStateOf(0L)
    var hasMoreHistory = mutableStateOf(true)

    private val messageIds = mutableSetOf<String>()

    val activeTypers: List<String>
        get() {
            val cutoff = Date().time - 5000
            return typingUsers.filter { it.value.time > cutoff }.keys.sorted()
        }

    fun findMessage(byId: String): Int? {
        return messages.indexOfFirst { it.id == byId }.takeIf { it >= 0 }
    }

    fun appendIfNew(msg: ChatMessage) {
        if (messageIds.contains(msg.id)) return
        messageIds.add(msg.id)
        if (messages.isNotEmpty() && msg.timestamp < messages.last().timestamp) {
            val idx = messages.indexOfFirst { it.timestamp > msg.timestamp }
            if (idx >= 0) messages.add(idx, msg) else messages.add(msg)
        } else {
            messages.add(msg)
        }
        // Only real messages (not system join/part) update lastActivityTime
        if (msg.from.isNotEmpty() && msg.timestamp.time > lastActivityTime.value) {
            lastActivityTime.value = msg.timestamp.time
        }
        // Either side can land first, so joining runs from both.
        if (msg.actRef != null) pairActCompanions()
    }

    /**
     * Join the task events this channel holds to the companion lines it holds.
     *
     * Cheap to repeat: already-joined pairs are left alone, and a line whose
     * event has not arrived waits for it.
     */
    fun pairActCompanions() {
        if (actTasks.tasks.isEmpty()) return
        actTasks.pair(
            messages.mapNotNull { m ->
                m.actRef?.let { ActLine(m.id, m.from, m.account, m.timestamp.time, it) }
            }
        )
        refreshActCards()
    }

    /** File one task event, and hand back the line the room is told, if any. */
    fun recordActEvent(ev: ActEventInput): String? {
        val line = actTasks.record(ev)
        refreshActCards()
        return line
    }

    private fun refreshActCards() {
        for (task in actTasks.tasks.values) {
            for (ev in task.events) {
                val id = ev.msgId ?: continue
                val card = ActCard(task, ev)
                if (actCards[id] != card) actCards[id] = card
            }
        }
    }

    /**
     * Seed `lastActivityTime` from a CHATHISTORY TARGETS server-time tag.
     * Mirrors iOS 6dff8b2: a freshly minted DM buffer (no messages yet)
     * takes the server time unconditionally so the chat list sorts
     * correctly on cold launch before per-DM history backfills; a buffer
     * that already has messages only moves forward, never regressing past
     * in-session activity. No-op on blank/unparseable input.
     */
    fun seedActivityFromTarget(serverTime: String?) {
        val ms = parseServerTimeMillis(serverTime) ?: return
        if (messages.isEmpty() || ms > lastActivityTime.value) {
            lastActivityTime.value = ms
        }
    }

    fun applyEdit(originalId: String, newId: String?, newText: String) {
        val idx = findMessage(originalId) ?: return
        messages[idx] = messages[idx].copy(text = newText, isEdited = true)
        if (newId != null) messageIds.add(newId)
    }

    fun applyDelete(msgId: String) {
        val idx = findMessage(msgId) ?: return
        messages[idx] = messages[idx].copy(isDeleted = true, text = "")
    }

    /// Add `from` to this emoji's reactors. Idempotent: `+react` is an
    /// explicit op, not a toggle, so a re-delivered or duplicated one is a
    /// no-op rather than a removal.
    fun addReaction(msgId: String, emoji: String, from: String) {
        mutateReactions(msgId, emoji) { nicks -> nicks.add(from) }
    }

    /// Remove `from` from this emoji's reactors — what `+freeq.at/unreact`
    /// means. Dropping the emoji entirely once nobody is left on it.
    fun removeReaction(msgId: String, emoji: String, from: String) {
        mutateReactions(msgId, emoji) { nicks -> nicks.remove(from) }
    }

    /// True when `from` has already reacted with `emoji` — lets the send path
    /// decide which explicit op to transmit without inferring it from a
    /// mutation's return value.
    fun hasReaction(msgId: String, emoji: String, from: String): Boolean {
        val idx = findMessage(msgId) ?: return false
        return messages[idx].reactions[emoji]?.contains(from) == true
    }

    private fun mutateReactions(
        msgId: String,
        emoji: String,
        change: (MutableSet<String>) -> Unit,
    ) {
        val idx = findMessage(msgId) ?: return
        val msg = messages[idx]
        // Build entirely new collections — mutating in place causes old.equals(new)
        // to be true on the data class, so LazyColumn skips recomposition.
        val newReactions = mutableMapOf<String, MutableSet<String>>()
        for ((e, nicks) in msg.reactions) {
            if (e != emoji) newReactions[e] = nicks.toMutableSet()
        }
        val target = msg.reactions[emoji]?.toMutableSet() ?: mutableSetOf()
        change(target)
        if (target.isNotEmpty()) newReactions[emoji] = target
        messages[idx] = msg.copy(reactions = newReactions)
    }

    /** Apply roster-time actor classes to this channel's members. Humans are
     *  omitted by the server, so anything absent stays human. */
    fun applyActorClasses(classes: List<ActorClassEntry>) {
        for (entry in classes) {
            val idx = members.indexOfFirst { it.nick.equals(entry.nick, ignoreCase = true) }
            if (idx < 0) continue
            members[idx] = members[idx].copy(actorClass = entry.actorClass)
        }
    }

    /** Apply live agent presence to this channel's copy of the nick. */
    fun applyPresence(nick: String, state: String, status: String?) {
        val idx = members.indexOfFirst { it.nick.equals(nick, ignoreCase = true) }
        if (idx < 0) return
        val m = members[idx]
        members[idx] = m.copy(
            // Publishing presence is itself proof this is an agent.
            actorClass = m.actorClass ?: "agent",
            presenceState = state,
            presenceStatus = status
        )
    }
}

// ── Connection state ──

enum class ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Registered
}

// ── AppState ViewModel ──

class AppState(application: Application) : AndroidViewModel(application) {
    var connectionState = mutableStateOf(ConnectionState.Disconnected)
    var nick = mutableStateOf("")
    var serverAddress = mutableStateOf(ServerConfig.ircServer)
    val channels = mutableStateListOf<ChannelState>()
    var activeChannel = mutableStateOf<String?>(null)
    var errorMessage = mutableStateOf<String?>(null)
    var authenticatedDID = mutableStateOf<String?>(null)
    val dmBuffers = mutableStateListOf<ChannelState>()
    val autoJoinChannels = mutableStateListOf<String>()
    val unreadCounts = mutableStateMapOf<String, Int>()
    val mutedChannels = mutableStateListOf<String>()

    // Safety: client-side block list (Google Play UGC policy requires in-app
    // block + report). SnapshotStateLists rather than plain MutableSets so
    // hiding blocked content recomposes immediately; set semantics are
    // enforced on insert. blockedNicks entries are stored lowercased.
    val blockedDids = mutableStateListOf<String>()
    val blockedNicks = mutableStateListOf<String>()

    // DID → display nick, learned from the conversation list's partner-did
    // tag and every nick↔DID binding. Display-grade: survives the peer going
    // offline, so a DID-keyed thread keeps rendering as a name.
    val didDisplayNames = mutableStateMapOf<String, String>()

    /** Human label for a thread key that may be a raw DID (see DidDisplay). */
    fun displayNameForKey(key: String): String =
        DidDisplay.displayName(key, didDisplayNames, knownDids)

    // Nick → server-bound DID learned from message account-tags. Keyed by
    // lowercased nick. Backfills channel member entries (the FFI NAMES reply
    // carries no DID) so DID-gated UI has a real source.
    val knownDids = mutableStateMapOf<String, String>()

    // Custom status, shipped as the IRC AWAY message (matches iOS):
    // `AWAY :<text>` on set, bare `AWAY` to clear. Persisted and re-sent
    // after every (re)registration.
    var customStatus = mutableStateOf("")

    var replyingTo = mutableStateOf<ChatMessage?>(null)
    var editingMessage = mutableStateOf<ChatMessage?>(null)

    var pendingWebToken: String? = null
    var pendingNavigation = mutableStateOf<String?>(null)
    var pendingJoinChannel: String? = null  // Track user-initiated joins for navigation
    var brokerToken: String? = null
    private val authBrokerBase: String
        get() = ServerConfig.authBrokerBase
    private var brokerRetryCount = 0
    private var consecutive401Count = 0  // Require 3 consecutive 401s before nuking token

    // Keep users logged in for at least 14 days unless they explicitly log out
    private val lastLoginTime: Long
        get() = prefs.getLong("lastLoginTime", 0L)

    private val canAutoClearBrokerCredentials: Boolean
        get() {
            if (lastLoginTime == 0L) return false
            val fourteenDaysMs = 14L * 24 * 60 * 60 * 1000
            return System.currentTimeMillis() - lastLoginTime >= fourteenDaysMs
        }
    internal var intentionalDisconnect = false
    /** Set to true after a WS connect attempt has been swapped for plain
     *  TCP within a single user-initiated `connect()` call. Prevents
     *  ping-ponging between transports. Reset on each fresh `connect()`. */
    private var transportFallbackUsed = false
    var loggedOut = mutableStateOf(false)
    private var cachedWebToken: String? = null
    private var cachedWebTokenExpiry: Long = 0L  // epoch millis

    val hasSavedSession: Boolean
        // brokerToken alone is enough — broker /session call returns the real
        // handle, so we don't need a saved nick to attempt reconnect.
        get() = brokerToken != null
    val lastReadMessageIds = mutableStateMapOf<String, String>()
    val lastReadTimestamps = mutableStateMapOf<String, Long>()
    var isDarkTheme = mutableStateOf(true)

    val batches = mutableMapOf<String, BatchBuffer>()

    // MOTD
    val motdLines = mutableStateListOf<String>()
    var showMotd = mutableStateOf(false)
    internal var collectingMotd = false

    private var client: FreeqClient? = null
    private var lastTypingSent: Long = 0
    var reconnectAttempts = 0
    internal val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    /** Learns who a bare nick is before the first DM to them, so that message
     *  can be signed like every other one. */
    internal val dmResolver = DmResolver(
        nickToDid = ::didForNick,
        askWhois = { nick ->
            try {
                client?.requestWhois(nick)
            } catch (_: Exception) {}
        },
    )
    val notificationManager = FreeqNotificationManager(application)
    val networkMonitor = NetworkMonitor(application).also { it.bind(this) }

    internal val prefs: SharedPreferences
        get() = getApplication<Application>().getSharedPreferences("freeq", Context.MODE_PRIVATE)

    internal val securePrefs: SharedPreferences by lazy { buildSecurePrefs() }

    private fun createEncryptedPrefs(): SharedPreferences {
        val masterKey = MasterKey.Builder(getApplication<Application>())
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            getApplication(),
            "freeq_secure",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    /**
     * Build the encrypted store, recovering from a corrupt keyset. On some
     * devices the Keystore master key survives an uninstall in a bad state, so
     * EncryptedSharedPreferences can't decrypt its own keyset and throws
     * (AEADBadTagException) — which, unhandled, crashes AppState construction on
     * launch. Reset the keyset + master-key alias and rebuild; stored secrets
     * are re-derived on next login. Falls back to plain prefs if even that fails.
     */
    private fun buildSecurePrefs(): SharedPreferences {
        return try {
            createEncryptedPrefs()
        } catch (e: Exception) {
            android.util.Log.w("AppState", "Encrypted prefs unreadable, resetting keyset", e)
            getApplication<Application>().deleteSharedPreferences("freeq_secure")
            try {
                val ks = java.security.KeyStore.getInstance("AndroidKeyStore")
                ks.load(null)
                ks.deleteEntry("_androidx_security_master_key_")
            } catch (_: Exception) {}
            try {
                createEncryptedPrefs()
            } catch (e2: Exception) {
                android.util.Log.e("AppState", "Encrypted prefs unavailable; using plaintext prefs", e2)
                getApplication<Application>().getSharedPreferences("freeq_secure_fallback", Context.MODE_PRIVATE)
            }
        }
    }

    val activeChannelState: ChannelState?
        get() {
            val name = activeChannel.value ?: return null
            return channels.firstOrNull { it.name.equals(name, ignoreCase = true) }
                ?: dmBuffers.firstOrNull { it.name.equals(name, ignoreCase = true) }
        }

    /** The buffer with this name, channel or DM thread, if one is open. */
    fun buffer(name: String): ChannelState? =
        channels.firstOrNull { it.name.equals(name, ignoreCase = true) }
            ?: dmBuffers.firstOrNull { it.name.equals(name, ignoreCase = true) }

    /** The buffer whose task map already holds this task, if one does. A task
     *  lives in one venue, so at most one thread can answer. */
    fun bufferHoldingTask(taskId: String): String? =
        (channels + dmBuffers).firstOrNull { it.actTasks.task(taskId) != null }?.name

    init {
        // Migrate secrets from plain prefs to encrypted prefs (one-time)
        if (prefs.contains("brokerToken") || prefs.contains("did")) {
            prefs.getString("brokerToken", null)?.let { securePrefs.edit().putString("brokerToken", it).apply() }
            prefs.getString("did", null)?.let { securePrefs.edit().putString("did", it).apply() }
            prefs.edit().remove("brokerToken").remove("did").apply()
        }

        // Load secrets from encrypted storage
        brokerToken = securePrefs.getString("brokerToken", null)
        authenticatedDID.value = securePrefs.getString("did", null)
        // Restore cached web token if still valid (25 min TTL, server expires at 30 min)
        val savedExpiry = prefs.getLong("webTokenExpiry", 0L)
        if (savedExpiry > System.currentTimeMillis()) {
            cachedWebToken = securePrefs.getString("webToken", null)
            cachedWebTokenExpiry = savedExpiry
        } else {
            securePrefs.edit().remove("webToken").apply()
            prefs.edit().remove("webTokenExpiry").apply()
        }

        // Restore persisted state. If the saved nick is a Guest temp name but
        // we have a DID, the previous session got Guest-renamed and poisoned
        // the saved nick — drop it and let the broker /session call return the
        // user's real handle on next reconnect.
        val savedNick = prefs.getString("nick", "") ?: ""
        if (authenticatedDID.value != null && savedNick.startsWith("Guest", ignoreCase = true)) {
            prefs.edit().remove("nick").apply()
            nick.value = ""
        } else {
            nick.value = savedNick
        }
        serverAddress.value = prefs.getString("server", ServerConfig.ircServer) ?: ServerConfig.ircServer
        prefs.getStringSet("channels", setOf("#general"))?.forEach { ch ->
            if (ch !in autoJoinChannels) autoJoinChannels.add(ch)
        }
        if (autoJoinChannels.isEmpty()) autoJoinChannels.add("#general")
        isDarkTheme.value = prefs.getBoolean("darkTheme", true)

        // Restore read positions
        prefs.getStringSet("readPositionKeys", emptySet())?.forEach { key ->
            prefs.getString("readPos_$key", null)?.let { lastReadMessageIds[key] = it }
            val ts = prefs.getLong("readPosTime_$key", 0L)
            if (ts > 0) lastReadTimestamps[key] = ts
        }

        // Restore muted channels
        prefs.getStringSet("mutedChannels", emptySet())?.forEach { ch ->
            if (ch !in mutedChannels) mutedChannels.add(ch)
        }

        // Restore block lists
        prefs.getStringSet("blockedNicks", emptySet())?.forEach { n ->
            if (n !in blockedNicks) blockedNicks.add(n)
        }
        prefs.getStringSet("blockedDids", emptySet())?.forEach { d ->
            if (d !in blockedDids) blockedDids.add(d)
        }

        // Restore custom status
        customStatus.value = prefs.getString("customStatus", "") ?: ""

        // Hydrate channels/DMs from the on-disk cache so the UI renders the
        // last session's context before any network round-trip completes.
        hydrateBuffersFromCache()

        // Prune stale typing indicators every 3 seconds
        scope.launch {
            while (isActive) {
                delay(3000)
                pruneTypingIndicators()
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        scope.cancel()
        networkMonitor.destroy()
        client?.disconnect()
    }

    // ── Connection ──

    fun connect(nickName: String) {
        // Fresh user-initiated connect — start by preferring WebSocket again.
        transportFallbackUsed = false
        connect(nickName, useWebSocket = true)
    }

    private fun connect(nickName: String, useWebSocket: Boolean) {
        intentionalDisconnect = false
        loggedOut.value = false
        nick.value = nickName
        connectionState.value = ConnectionState.Connecting
        errorMessage.value = null

        // Don't overwrite the saved nick with a Guest temp name when we're a
        // DID-authenticated user — once that happens, every subsequent reconnect
        // sends the Guest nick, SASL fails, and the user is stuck.
        val shouldPersistNick = !(authenticatedDID.value != null
                && nickName.startsWith("Guest", ignoreCase = true))
        if (shouldPersistNick) {
            prefs.edit().putString("nick", nickName).putString("server", serverAddress.value).apply()
        } else {
            prefs.edit().putString("server", serverAddress.value).apply()
        }

        try {
            val handler = AndroidEventHandler(this)
            client = FreeqClient(serverAddress.value, nickName, handler)
            client?.setPlatform("freeq android")
            // Prefer WebSocket on 443/wss like the iOS client; pass an empty
            // string to disable WS and use the TCP `serverAddress` directly
            // (the fallback path triggered by attemptTransportFallback below).
            client?.setWebsocketUrl(if (useWebSocket) ServerConfig.wssServer else "")

            pendingWebToken?.let { token ->
                client?.setWebToken(token)
                pendingWebToken = null
            }

            client?.connect()
        } catch (e: Exception) {
            connectionState.value = ConnectionState.Disconnected
            errorMessage.value = "Connection failed: ${e.message}"
        }
    }

    /** If a Disconnected reason looks like a WS handshake / connect failure
     *  and we haven't already swapped this attempt, retry on plain TCP once.
     *  Returns true if a fallback was scheduled (caller should not also run
     *  the standard auto-reconnect path). Mirrors iOS attemptTransportFallback. */
    internal fun attemptTransportFallback(reason: String): Boolean {
        if (!TransportFallback.shouldFallback(
                reason = reason,
                transportFallbackUsed = transportFallbackUsed,
                hasSavedSession = hasSavedSession,
                nickIsEmpty = nick.value.isEmpty(),
            )) return false
        transportFallbackUsed = true
        Log.w("freeq.auth", "WS connect failed; falling back to TCP. reason=$reason")
        client?.disconnect()
        client = null
        connect(nick.value, useWebSocket = false)
        return true
    }

    // ── Buffer cache ──

    private val bufferCacheDir: File
        get() = getApplication<Application>().filesDir

    /**
     * Read cached channels/DMs from disk into the live buffers. Replayed
     * CHATHISTORY dedups against this through `appendIfNew`.
     *
     * The read + JSON decode run off the main thread — done inline in
     * `AppState` init they froze the first frame for ~720 ms at ~47
     * buffers. Applying late is safe: `appendIfNew` inserts by timestamp
     * and dedups by id, so buffers filling a beat after launch (possibly
     * after live traffic) land identically.
     */
    private fun hydrateBuffersFromCache() {
        scope.launch {
            val cached = withContext(Dispatchers.IO) { BufferCache.load(bufferCacheDir) }
                ?: return@launch
            applyCachedBuffers(cached)
        }
    }

    private fun applyCachedBuffers(cached: List<CachedBuffer>) {
        for (buf in cached) {
            val target = if (buf.isDM) getOrCreateDM(buf.name) else getOrCreateChannel(buf.name)
            // Re-teach the display label a DID-keyed thread had when it was
            // snapshotted, or a cold launch renders the compacted DID until
            // the peer's next live event. Display-direction map ONLY —
            // knownDids feeds authorship checks and addressing, and a stale
            // cache must never reach those.
            if (buf.displayName != null && DidDisplay.isDid(buf.name) &&
                !didDisplayNames.containsKey(buf.name)
            ) {
                didDisplayNames[buf.name] = buf.displayName
            }
            buf.topic?.let { target.topic.value = it }
            buf.messages.forEach { target.appendIfNew(it) }
            // Sort the chat list the way the user last saw it rather than
            // dropping every restored buffer to the bottom.
            target.messages.lastOrNull()?.let {
                target.lastActivityTime.value = it.timestamp.time
            }
        }
    }

    /** Snapshot every buffer to disk. Safe to call when nothing is connected. */
    fun flushBuffersToCache() {
        BufferCache.save(
            bufferCacheDir,
            BufferCache.snapshot(channels + dmBuffers, ::displayNameForKey),
        )
    }

    fun disconnect() {
        intentionalDisconnect = true
        // Persist before tearing down: a manual disconnect or transport
        // retry otherwise drops the session the next launch would restore.
        flushBuffersToCache()
        client?.disconnect()
        client = null  // Clear reference so reconnect creates fresh client
        connectionState.value = ConnectionState.Disconnected
        channels.clear()
        // A dropped connection ends every question that was out on it, and a
        // WHOIS answer from the old session is not a live binding on the new
        // one.
        identityLookups.clear()
        whoisNoSuchNick.clear()
        dmBuffers.clear()
        batches.clear()
        activeChannel.value = null
        replyingTo.value = null
        editingMessage.value = null
        authenticatedDID.value = null
    }

    fun cacheWebToken(token: String) {
        cachedWebToken = token
        cachedWebTokenExpiry = System.currentTimeMillis() + 25 * 60 * 1000L
        securePrefs.edit().putString("webToken", token).apply()
        prefs.edit().putLong("webTokenExpiry", cachedWebTokenExpiry).apply()
    }

    fun invalidateCachedWebToken() {
        cachedWebToken = null
        cachedWebTokenExpiry = 0L
        securePrefs.edit().remove("webToken").apply()
        prefs.edit().remove("webTokenExpiry").apply()
    }

    fun logout() {
        intentionalDisconnect = true
        loggedOut.value = true
        errorMessage.value = null
        brokerToken = null
        pendingWebToken = null
        cachedWebToken = null
        cachedWebTokenExpiry = 0L
        securePrefs.edit().remove("brokerToken").remove("did").remove("webToken").apply()
        prefs.edit().remove("nick").remove("webTokenExpiry").remove("lastLoginTime").apply()
        nick.value = ""
        disconnect()
        // After disconnect, which flushes: never leave one account's
        // messages on disk for whoever signs in next.
        BufferCache.clear(bufferCacheDir)
    }

    /**
     * @param fresh a new reconnect episode (user action, network restored,
     * disconnect event) — resets the broker retry budget. The internal
     * backoff recursion passes false so one episode still caps at 5 tries.
     */
    fun reconnectSavedSession(fresh: Boolean = true) {
        if (!hasSavedSession || connectionState.value != ConnectionState.Disconnected) return
        if (fresh) brokerRetryCount = 0
        if (pendingWebToken != null) { connect(nick.value); return }

        // Reuse cached web token if still within TTL (avoids broker round-trip)
        val cached = cachedWebToken
        if (cached != null && System.currentTimeMillis() < cachedWebTokenExpiry) {
            pendingWebToken = cached
            connect(nick.value)
            return
        }

        val token = brokerToken ?: run {
            // No broker token and cached web token expired — must sign in again
            connectionState.value = ConnectionState.Disconnected
            return
        }

        connectionState.value = ConnectionState.Connecting

        scope.launch {
            try {
                val session = withContext(Dispatchers.IO) { fetchBrokerSession(token) }
                brokerRetryCount = 0
                pendingWebToken = session.token
                cacheWebToken(session.token)
                authenticatedDID.value = session.did
                securePrefs.edit().putString("did", session.did).apply()
                connect(session.nick)
            } catch (e: Exception) {
                Log.w("freeq.auth", "reconnect: broker /session failed (retry ${brokerRetryCount + 1}): ${e.message}")
                brokerRetryCount++
                if (brokerRetryCount <= 4) {
                    val delayMs = 3000L * (1L shl (brokerRetryCount - 1)) // 3, 6, 12, 24s
                    connectionState.value = ConnectionState.Disconnected
                    delay(delayMs)
                    if (connectionState.value == ConnectionState.Disconnected) {
                        reconnectSavedSession(fresh = false)
                    }
                } else {
                    connectionState.value = ConnectionState.Disconnected
                }
            }
        }
    }

    internal data class BrokerSessionResponse(val token: String, val nick: String, val did: String)

    internal fun fetchBrokerSession(brokerToken: String): BrokerSessionResponse {
        // Retry up to 3 times with backoff — DPoP nonce rotation causes the first call to fail
        for (attempt in 0..2) {
            val url = java.net.URL("$authBrokerBase/session")
            val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                connectTimeout = 10_000
                readTimeout = 10_000
                setRequestProperty("Content-Type", "application/json")
            }
            conn.outputStream.use { out ->
                out.write("""{"broker_token":"$brokerToken"}""".toByteArray())
            }
            val status = conn.responseCode
            if (status == 502 && attempt < 2) {
                Thread.sleep(if (attempt == 0) 500 else 1000)
                continue
            }
            // 401 from /session means the broker doesn't recognize this
            // broker_token at all — its session record is gone (broker DB
            // wiped, token rotated, manual revoke). That's not a transient
            // failure: no amount of retrying will recover. Clear the bad
            // creds so hasSavedSession flips false and the UI falls back to
            // ConnectScreen for re-OAuth, instead of spinning on
            // ReconnectingScreen forever. We still wait for 3 consecutive
            // 401s in case there's a brief broker glitch, but the 14-day
            // "keep logged in" guard does not apply here — the broker has
            // *explicitly* told us it doesn't know this token.
            if (status == 401) {
                consecutive401Count++
                if (consecutive401Count >= 3) {
                    consecutive401Count = 0
                    this.brokerToken = null
                    cachedWebToken = null
                    cachedWebTokenExpiry = 0L
                    securePrefs.edit().remove("brokerToken").remove("webToken").apply()
                    prefs.edit().remove("webTokenExpiry").remove("lastLoginTime").apply()
                    throw Exception("Session expired — please sign in again")
                } else {
                    throw Exception("Auth failed (attempt $consecutive401Count/3)")
                }
            }
            if (status != 200) {
                throw Exception("Broker returned $status")
            }
            // Success — reset 401 counter
            consecutive401Count = 0
            val body = conn.inputStream.bufferedReader().readText()
            val json = org.json.JSONObject(body)
            return BrokerSessionResponse(
                token = json.getString("token"),
                nick = json.getString("nick"),
                did = json.getString("did")
            )
        }
        throw Exception("Broker failed after retries")
    }

    // ── Channel operations ──

    fun joinChannel(channel: String, navigate: Boolean = true) {
        val target = JoinTarget.parse(channel) ?: return
        // Track for navigation after JOIN confirmation (only for user-initiated joins)
        if (navigate) pendingJoinChannel = target.channel
        try {
            client?.join(target.line)
        } catch (_: Exception) {
            if (navigate) pendingJoinChannel = null
            errorMessage.value = "Failed to join ${target.channel}"
        }
    }

    fun partChannel(channel: String) {
        try {
            client?.part(channel)
        } catch (_: Exception) {}
    }

    // ── Messaging ──

    /**
     * Send what the compose bar holds — a new message, an edit, or a reply.
     *
     * Every branch goes through a typed SDK sender, which signs the message
     * and files an event id for it. Hand-built lines reach the wire as raw
     * commands, which the SDK deliberately never signs; an edit sent that way
     * carried no proof of who made it.
     *
     * `\n` is passed through untouched. The SDK auto-routes newline-bearing
     * text to a `draft/multiline` BATCH when the server acked the cap, and
     * signs the body a receiver reassembles — so the escaping this used to do
     * would have signed bytes nobody ever holds.
     */
    fun sendMessage(target: String, text: String) {
        if (text.isEmpty()) return
        stopTyping(target)
        val plan = ComposeSend.plan(
            target,
            text,
            editingId = editingMessage.value?.id,
            replyToId = replyingTo.value?.id,
        ) ?: return
        editingMessage.value = null
        replyingTo.value = null
        scope.launch {
            // A first DM to a bare nick waits, briefly, to learn who they are
            // — a nick is not a venue a signature can name. Already-known
            // peers and channels don't suspend at all.
            val venue = dmResolver.resolve(plan.target)
            try {
                when (plan) {
                    is OutboundSend.Edit -> client?.editMessage(venue, plan.msgId, plan.text)
                    is OutboundSend.Reply -> client?.reply(venue, plan.msgId, plan.text)
                    is OutboundSend.Plain -> client?.sendMessage(venue, plan.text)
                }
            } catch (_: Exception) {
                errorMessage.value = "Send failed"
            }
        }
    }

    /** Send a `/me` as a CTCP ACTION. The framing lives in the body, so the
     *  SDK signs it as the ordinary message it is. */
    fun sendAction(target: String, text: String) {
        if (text.isEmpty()) return
        stopTyping(target)
        try {
            client?.sendMessage(target, "\u0001ACTION $text\u0001")
        } catch (_: Exception) {
            errorMessage.value = "Send failed"
        }
    }

    fun sendRaw(line: String) {
        if (client == null) {
            return
        }
        try {
            client?.sendRaw(line)
        } catch (_: Exception) {}
    }

    /// Toggle our own reaction: which explicit op to send is decided from the
    /// current state, then applied locally and transmitted. Removing used to
    /// update the screen and send nothing at all, so an un-react never left
    /// the device — the reaction stayed for everyone else.
    fun sendReaction(target: String, msgId: String, emoji: String) {
        val ch = channels.firstOrNull { it.name.equals(target, ignoreCase = true) }
            ?: dmBuffers.firstOrNull { it.name.equals(target, ignoreCase = true) }
        val alreadyReacted = ch?.hasReaction(msgId, emoji, nick.value) ?: false
        if (alreadyReacted) {
            ch?.removeReaction(msgId, emoji, nick.value)
        } else {
            ch?.addReaction(msgId, emoji, nick.value)
        }
        try {
            when (val op = ReactionOp.plan(target, msgId, emoji, alreadyReacted)) {
                is ReactionSend.Add -> client?.react(op.target, op.emoji, op.msgId)
                is ReactionSend.Remove -> client?.unreact(op.target, op.emoji, op.msgId)
            }
        } catch (_: Exception) {}
    }

    fun deleteMessage(target: String, msgId: String) {
        // Optimistic local delete — server doesn't echo TAGMSG to sender
        val ch = channels.firstOrNull { it.name.equals(target, ignoreCase = true) }
            ?: dmBuffers.firstOrNull { it.name.equals(target, ignoreCase = true) }
        ch?.applyDelete(msgId)
        try {
            client?.deleteMessage(target, msgId)
        } catch (_: Exception) {}
    }

    fun sendTyping(target: String) {
        val now = System.currentTimeMillis()
        if (now - lastTypingSent < 3000) return
        lastTypingSent = now
        try {
            client?.typingStart(target)
        } catch (_: Exception) {}
    }

    /** Withdraw the typing indicator. Ephemeral either way — it carries no
     *  event id and nothing signs it, because nothing about it is worth
     *  attesting to later. */
    private fun stopTyping(target: String) {
        lastTypingSent = 0
        try {
            client?.typingStop(target)
        } catch (_: Exception) {}
    }

    /** DM threads whose history this session has asked for. A restored thread
     *  asks when it is opened; see [DmHistoryOnOpen]. */
    private val dmHistoryAsked = mutableSetOf<String>()

    fun requestHistory(channel: String) {
        // Channel history is served to any member, guests included —
        // membership is the server's only check. DM history requires an
        // authenticated DID; unauthenticated requests draw a FAIL the
        // notice handler then has to swallow. Gate only the DM case.
        val isChannel = channel.startsWith("#") || channel.startsWith("&")
        if (!isChannel && authenticatedDID.value == null) return
        if (!isChannel) dmHistoryAsked.add(channel.lowercase())
        sendRaw("CHATHISTORY LATEST $channel * 100")
    }

    /**
     * A thread was opened. A DM whose history this session never got asks for
     * it now — the page carries the thread's task events, which a DM has no
     * join to replay and which a restored buffer would otherwise never see.
     */
    fun noteThreadOpened(name: String) {
        if (DmHistoryOnOpen.shouldFetch(name, authenticatedDID.value != null, dmHistoryAsked)) {
            requestHistory(name)
        }
    }

    fun pinMessage(channel: String, msgId: String) {
        sendRaw("PIN $channel $msgId")
        PinCache.addPin(channel, msgId)
    }

    fun unpinMessage(channel: String, msgId: String) {
        sendRaw("UNPIN $channel $msgId")
        PinCache.removePin(channel, msgId)
    }

    // ── Read tracking ──

    fun markRead(channel: String) {
        unreadCounts[channel] = 0
        val buffer = channels.firstOrNull { it.name == channel }
            ?: dmBuffers.firstOrNull { it.name == channel }
        UnreadTracker.anchorMessage(buffer?.messages ?: emptyList())?.let { anchor ->
            lastReadMessageIds[channel] = anchor.id
            lastReadTimestamps[channel] = anchor.timestamp.time
            persistReadPositions()
        }
    }

    fun incrementUnread(channel: String) {
        if (UnreadTracker.shouldIncrement(channel, activeChannel.value, isMuted(channel))) {
            unreadCounts[channel] = (unreadCounts[channel] ?: 0) + 1
        }
    }

    // ── Theme ──

    fun toggleTheme() {
        isDarkTheme.value = !isDarkTheme.value
        prefs.edit().putBoolean("darkTheme", isDarkTheme.value).apply()
    }

    // ── Muted channels ──

    fun isMuted(channel: String): Boolean =
        mutedChannels.any { it.equals(channel, ignoreCase = true) }

    fun toggleMute(channel: String) {
        val existing = mutedChannels.indexOfFirst { it.equals(channel, ignoreCase = true) }
        if (existing >= 0) {
            mutedChannels.removeAt(existing)
        } else {
            mutedChannels.add(channel)
        }
        prefs.edit().putStringSet("mutedChannels", mutedChannels.toSet()).apply()
    }

    // ── Safety: block & report ──

    fun isBlocked(nick: String, did: String? = null): Boolean =
        (did != null && did in blockedDids) || nick.lowercase() in blockedNicks

    fun blockUser(nick: String, did: String? = null) {
        val n = nick.trim().lowercase()
        if (n.isNotEmpty() && n !in blockedNicks) blockedNicks.add(n)
        if (!did.isNullOrEmpty() && did !in blockedDids) blockedDids.add(did)
        persistBlockLists()
    }

    fun unblockUser(nick: String? = null, did: String? = null) {
        nick?.let { n -> blockedNicks.removeAll { it.equals(n, ignoreCase = true) } }
        did?.let { blockedDids.remove(it) }
        persistBlockLists()
    }

    /** Report = local audit-trail log + block. The log line is the record
     *  until a server-side report endpoint exists; abuse@freeq.at handles
     *  escalation (surfaced in Settings → Safety). */
    fun reportUser(nick: String, did: String? = null, reason: String) {
        Log.w("freeq.safety", "user report: nick=$nick did=${did ?: "unknown"} reason=$reason")
        blockUser(nick, did)
    }

    private fun persistBlockLists() {
        prefs.edit()
            .putStringSet("blockedNicks", blockedNicks.toSet())
            .putStringSet("blockedDids", blockedDids.toSet())
            .apply()
    }

    // ── DID identity helpers ──

    /** Server-bound DID for a nick: channel member entries first, then the
     *  account-tag map. Never derived from the nick itself (impersonation). */
    fun didForNick(nick: String): String? {
        for (ch in channels) {
            ch.members.firstOrNull { it.nick.equals(nick, ignoreCase = true) }
                ?.did?.let { return it }
        }
        return knownDids[nick.lowercase()]
    }

    /** Record a server-verified DID (from a message account-tag) on the
     *  nick's channel member entries. NAMES carries no DID over the FFI, so
     *  this is what makes DID-gated UI (verified badge, profile sheet) work. */
    /** Record a nick↔DID binding and fold any nick-keyed DM thread into the
     *  DID-keyed one, repointing the active thread. Shared by MemberDid (live
     *  learning) and the conversation list's partner-did — an OFFLINE peer
     *  never produces a live MemberDid, so without the TARGETS path a stale
     *  nick-keyed thread and the DID-keyed one coexist as duplicate rows. */
    fun adoptDmBinding(nick: String, did: String) {
        recordUserDid(nick, did)
        if (DidDisplay.mergeDmBuffers(dmBuffers, unreadCounts, nick, did)
            && activeChannel.value.equals(nick, ignoreCase = true)
        ) {
            activeChannel.value = did
        }
    }

    fun recordUserDid(nick: String, did: String) {
        knownDids[nick.lowercase()] = did
        dmResolver.learned(nick, did)
        didDisplayNames[did] = nick
        for (ch in channels) {
            val idx = ch.members.indexOfFirst { it.nick.equals(nick, ignoreCase = true) }
            if (idx >= 0 && ch.members[idx].did != did) {
                ch.members[idx] = ch.members[idx].copy(did = did)
            }
        }
    }

    // ── Custom status (IRC AWAY) ──

    fun setCustomStatus(status: String) {
        val trimmed = status.trim()
        customStatus.value = trimmed
        prefs.edit().putString("customStatus", trimmed).apply()
        sendCustomStatus()
    }

    /** Push the persisted status to the server: `AWAY :<text>`, bare `AWAY`
     *  to clear. No-op while unregistered — the Registered handler re-sends
     *  a non-empty status after every (re)connect. */
    internal fun sendCustomStatus() {
        if (connectionState.value != ConnectionState.Registered) return
        val s = customStatus.value
        sendRaw(if (s.isEmpty()) "AWAY" else "AWAY :$s")
    }

    // ── Channel helpers ──

    fun getOrCreateChannel(name: String): ChannelState {
        val trimmed = name.trim()
        return when (BufferRouter.classify(trimmed)) {
            // A bare nick handed to getOrCreateChannel must NOT be appended
            // to `channels` — it'd render in the Channels pane styled like a
            // channel and shadow real channels of the same letters.
            BufferRouter.Target.DM -> getOrCreateDM(trimmed)
            BufferRouter.Target.INVALID -> ChannelState("_empty")
            BufferRouter.Target.CHANNEL -> {
                channels.firstOrNull { it.name.equals(trimmed, ignoreCase = true) }
                    ?.let { return it }
                val channel = ChannelState(trimmed)
                channels.add(channel)
                channel
            }
        }
    }

    fun getOrCreateDM(nick: String): ChannelState {
        val trimmed = nick.trim()
        return when (BufferRouter.classify(trimmed)) {
            // Caller handed us a channel-prefixed name; route to channels
            // instead. Same anti-shadowing reason as in getOrCreateChannel.
            BufferRouter.Target.CHANNEL -> getOrCreateChannel(trimmed)
            BufferRouter.Target.INVALID -> ChannelState("_empty")
            BufferRouter.Target.DM -> {
                // Key by resolved identity: a typed nick whose DID is known
                // must land in the existing DID-keyed thread, not fork a
                // second one that only merges on the next inbound event.
                val key = DidDisplay.canonicalDmKey(trimmed, ::didForNick)
                // Ask who they are the moment the thread opens, so the first
                // message doesn't have to wait on the answer to be signed.
                dmResolver.probe(key)
                dmBuffers.firstOrNull { it.name.equals(key, ignoreCase = true) }
                    ?.let { return it }
                val dm = ChannelState(key)
                dm.lastActivityTime.value = 0L // Don't appear as recent until a message arrives.
                dmBuffers.add(dm)
                requestHistory(key)
                dm
            }
        }
    }

    // ── Persistence ──

    internal fun persistChannels() {
        prefs.edit().putStringSet("channels", autoJoinChannels.toSet()).apply()
    }

    private fun persistReadPositions() {
        val editor = prefs.edit()
        editor.putStringSet("readPositionKeys", lastReadMessageIds.keys.toSet())
        lastReadMessageIds.forEach { (key, value) -> editor.putString("readPos_$key", value) }
        lastReadTimestamps.forEach { (key, value) -> editor.putLong("readPosTime_$key", value) }
        editor.apply()
    }

    private fun pruneTypingIndicators() {
        val cutoff = Date().time - 5000
        for (ch in channels + dmBuffers) {
            val stale = ch.typingUsers.filter { it.value.time < cutoff }.keys.toList()
            stale.forEach { ch.typingUsers.remove(it) }
        }
    }

    fun renameUser(oldNick: String, newNick: String) {
        for (ch in channels) {
            val idx = ch.members.indexOfFirst { it.nick.equals(oldNick, ignoreCase = true) }
            if (idx >= 0) {
                ch.members[idx] = ch.members[idx].copy(nick = newNick)
            }
            ch.typingUsers.remove(oldNick)?.let { ch.typingUsers[newNick] = it }
        }
        val dmIdx = dmBuffers.indexOfFirst { it.name.equals(oldNick, ignoreCase = true) }
        if (dmIdx >= 0) {
            val old = dmBuffers[dmIdx]
            val renamed = ChannelState(newNick)
            renamed.messages.addAll(old.messages)
            renamed.members.addAll(old.members)
            renamed.topic.value = old.topic.value
            renamed.typingUsers.putAll(old.typingUsers)
            dmBuffers.removeAt(dmIdx)
            dmBuffers.add(renamed)
            unreadCounts.remove(old.name)?.let { unreadCounts[newNick] = it }
        }
        if (nick.value.equals(oldNick, ignoreCase = true)) {
            nick.value = newNick
        }
        knownDids.remove(oldNick.lowercase())?.let { did ->
            knownDids[newNick.lowercase()] = did
            didDisplayNames[did] = newNick
        }
        // An identity answer is about a nick, and a rename moves the nick.
        // Drop both sides rather than let one person's answer describe
        // whoever picks the name up next.
        identityLookups.remove(oldNick.lowercase())
        identityLookups.remove(newNick.lowercase())
    }

    // ── Identity lookup for a surface the reader opened ──

    /** Where the ask stands for each nick a card has asked about, keyed
     *  lowercased. Read by identity surfaces so they can say a lookup is under
     *  way rather than declaring the sender unknown before anyone asked. */
    val identityLookups = mutableStateMapOf<String, IdentityLookup>()

    /** Nicks the server answered with "no such nick". They are not guests —
     *  nobody is holding the name, so there is nobody to have an account. */
    private val whoisNoSuchNick = mutableSetOf<String>()

    /** Only a backstop; the real answer is the server's end-of-WHOIS. Matches
     *  the macOS client's budget. */
    private val identityLookupBackstopMs = 5_000L

    /**
     * Ask who this nick is, for a card the reader just opened.
     *
     * Asks once. A nick we can already name needs nothing; an ask already out
     * is not repeated; and an answer we have — "no account", the guest case —
     * stands until something could have changed it, so reopening the same card
     * doesn't re-interrogate the server. An answer that names nobody at all
     * leaves nothing behind, so that one can be asked again.
     */
    fun lookUpIdentity(nick: String) {
        val key = nick.trim().lowercase()
        if (key.isEmpty()) return
        if (liveDidForNick(key) != null || identityLookups.containsKey(key)) return
        whoisNoSuchNick.remove(key)
        identityLookups[key] = IdentityLookup.IN_FLIGHT
        try {
            client?.requestWhois(nick)
        } catch (_: Exception) {}
        // The answer normally arrives as the server's own end-of-WHOIS. This
        // only catches a server that goes quiet mid-answer, or a socket that
        // drops with the ask still out: without it the card spins for the rest
        // of the session, because an ask already in flight is never repeated.
        scope.launch {
            delay(identityLookupBackstopMs)
            abandonIdentityLookup(key)
        }
    }

    /** The ask never came back. That is a fact about the connection, not about
     *  the person, so nothing is claimed and the next card may ask again. */
    private fun abandonIdentityLookup(key: String) {
        if (identityLookups[key] == IdentityLookup.IN_FLIGHT) {
            identityLookups.remove(key)
        }
    }

    /** The server says nobody holds this name. */
    fun noteWhoisNoSuchNick(nick: String) {
        whoisNoSuchNick.add(nick.trim().lowercase())
    }

    /**
     * The server has finished answering. Whatever it did or didn't say is the
     * answer now, so the card stops waiting.
     *
     * A DID that arrived speaks for itself. Otherwise the server answered about
     * a real person and named no account — a guest — unless it told us nobody
     * holds the name at all, which says nothing about anybody.
     */
    fun settleIdentityLookup(nick: String) {
        val key = nick.trim().lowercase()
        if (identityLookups[key] != IdentityLookup.IN_FLIGHT) return
        // Nobody-holds-this-name always wins: a 401 says nothing about
        // anybody, and a DID the cache happens to remember must never be
        // laundered into "the answer named one" — that is the stale-cache
        // vote this whole design exists to end.
        if (key in whoisNoSuchNick) {
            identityLookups.remove(key)
        } else if (didForNick(key) != null) {
            identityLookups[key] = IdentityLookup.ANSWERED_DID
        } else {
            identityLookups[key] = IdentityLookup.NO_ACCOUNT
        }
    }

    /** What a card should assume about this nick right now. */
    fun identityLookup(nick: String): IdentityLookup =
        identityLookups[nick.trim().lowercase()] ?: IdentityLookup.NOT_ASKED

    /** True when the nick is in some channel roster right now. */
    fun isNickPresent(nick: String): Boolean {
        for (ch in channels) {
            if (ch.members.any { it.nick.equals(nick, ignoreCase = true) }) return true
        }
        return false
    }

    /**
     * The nick's DID, only when it is live-known: the nick is in a roster
     * right now, or a WHOIS answered with it this session. A binding
     * remembered from an earlier session never votes on identity — that is
     * how one absent sender used to read differently on different clients.
     * The persisted map stays for display and addressing, where staleness
     * costs a name, not a claim.
     */
    fun liveDidForNick(nick: String): String? {
        val key = nick.trim().lowercase()
        val answered = identityLookups[key] == IdentityLookup.ANSWERED_DID
        return if (answered || isNickPresent(nick)) didForNick(key) else null
    }

    /** The lookup state in the SDK's vocabulary, for the claim functions. */
    fun personLookup(nick: String): com.freeq.ffi.PersonLookup {
        val key = nick.trim().lowercase()
        return when {
            identityLookups[key] == IdentityLookup.IN_FLIGHT -> com.freeq.ffi.PersonLookup.IN_FLIGHT
            identityLookups[key] == IdentityLookup.NO_ACCOUNT -> com.freeq.ffi.PersonLookup.NO_ACCOUNT
            key in whoisNoSuchNick -> com.freeq.ffi.PersonLookup.NO_SUCH_NICK
            else -> com.freeq.ffi.PersonLookup.NOT_ASKED
        }
    }

    fun awayMessage(nick: String): String? {
        for (ch in channels) {
            val member = ch.members.firstOrNull { it.nick.equals(nick, ignoreCase = true) }
            if (member?.awayMsg != null) return member.awayMsg
        }
        return null
    }

    fun updateAwayStatus(nick: String, awayMsg: String?) {
        for (ch in channels) {
            val idx = ch.members.indexOfFirst { it.nick.equals(nick, ignoreCase = true) }
            if (idx >= 0) {
                ch.members[idx] = ch.members[idx].copy(awayMsg = awayMsg)
            }
        }
    }
}

// ── Event handler ──

class AndroidEventHandler(private val state: AppState) : EventHandler {
    override fun onEvent(event: FreeqEvent) {
        CoroutineScope(Dispatchers.Main).launch {
            handleEvent(event)
        }
    }

    private fun handleEvent(event: FreeqEvent) {
        when (event) {
            is FreeqEvent.Connected -> {
                state.connectionState.value = ConnectionState.Connected
            }

            is FreeqEvent.Registered -> {
                state.reconnectAttempts = 0
                // If authenticated user got Guest nick, token was stale — retry broker
                if (state.authenticatedDID.value != null
                    && event.nick.startsWith("Guest", ignoreCase = true)) {
                    state.disconnect()
                    // The cached web-token we just sent is single-use and the
                    // server consumed it on the failed SASL attempt. Wipe it
                    // so reconnectSavedSession falls through to broker
                    // /session for a fresh token (matches iOS).
                    state.invalidateCachedWebToken()
                    state.scope.launch {
                        delay(2000)
                        if (state.connectionState.value == ConnectionState.Disconnected
                            && state.hasSavedSession) {
                            state.pendingWebToken = null
                            state.reconnectSavedSession()
                        }
                    }
                    return
                }
                state.connectionState.value = ConnectionState.Registered
                state.nick.value = event.nick
                // Auto-join saved channels (no navigation - don't override user's position)
                for (channel in state.autoJoinChannels.toList()) {
                    state.joinChannel(channel, navigate = false)
                }
                // Fetch DM conversation list if authenticated
                if (state.authenticatedDID.value != null) {
                    state.sendRaw("CHATHISTORY TARGETS * * 50")
                }
                // Re-assert persisted custom status (AWAY) on every
                // (re)registration — the server forgets it across connections.
                if (state.customStatus.value.isNotEmpty()) {
                    state.sendCustomStatus()
                }
            }

            is FreeqEvent.Authenticated -> {
                state.authenticatedDID.value = event.did
                state.securePrefs.edit().putString("did", event.did).apply()
                // Refresh login timestamp on every successful auth so
                // hasSavedSession's grace window doesn't expire on a
                // long-lived registered user (matches iOS).
                state.prefs.edit().putLong("lastLoginTime", System.currentTimeMillis()).apply()
            }

            is FreeqEvent.AuthFailed -> {
                state.errorMessage.value = "Auth failed: ${event.reason}"
            }

            is FreeqEvent.Joined -> {
                val ch = state.getOrCreateChannel(event.channel)
                if (event.nick.equals(state.nick.value, ignoreCase = true)) {
                    // We joined — clear stale members before NAMES arrives
                    ch.members.clear()
                }
                // Add joiner to members if not already present
                if (ch.members.none { it.nick.equals(event.nick, ignoreCase = true) }) {
                    ch.members.add(MemberInfo(
                        nick = event.nick, isOp = false, isVoiced = false,
                        did = state.knownDids[event.nick.lowercase()]
                    ))
                }
                if (event.nick.equals(state.nick.value, ignoreCase = true)) {
                    // Navigate if this was a user-initiated join
                    if (state.pendingJoinChannel?.equals(event.channel, ignoreCase = true) == true) {
                        state.pendingJoinChannel = null
                        state.pendingNavigation.value = event.channel
                    } else if (state.activeChannel.value == null) {
                        state.activeChannel.value = event.channel
                    }
                    if (state.autoJoinChannels.none { it.equals(event.channel, ignoreCase = true) }) {
                        state.autoJoinChannels.add(event.channel)
                        state.persistChannels()
                    }
                    // Only request history if channel has no messages yet (avoid duplicate requests)
                    if (ch.messages.isEmpty()) {
                        state.requestHistory(event.channel)
                    }
                }
                ch.appendIfNew(ChatMessage(
                    id = UUID.randomUUID().toString(),
                    from = "",
                    text = "${event.nick} joined",
                    isAction = false,
                    timestamp = Date()
                ))
            }

            is FreeqEvent.Parted -> {
                if (event.nick.equals(state.nick.value, ignoreCase = true)) {
                    state.channels.removeAll { it.name == event.channel }
                    state.autoJoinChannels.removeAll { it.equals(event.channel, ignoreCase = true) }
                    state.persistChannels()
                    if (state.activeChannel.value == event.channel) {
                        state.activeChannel.value = state.channels.firstOrNull()?.name
                    }
                } else {
                    val ch = state.getOrCreateChannel(event.channel)
                    ch.appendIfNew(ChatMessage(
                        id = UUID.randomUUID().toString(),
                        from = "",
                        text = "${event.nick} left",
                        isAction = false,
                        timestamp = Date()
                    ))
                    ch.members.removeAll { it.nick.equals(event.nick, ignoreCase = true) }
                }
            }

            is FreeqEvent.Message -> {
                val ircMsg = event.msg
                val isSelf = ircMsg.fromNick.equals(state.nick.value, ignoreCase = true)

                // Prefetch avatar using DID if available (from account-tag),
                // and record the server-bound DID on member entries so the
                // verified badge / profile sheet gate on real identity.
                ircMsg.account?.let { did ->
                    AvatarCache.prefetch(ircMsg.fromNick, did)
                    state.recordUserDid(ircMsg.fromNick, did)
                }

                // Blocked sender: message is still stored (hidden at render
                // so unblocking restores history) but must not notify or
                // count as unread.
                val fromBlocked = !isSelf && state.isBlocked(
                    ircMsg.fromNick,
                    ircMsg.account ?: state.didForNick(ircMsg.fromNick)
                )

                // Handle pin/unpin sync broadcasts
                if (ircMsg.pinMsgid != null && ircMsg.target.startsWith("#")) {
                    PinCache.addPin(ircMsg.target, ircMsg.pinMsgid!!)
                    val ch = state.getOrCreateChannel(ircMsg.target)
                    ch.appendIfNew(ChatMessage(
                        id = UUID.randomUUID().toString(),
                        from = "",
                        text = "${ircMsg.fromNick} pinned a message",
                        isAction = false,
                        timestamp = Date()
                    ))
                    return
                }
                if (ircMsg.unpinMsgid != null && ircMsg.target.startsWith("#")) {
                    PinCache.removePin(ircMsg.target, ircMsg.unpinMsgid!!)
                    val ch = state.getOrCreateChannel(ircMsg.target)
                    ch.appendIfNew(ChatMessage(
                        id = UUID.randomUUID().toString(),
                        from = "",
                        text = "${ircMsg.fromNick} unpinned a message",
                        isAction = false,
                        timestamp = Date()
                    ))
                    return
                }

                val msg = MessageMapper.fromIrc(ircMsg)

                // Handle edits (prefer editOf, fall back to replacesMsgid)
                val editTarget = ircMsg.editOf ?: ircMsg.replacesMsgid
                if (editTarget != null) {
                    val batchId = ircMsg.batchId
                    if (batchId != null) {
                        state.batches[batchId]?.let { batch ->
                            val idx = batch.messages.indexOfFirst { it.id == editTarget }
                            if (idx >= 0) {
                                val held = batch.messages[idx]
                                // Reactions attach to the msgid the user reacted
                                // to — usually the latest edit id — so replay
                                // delivers them ON the edit row; merge them or
                                // reactions on edited messages vanish every
                                // relaunch. (The id deliberately stays the
                                // original's: the flush dedupe is id-only, and
                                // re-keying would append a duplicate beside a
                                // held copy after an offline-window edit. An
                                // edit-anchor merge at flush is the follow-up
                                // that unlocks re-keying.)
                                for ((emoji, nicks) in msg.reactions) {
                                    if (nicks.isNotEmpty()) held.reactions[emoji] = nicks
                                }
                                batch.messages[idx] = held.copy(
                                    text = ircMsg.text,
                                    isEdited = true,
                                )
                            } else {
                                batch.messages.add(msg)
                            }
                        }
                        return
                    }
                    val ch = if (ircMsg.target.startsWith("#")) {
                        state.channels.firstOrNull { it.name.equals(ircMsg.target, ignoreCase = true) }
                    } else {
                        val bufferName = if (isSelf) ircMsg.target else ircMsg.fromNick
                        state.dmBuffers.firstOrNull { it.name.equals(bufferName, ignoreCase = true) }
                    }
                    if (ch != null && MessageAuthorship.actorIsAuthor(
                            ch, editTarget, ircMsg.fromNick, ircMsg.account, state::didForNick
                        )
                    ) {
                        ch.applyEdit(editTarget, ircMsg.msgid, ircMsg.text)
                    }
                    ch?.typingUsers?.remove(ircMsg.fromNick)
                    return
                }

                // If part of CHATHISTORY batch, buffer for later merge
                val batchId = ircMsg.batchId
                if (batchId != null && state.batches.containsKey(batchId)) {
                    state.batches[batchId]?.messages?.add(msg)
                    return
                }

                if (ircMsg.target.startsWith("#")) {
                    val ch = state.getOrCreateChannel(ircMsg.target)
                    ch.appendIfNew(msg)
                    if (!fromBlocked) state.incrementUnread(ircMsg.target)
                    ch.typingUsers.remove(ircMsg.fromNick)

                    if (!isSelf && !fromBlocked && !state.isMuted(ircMsg.target) && ircMsg.text.contains(state.nick.value, ignoreCase = true)) {
                        state.notificationManager.sendMessageNotification(
                            from = ircMsg.fromNick, text = ircMsg.text, channel = ircMsg.target
                        )
                    }
                } else {
                    // Our OWN echoed DM carries the recipient's nick as
                    // `target` and their canonical DID as `dmKey`. Adopt that
                    // binding FIRST so a thread opened by nick folds into the
                    // DID-keyed thread the echo routes to — otherwise the
                    // sender never sees their own DM until the peer replies.
                    DmEcho.recipientBinding(isSelf, ircMsg.target, ircMsg.dmKey)?.let { (n, d) ->
                        state.adoptDmBinding(n, d)
                    }
                    // The SDK's canonical conversation key (peer DID when
                    // known, else nick) — one person, one thread. Fallback
                    // preserves behavior against an older SDK.
                    val bufferName = ircMsg.dmKey
                        ?: (if (isSelf) ircMsg.target else ircMsg.fromNick)
                    val dm = state.getOrCreateDM(bufferName)
                    dm.appendIfNew(msg)
                    if (!fromBlocked) state.incrementUnread(bufferName)

                    if (!isSelf && !fromBlocked) {
                        state.notificationManager.sendMessageNotification(
                            from = ircMsg.fromNick, text = ircMsg.text, channel = bufferName
                        )
                    }
                }
            }

            is FreeqEvent.Names -> {
                // Add or update members from NAMES reply (may arrive in multiple 353 batches)
                val ch = state.getOrCreateChannel(event.channel)
                for (m in event.members) {
                    val idx = ch.members.indexOfFirst { it.nick.equals(m.nick, ignoreCase = true) }
                    if (idx >= 0) {
                        // Update existing member with correct op/voice status from NAMES
                        ch.members[idx] = ch.members[idx].copy(
                            isOp = m.isOp,
                            isHalfop = m.isHalfop,
                            isVoiced = m.isVoiced,
                            awayMsg = m.awayMsg ?: ch.members[idx].awayMsg
                        )
                    } else {
                        ch.members.add(MemberInfo(
                            nick = m.nick, isOp = m.isOp, isHalfop = m.isHalfop,
                            isVoiced = m.isVoiced, awayMsg = m.awayMsg,
                            did = state.knownDids[m.nick.lowercase()]
                        ))
                    }
                }
                AvatarCache.prefetchAll(event.members.map { it.nick })
                // Prefetch pins for channels
                if (event.channel.startsWith("#")) {
                    PinCache.prefetch(event.channel)
                }
            }

            is FreeqEvent.TopicChanged -> {
                val ch = state.getOrCreateChannel(event.channel)
                ch.topic.value = event.topic.text
            }

            is FreeqEvent.ModeChanged -> {
                val nick = event.arg ?: return
                val ch = state.channels.firstOrNull { it.name.equals(event.channel, ignoreCase = true) } ?: return
                val idx = ch.members.indexOfFirst { it.nick.equals(nick, ignoreCase = true) }
                if (idx >= 0) {
                    val m = ch.members[idx]
                    ch.members[idx] = when (event.mode) {
                        "+o" -> m.copy(isOp = true)
                        "-o" -> m.copy(isOp = false)
                        "+h" -> m.copy(isHalfop = true)
                        "-h" -> m.copy(isHalfop = false)
                        "+v" -> m.copy(isVoiced = true)
                        "-v" -> m.copy(isVoiced = false)
                        else -> m
                    }
                }
            }

            is FreeqEvent.Kicked -> {
                if (event.nick.equals(state.nick.value, ignoreCase = true)) {
                    state.channels.removeAll { it.name == event.channel }
                    state.autoJoinChannels.removeAll { it.equals(event.channel, ignoreCase = true) }
                    state.persistChannels()
                    if (state.activeChannel.value == event.channel) {
                        state.activeChannel.value = state.channels.firstOrNull()?.name
                    }
                    state.errorMessage.value = "Kicked from ${event.channel} by ${event.by}: ${event.reason}"
                } else {
                    val ch = state.getOrCreateChannel(event.channel)
                    ch.appendIfNew(ChatMessage(
                        id = UUID.randomUUID().toString(),
                        from = "",
                        text = "${event.nick} was kicked by ${event.by} (${event.reason})",
                        isAction = false,
                        timestamp = Date()
                    ))
                    ch.members.removeAll { it.nick.equals(event.nick, ignoreCase = true) }
                }
            }

            is FreeqEvent.UserQuit -> {
                for (ch in state.channels) {
                    ch.members.removeAll { it.nick.equals(event.nick, ignoreCase = true) }
                    ch.typingUsers.remove(event.nick)
                }
            }

            is FreeqEvent.Notice -> {
                val text = event.text
                if (text == "MOTD:START") {
                    state.collectingMotd = true
                    state.motdLines.clear()
                } else if (text == "MOTD:END") {
                    state.collectingMotd = false
                    if (state.motdLines.isNotEmpty()) {
                        val content = state.motdLines.joinToString("\n")
                        val hash = content.hashCode().toString(36)
                        val seenHash = state.prefs.getString("motd_seen_hash", null)
                        if (hash != seenHash) {
                            state.showMotd.value = true
                        }
                    }
                } else if (text.startsWith("MOTD:") && state.collectingMotd) {
                    state.motdLines.add(text.removePrefix("MOTD:"))
                } else if (text.startsWith("__")) {
                    // Internal SDK signal — ignore
                } else if (text.startsWith("CHATHISTORY ")) {
                    // FAIL CHATHISTORY responses — don't toast these
                } else if (!state.collectingMotd && text.isNotBlank()) {
                    // Server error or notice — show to user
                    state.errorMessage.value = text
                }
            }

            is FreeqEvent.Disconnected -> {
                state.connectionState.value = ConnectionState.Disconnected
                if (event.reason.isNotEmpty() && !state.intentionalDisconnect) {
                    state.errorMessage.value = "Disconnected: ${event.reason}"
                }
                // If the WS handshake failed on this attempt, swap to plain
                // TCP once before falling through to broker-session retry.
                if (!state.intentionalDisconnect && state.attemptTransportFallback(event.reason)) {
                    return
                }
                // Auto-reconnect: prefer broker session restore, fall back to plain reconnect
                if (state.nick.value.isNotEmpty() && !state.intentionalDisconnect) {
                    state.reconnectAttempts++
                    val delay = ReconnectBackoff.delaySeconds(state.reconnectAttempts)
                    state.scope.launch {
                        kotlinx.coroutines.delay(delay * 1000)
                        if (state.connectionState.value == ConnectionState.Disconnected
                            && state.nick.value.isNotEmpty()) {
                            if (state.hasSavedSession) {
                                state.reconnectSavedSession()
                            } else {
                                state.connect(state.nick.value)
                            }
                        }
                    }
                }
            }

            is FreeqEvent.TagMsg -> {
                val tags = event.msg.tags.associate { it.key to it.value }
                val target = event.msg.target
                val from = event.msg.from
                fun lookupBuffer(name: String): ChannelState? =
                    if (name.startsWith("#"))
                        state.channels.firstOrNull { it.name.equals(name, ignoreCase = true) }
                    else
                        state.dmBuffers.firstOrNull { it.name.equals(name, ignoreCase = true) }

                // Typing indicators. Our own typing — echo or another of
                // our devices — never renders as "someone is typing".
                tags["+typing"]?.let { typing ->
                    if (from.equals(state.nick.value, ignoreCase = true)) return@let
                    val bufferName = TagMsgRouter.routeTo(target, from, state.nick.value, event.msg.dmKey)
                    lookupBuffer(bufferName)?.let { ch ->
                        if (typing == "active") ch.typingUsers[from] = Date()
                        else if (typing == "done") ch.typingUsers.remove(from)
                    }
                }

                // Message deletion. Applies for self events too: our own
                // other device's deletes arrive under our nick, and
                // applyDelete is idempotent so a true echo is harmless.
                tags["+draft/delete"]?.let { deleteId ->
                    val bufferName = TagMsgRouter.routeTo(target, from, state.nick.value, event.msg.dmKey)
                    val buf = lookupBuffer(bufferName) ?: return@let
                    val account = tags["account"] ?: tags["+freeq.at/account"]
                    if (MessageAuthorship.actorIsAuthor(
                            buf, deleteId, from, account, state::didForNick
                        )
                    ) {
                        buf.applyDelete(deleteId)
                    }
                }

                // Reactions (self-echo already applied optimistically by
                // sendReaction). Explicit ops, never a toggle: a re-delivered
                // `+react` must be a no-op, and an unreact must remove —
                // unreact wasn't handled here at all, so a reaction someone
                // took back stayed on screen until a history refetch.
                val replyId = tags["+reply"]
                val addEmoji = tags["+react"]
                val removeEmoji = tags["+freeq.at/unreact"]
                if (replyId != null && (addEmoji != null || removeEmoji != null)) {
                    val bufferName = TagMsgRouter.routeTo(target, from, state.nick.value, event.msg.dmKey)
                    val buf = lookupBuffer(bufferName)
                    if (addEmoji != null) buf?.addReaction(replyId, addEmoji, from)
                    if (removeEmoji != null) buf?.removeReaction(replyId, removeEmoji, from)
                }
            }

            is FreeqEvent.Act -> {
                // A task event rides as a TAGMSG, so it names its venue the
                // way every other TAGMSG does. The SDK has already read the
                // tags and dropped the repeats a joiner is handed.
                val act = event.event
                // Where the event was said, and then where its task lives: a
                // receipt the home signs for itself is keyed by the server, so
                // the venue alone would file a DM's confirm in a thread named
                // after the server rather than beside the moves it confirms.
                val venue =
                    TagMsgRouter.routeTo(act.target, act.from, state.nick.value, act.dmKey)
                val bufferName = ActEventRouting.buffer(
                    venue = venue,
                    taskId = act.taskId,
                    eventId = act.eventId,
                    bufferHoldingTask = state.bufferHoldingTask(act.taskId),
                    hasBuffer = { name -> state.buffer(name) != null },
                ) ?: return
                val buf = if (bufferName.startsWith("#")) {
                    state.getOrCreateChannel(bufferName)
                } else {
                    state.getOrCreateDM(bufferName)
                }
                val line = buf.recordActEvent(
                    ActEventInput(
                        from = act.from,
                        did = act.did,
                        kind = act.kind,
                        verb = act.verb,
                        eventId = act.eventId,
                        taskId = act.taskId,
                        fields = act.fields.associate { it.key to it.value },
                    )
                )
                buf.pairActCompanions()
                // The home signs confirm and expire itself and sends no line
                // beside them, so the room hears about those two here. Dated
                // by the id the home minted the event under — a receipt handed
                // back on join is old news, and saying "now" would date it
                // wrong and file it under the newest thing said. Keyed by that
                // id too, so a replayed receipt lands on the dedup rather than
                // printing twice.
                if (line != null) {
                    buf.appendIfNew(
                        ChatMessage(
                            id = act.eventId,
                            from = "",
                            text = line,
                            isAction = false,
                            timestamp = actEventTimeMs(act.eventId)?.let { Date(it) } ?: Date(),
                        )
                    )
                }
            }

            is FreeqEvent.NickChanged -> {
                state.renameUser(event.oldNick, event.newNick)
            }

            is FreeqEvent.AwayChanged -> {
                state.updateAwayStatus(event.nick, event.awayMsg)
            }

            is FreeqEvent.ActorClasses -> {
                val ch = state.channels.firstOrNull { it.name.equals(event.channel, ignoreCase = true) }
                ch?.applyActorClasses(event.classes)
            }

            // Every channel, so a working agent reads as working everywhere
            // it is visible. `task` is not shown.
            is FreeqEvent.Presence -> {
                for (ch in state.channels) {
                    ch.applyPresence(event.nick, event.state, event.status)
                }
            }

            is FreeqEvent.BatchStart -> {
                state.batches[event.id] = BatchBuffer(target = event.target, batchType = event.batchType)
            }

            is FreeqEvent.BatchEnd -> {
                val batch = state.batches.remove(event.id) ?: return
                if (batch.target.isEmpty()) return
                val ch = if (batch.target.startsWith("#"))
                    state.getOrCreateChannel(batch.target)
                else
                    state.getOrCreateDM(batch.target)
                BatchFlush.flushInto(batch, ch)
                if (BatchFlush.isExhaustedHistory(batch)) {
                    ch.hasMoreHistory.value = false
                }
            }

            is FreeqEvent.ChatHistoryTarget -> {
                // Create a DM buffer for each conversation partner and seed
                // its last-activity from the server-time tag so the chat
                // list orders correctly on cold launch before per-DM
                // history backfills (matches iOS 70c4ae3/6dff8b2).
                // Key by the conversation's stable identity when the server
                // names it (freeq.at/partner-did); the display nick renders
                // via displayNameForKey.
                val key = event.partnerDid ?: event.nick
                // Record the binding AND merge, exactly like MemberDid — an
                // offline peer never emits one, so a leftover nick-keyed
                // thread would otherwise duplicate the DID-keyed row.
                event.partnerDid?.let { state.adoptDmBinding(event.nick, it) }
                val dm = state.getOrCreateDM(key)
                dm.seedActivityFromTarget(event.timestamp)
                // The server has just named this conversation. Holding nothing
                // for it means either a thread restored empty or one never
                // fetched — and getOrCreateDM only asks for a thread it had to
                // create, so a restored one would never ask at all. A thread
                // with no messages is also hidden from the chat list, so this
                // is what makes it visible again.
                if (dm.messages.isEmpty()) state.requestHistory(key)
            }

            is FreeqEvent.MemberDid -> {
                // A nick↔DID binding was learned (join/whois/account tag).
                // Record it and fold any nick-keyed DM thread into the
                // DID-keyed one — a cold first DM keys by nick until now.
                state.adoptDmBinding(event.nick, event.did)
            }

            is FreeqEvent.WhoisReply -> {
                // "No such nick" is an answer about the name, not about a
                // person: an unheld name has nobody to have an account.
                if (event.info.contains("No such nick")) {
                    state.noteWhoisNoSuchNick(event.nick)
                }
            }

            // The server has finished. A card that was waiting has its answer
            // now, whatever the answer turned out to be.
            is FreeqEvent.WhoisEnd -> {
                state.settleIdentityLookup(event.nick)
            }

            is FreeqEvent.ReadMarker -> {
                // draft/read-marker (cross-device read state). No UI effect yet
                // — mirrors iOS/macOS, which just store the latest marker.
            }
        }
    }
}
