package com.freeq.model

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Date

/** One buffer as it sits on disk. */
internal data class CachedBuffer(
    val name: String,
    val isDM: Boolean,
    val topic: String?,
    val messages: List<ChatMessage>,
)

/**
 * On-disk cache of the last-seen conversation state, so a cold launch —
 * including the ones Android forces by killing the process — renders the
 * previous session's messages instead of empty buffers. Replayed
 * CHATHISTORY merges over the top through `ChannelState.appendIfNew`.
 *
 * Pure functions plus file IO against a caller-supplied directory, which
 * keeps the whole thing unit-testable.
 */
internal object BufferCache {
    const val VERSION = 1
    const val MAX_MESSAGES_PER_BUFFER = 50
    const val FILE_NAME = "buffers.json"

    private val UUID_SHAPE =
        Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOption.IGNORE_CASE)

    /**
     * Messages with a locally-minted id are not cached. Join/part notices
     * and anything the server never assigned a msgid get a random UUID;
     * the server's own ids are ULIDs. Since dedup on replay is by id, a
     * locally-minted one can never match what history sends back, so
     * caching it would stack a fresh copy beside the replayed message.
     */
    fun isLocallyMintedId(id: String): Boolean = UUID_SHAPE.matches(id)

    /** Snapshot live buffers, newest [MAX_MESSAGES_PER_BUFFER] each. */
    fun snapshot(buffers: List<ChannelState>): List<CachedBuffer> = buffers.map { buf ->
        val persistable = buf.messages.filterNot { isLocallyMintedId(it.id) }
        CachedBuffer(
            name = buf.name,
            isDM = !(buf.name.startsWith("#") || buf.name.startsWith("&")),
            topic = buf.topic.value.takeIf { it.isNotEmpty() },
            messages = persistable.takeLast(MAX_MESSAGES_PER_BUFFER),
        )
    }

    fun encode(buffers: List<CachedBuffer>): String {
        val arr = JSONArray()
        for (buf in buffers) {
            val messages = JSONArray()
            for (m in buf.messages) {
                val reactions = JSONObject()
                for ((emoji, nicks) in m.reactions) {
                    reactions.put(emoji, JSONArray(nicks.toList()))
                }
                messages.put(
                    JSONObject()
                        .put("id", m.id)
                        .put("from", m.from)
                        .put("text", m.text)
                        .put("isAction", m.isAction)
                        .put("timestamp", m.timestamp.time)
                        .put("replyTo", m.replyTo)
                        .put("isEdited", m.isEdited)
                        .put("isDeleted", m.isDeleted)
                        .put("isSigned", m.isSigned)
                        .put("origin", m.origin)
                        .put("reactions", reactions)
                )
            }
            arr.put(
                JSONObject()
                    .put("name", buf.name)
                    .put("isDM", buf.isDM)
                    .put("topic", buf.topic)
                    .put("messages", messages)
            )
        }
        return JSONObject().put("version", VERSION).put("buffers", arr).toString()
    }

    /**
     * Returns null for anything this build cannot use — a cache written by
     * a different version, or one that no longer parses. Callers discard
     * rather than migrate; the messages are all recoverable from history.
     */
    fun decode(json: String): List<CachedBuffer>? {
        return try {
            val root = JSONObject(json)
            if (root.optInt("version", -1) != VERSION) return null
            val arr = root.optJSONArray("buffers") ?: return null
            (0 until arr.length()).map { i ->
                val obj = arr.getJSONObject(i)
                val messages = obj.optJSONArray("messages") ?: JSONArray()
                CachedBuffer(
                    name = obj.getString("name"),
                    isDM = obj.optBoolean("isDM"),
                    topic = obj.optString("topic").takeIf { it.isNotEmpty() },
                    messages = (0 until messages.length()).map { decodeMessage(messages.getJSONObject(it)) },
                )
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun decodeMessage(obj: JSONObject): ChatMessage {
        val reactions = mutableMapOf<String, MutableSet<String>>()
        obj.optJSONObject("reactions")?.let { r ->
            for (emoji in r.keys()) {
                val nicks = r.optJSONArray(emoji) ?: continue
                reactions[emoji] = (0 until nicks.length()).map { nicks.getString(it) }.toMutableSet()
            }
        }
        return ChatMessage(
            id = obj.getString("id"),
            from = obj.optString("from"),
            text = obj.optString("text"),
            isAction = obj.optBoolean("isAction"),
            timestamp = Date(obj.optLong("timestamp")),
            replyTo = obj.optString("replyTo").takeIf { it.isNotEmpty() },
            isEdited = obj.optBoolean("isEdited"),
            isDeleted = obj.optBoolean("isDeleted"),
            isSigned = obj.optBoolean("isSigned"),
            origin = obj.optString("origin").takeIf { it.isNotEmpty() },
            reactions = reactions,
        )
    }

    /**
     * Write through a temporary file and rename, so a process killed
     * mid-write leaves the previous cache intact rather than a half file.
     */
    fun save(dir: File, buffers: List<CachedBuffer>) {
        try {
            if (!dir.exists() && !dir.mkdirs()) return
            val tmp = File(dir, "$FILE_NAME.tmp")
            tmp.writeText(encode(buffers))
            if (!tmp.renameTo(File(dir, FILE_NAME))) tmp.delete()
        } catch (_: Exception) {
        }
    }

    fun load(dir: File): List<CachedBuffer>? {
        val file = File(dir, FILE_NAME)
        if (!file.exists()) return null
        val decoded = try {
            decode(file.readText())
        } catch (_: Exception) {
            null
        }
        if (decoded == null) file.delete()
        return decoded
    }

    fun clear(dir: File) {
        try {
            File(dir, FILE_NAME).delete()
            File(dir, "$FILE_NAME.tmp").delete()
        } catch (_: Exception) {
        }
    }
}
