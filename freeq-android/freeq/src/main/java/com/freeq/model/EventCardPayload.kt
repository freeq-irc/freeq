package com.freeq.model

import org.json.JSONArray
import org.json.JSONObject

/** One key/value line on an event card. */
data class PayloadRow(val key: String, val value: String)

/**
 * The rows an event card shows for its `+freeq.at/payload` tag.
 *
 * The tag is JSON by convention and nothing enforces it, so the rule answers
 * for everything that can arrive rather than for the happy case: an object
 * spreads into its top-level keys, anything else that parses becomes one
 * `payload` row, and text that never was JSON becomes that same row carrying
 * what was sent. A tag that arrived is never dropped.
 *
 * A value is shown as the document wrote it, never re-serialized: a string
 * decoded, everything else sliced out of the source text with the whitespace
 * between its tokens dropped. The parsed value would not do — `toString` of a
 * parsed `0.3` can come back as `0.29999999999999999`, and `1.0` as `1`.
 *
 * The same rule the web and Apple clients apply, so one payload reads the same
 * on all four.
 */
object EventCardPayload {

    fun rows(rawTagValue: String?): List<PayloadRow> {
        val raw = rawTagValue?.takeIf { it.isNotBlank() } ?: return emptyList()
        val decoded = percentDecode(raw)
        val trimmed = decoded.trim()

        if (trimmed.startsWith("{")) {
            val obj = runCatching { JSONObject(trimmed) }.getOrNull()
            if (obj != null) return objectRows(obj, trimmed)
        }
        if (trimmed.startsWith("[")) {
            val arr = runCatching { JSONArray(trimmed) }.getOrNull()
            if (arr != null) return listOf(PayloadRow("payload", compact(trimmed)))
        }
        return listOf(PayloadRow("payload", scalar(trimmed) ?: decoded))
    }

    /**
     * One row per top-level key, in the order the document wrote them, each
     * value the source text the document gave it.
     *
     * Both come off the text rather than out of the parsed object: `JSONObject`
     * is backed by a hash map here and hands its keys back in an order of its
     * own, and a parsed number no longer knows how it was written.
     */
    private fun objectRows(obj: JSONObject, text: String): List<PayloadRow> {
        val scanned = scanObject(text)
        if (scanned != null) {
            // A key written twice is one row: the rows are keyed by their key.
            val seen = mutableSetOf<String>()
            return scanned.filter { seen.add(it.key) }
                .map { PayloadRow(it.key, showSource(it.raw)) }
        }
        return obj.keys().asSequence().toList()
            .map { key -> PayloadRow(key, showParsed(obj.get(key))) }
    }

    /** One top-level key with the source text of its value. */
    private data class Entry(val key: String, val raw: String)

    /**
     * The top-level entries of a JSON object, each with the source text of its
     * value, in the order the document wrote them.
     *
     * Null when the text is not one complete JSON object, which leaves the
     * caller its own fallback.
     */
    private fun scanObject(text: String): List<Entry>? {
        var i = 0
        fun skip() { while (i < text.length && text[i].isJsonSpace()) i++ }
        fun at(): Char? = text.getOrNull(i)

        skip()
        if (at() != '{') return null
        i++
        val entries = mutableListOf<Entry>()
        skip()
        if (at() == '}') {
            i++
            skip()
            return if (i == text.length) entries else null
        }
        while (true) {
            skip()
            if (at() != '"') return null
            val keyEnd = endOfString(text, i)
            if (keyEnd < 0) return null
            val key = decodeString(text.substring(i, keyEnd + 1)) ?: return null
            i = keyEnd + 1
            skip()
            if (at() != ':') return null
            i++
            skip()
            val valueEnd = endOfValue(text, i)
            if (valueEnd < 0) return null
            entries.add(Entry(key, text.substring(i, valueEnd)))
            i = valueEnd
            skip()
            when (at()) {
                ',' -> { i++; continue }
                '}' -> {
                    i++
                    skip()
                    return if (i == text.length) entries else null
                }
                else -> return null
            }
        }
    }

    /** The index of the quote that closes the string opened at [start]. */
    private fun endOfString(text: String, start: Int): Int {
        var i = start + 1
        while (i < text.length) {
            when (text[i]) {
                '\\' -> i++
                '"' -> return i
            }
            i++
        }
        return -1
    }

    /** The index just past the value that starts at [start], or -1. */
    private fun endOfValue(text: String, start: Int): Int {
        if (start >= text.length) return -1
        val c = text[start]
        if (c == '"') {
            val end = endOfString(text, start)
            return if (end < 0) -1 else end + 1
        }
        if (c == '{' || c == '[') {
            var depth = 0
            var i = start
            while (i < text.length) {
                val ch = text[i]
                if (ch == '"') {
                    val end = endOfString(text, i)
                    if (end < 0) return -1
                    i = end + 1
                    continue
                }
                when (ch) {
                    '{', '[' -> depth++
                    '}', ']' -> {
                        depth--
                        if (depth == 0) return i + 1
                    }
                }
                i++
            }
            return -1
        }
        var i = start
        while (i < text.length && !text[i].isJsonSpace() &&
            text[i] != ',' && text[i] != '}' && text[i] != ']'
        ) {
            i++
        }
        return if (i == start) -1 else i
    }

    /** The same text with the whitespace between its tokens dropped. */
    private fun compact(text: String): String {
        val out = StringBuilder(text.length)
        var i = 0
        while (i < text.length) {
            if (text[i] == '"') {
                val end = endOfString(text, i)
                if (end < 0) return out.append(text.substring(i)).toString()
                out.append(text, i, end + 1)
                i = end + 1
                continue
            }
            if (!text[i].isJsonSpace()) out.append(text[i])
            i++
        }
        return out.toString()
    }

    private fun Char.isJsonSpace(): Boolean =
        this == ' ' || this == '\t' || this == '\n' || this == '\r'

    /** The text of a JSON string token, decoded. */
    private fun decodeString(token: String): String? =
        runCatching { JSONArray("[$token]") }.getOrNull()
            ?.takeIf { it.length() == 1 }
            ?.let { it.get(0) as? String }

    /** A value as a row shows it: a string decoded, everything else as written. */
    private fun showSource(raw: String): String =
        if (raw.startsWith("\"")) decodeString(raw) ?: compact(raw) else compact(raw)

    /** A parsed value, for the fallback where the source text could not be read. */
    private fun showParsed(value: Any?): String = when {
        value == null || value === JSONObject.NULL -> "null"
        value is String -> value
        else -> value.toString()
    }

    /**
     * A JSON scalar, as the row shows it, or null when the text is not JSON.
     *
     * Written out rather than handed to `JSONTokener`, which is lenient enough
     * to read a bare sentence as a string and would leave nothing that fails.
     */
    private fun scalar(text: String): String? = when {
        text == "true" || text == "false" || text == "null" -> text
        NUMBER.matches(text) -> text
        text.startsWith("\"") -> decodeString(text)
        else -> null
    }

    private val NUMBER = Regex("""-?(0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?""")

    /**
     * Percent-decoding, not form decoding: `+` stays a plus. Malformed
     * escaping keeps the bytes that arrived rather than throwing them away.
     */
    private fun percentDecode(s: String): String {
        if (!s.contains('%')) return s
        val out = java.io.ByteArrayOutputStream(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%') {
                if (i + 2 >= s.length) return s
                val hex = s.substring(i + 1, i + 3)
                val b = hex.toIntOrNull(16) ?: return s
                out.write(b)
                i += 3
            } else {
                out.write(c.toString().toByteArray(Charsets.UTF_8))
                i++
            }
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }
}
