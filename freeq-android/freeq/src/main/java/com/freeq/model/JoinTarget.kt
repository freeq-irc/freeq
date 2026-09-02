package com.freeq.model

/**
 * A `/join` argument split into the channel to track and the parameter to send.
 */
internal data class JoinTarget(
    /** The channel the server's JOIN echo will name (the first, for a list). */
    val channel: String,
    /** The JOIN argument as it goes on the wire, key included. */
    val line: String,
) {
    companion object {
        /** Null when there is no channel to join. */
        fun parse(input: String): JoinTarget? {
            val parts = input.trim().split(" ", limit = 2)
            val names = parts[0].let { if (it.startsWith("#")) it else "#$it" }
            val first = names.substringBefore(',')
            if (first.length <= 1) return null
            val key = parts.getOrNull(1)?.trim()?.takeIf { it.isNotEmpty() }
            return JoinTarget(first, if (key != null) "$names $key" else names)
        }
    }
}
