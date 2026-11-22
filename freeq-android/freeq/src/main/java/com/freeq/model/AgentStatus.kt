package com.freeq.model

/**
 * An agent's presence status, decoded.
 *
 * Agents built on harness-kit publish their status as space-separated
 * `key=value` pairs, with the prose `doing` field's spaces sent as `+`:
 *
 *     project=phoenix-agent model=opus doing=answering+chad+in+#phoenix+·+0s
 *
 * Carried in an AWAY reason it is prefixed with the presence state
 * (`executing: project=…`). Shown raw it is unreadable, so every surface
 * decodes it with this first. Mirrors freeq-app/src/lib/status.ts and the
 * Swift `AgentStatus` on macOS/iOS.
 */
data class AgentStatus(
    /** Presence state when the text carried one (`executing`, …). */
    val state: String? = null,
    /** What the agent is doing right now, as prose. */
    val doing: String? = null,
    val project: String? = null,
    val branch: String? = null,
    val repo: String? = null,
    val model: String? = null,
) {
    /** "phoenix-agent @main · opus": where the agent is working. */
    val context: String?
        get() {
            val where = listOfNotNull(project, branch?.let { "@$it" }).joinToString(" ")
            val parts = listOfNotNull(where.ifEmpty { null }, model)
            return if (parts.isEmpty()) null else parts.joinToString(" · ")
        }

    /** One line: "Working · answering chad in #phoenix". */
    val summary: String?
        get() {
            val parts = listOfNotNull(label(state), doing ?: context)
            return if (parts.isEmpty()) null else parts.joinToString(" · ")
        }

    /** Where it is working, as labelled facts for a detail view. */
    val facts: List<Pair<String, String>>
        get() = listOf("Project" to project, "Branch" to branch, "Repo" to repo, "Model" to model)
            .mapNotNull { (k, v) -> v?.let { k to it } }

    companion object {
        private val KNOWN = setOf("project", "branch", "repo", "model", "session", "doing")
        private val PAIR = Regex("^[a-z_]+=\\S*$")
        private val PREFIXED = Regex("^([a-z_]+):\\s+(.*)$")
        private val WS = Regex("\\s+")

        /** Decode, or null when [raw] is not an agent status (a person's
         *  free text, JSON, empty). Never throws. */
        fun parse(raw: String?): AgentStatus? {
            var text = raw?.trim().orEmpty()
            if (text.isEmpty()) return null
            var state: String? = null
            // "executing: project=…" — a state prefix, but only in front of pairs.
            PREFIXED.matchEntire(text)?.let { m ->
                val rest = m.groupValues[2]
                val first = rest.split(WS).firstOrNull().orEmpty()
                if (PAIR.matches(first)) {
                    state = m.groupValues[1]
                    text = rest
                }
            }
            val tokens = text.split(WS).filter { it.isNotEmpty() }
            if (tokens.isEmpty() || !tokens.all { PAIR.matches(it) }) return null
            var out = AgentStatus(state = state)
            var recognised = 0
            for (tok in tokens) {
                val eq = tok.indexOf('=')
                val key = tok.substring(0, eq)
                val value = tok.substring(eq + 1)
                if (key !in KNOWN) continue
                recognised++
                if (value.isEmpty()) continue
                out = when (key) {
                    "doing" -> out.copy(doing = value.replace('+', ' '))
                    "project" -> out.copy(project = value)
                    "branch" -> out.copy(branch = value)
                    "repo" -> out.copy(repo = value)
                    "model" -> out.copy(model = value)
                    else -> out // session: never shown
                }
            }
            return if (recognised > 0) out else null
        }

        /** Words for a presence state. */
        fun label(state: String?): String? {
            if (state.isNullOrEmpty()) return null
            return when (state) {
                "executing" -> "Working"
                "active", "online" -> "Available"
                "idle" -> "Idle"
                "waiting_for_input" -> "Waiting for input"
                "blocked_on_permission" -> "Needs approval"
                "blocked_on_budget" -> "Out of budget"
                "rate_limited" -> "Rate limited"
                "degraded" -> "Degraded"
                "paused" -> "Paused"
                "sandboxed" -> "Sandboxed"
                "revoked" -> "Revoked"
                "offline" -> "Offline"
                else -> state.replace('_', ' ')
            }
        }

        /** An AWAY reason as display text: an agent's decoded, anyone
         *  else's as is. */
        fun displayAway(away: String?): String? {
            if (away.isNullOrEmpty()) return null
            parse(away)?.let { return it.summary }
            return away
        }
    }
}
