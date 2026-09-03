package com.freeq.model

import org.json.JSONObject

/**
 * The seal panel's words, read from the bundled copy of
 * `spec/act-card-copy.json`.
 *
 * The prose is not written here and is not written in the other three clients
 * either: all four read the same file so a sentence cannot drift between them.
 * The copy under `src/main/resources` is packaged onto the classpath, and a
 * test pins it byte-identical to the canonical file.
 */
object SealPanelCopy {

    private val panel: JSONObject by lazy {
        val text = SealPanelCopy::class.java.classLoader!!
            .getResourceAsStream("act-card-copy.json")!!
            .reader(Charsets.UTF_8).readText()
        JSONObject(text).getJSONObject("seal_panel")
    }

    /** `HANDOFF: Rules Enforced` — the kind comes off the event's own act tag. */
    fun header(kind: String): String =
        panel.getString("header_format").replace("<KIND>", kind.uppercase())

    fun linkText(): String = panel.getString("link_text")

    /**
     * What the server enforced on this step, in one sentence.
     *
     * Chosen off the `who` of the transition row the verb matched — never off
     * the verb's name and never off the kind. A system row and a verb with no
     * row at all claim nothing, so neither gets a sentence.
     */
    fun sentence(verb: String): String? {
        val role = ActVerbs.whoRole(verb) ?: return null
        return panel.getJSONObject("sentences").optString(role).takeIf { it.isNotEmpty() }
    }
}
