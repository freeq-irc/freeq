package com.freeq.model

/**
 * The word each task verb shows a reader.
 *
 * The headline of a card is the word for the verb its event carried — the
 * verb is on the wire and the client computes nothing from it, so a progress
 * report never reads as a claim. A verb with no row here shows itself, which
 * is how a kind may add one without this having to be taught it.
 *
 * The same rows the web client reads (`freeq-app/src/lib/act-verbs.ts`), so
 * the same move is called the same thing wherever it is read.
 */
object ActVerbs {
    private val HEADLINE = mapOf(
        "offer" to "offered",
        "accept" to "accepted",
        "decline" to "declined",
        "claim" to "claimed",
        "progress" to "in progress",
        "complete" to "completed",
        "fail" to "failed",
        "cancel" to "cancelled",
        "bid" to "bid",
        "award" to "awarded",
        "submit" to "submitted",
        "revise" to "revisions requested",
        "accept-work" to "accepted",
        "forfeit" to "forfeited",
        // The two the home signs for itself. They write no companion line, so
        // these words are read in the timeline rather than on a card.
        "confirm" to "confirmed",
        "expire" to "expired",
    )

    fun headline(verb: String): String = HEADLINE[verb] ?: verb

    /**
     * The glyph each task verb shows a reader, beside its word.
     *
     * One row per verb, read the same way the word above it is: off the verb
     * the event carried, never off where the task got to. A verb with no row
     * here gets the generic pin, so a kind may add a move without this being
     * taught it.
     */
    private val EMOJI = mapOf(
        "offer" to "📋",
        "accept" to "👍",
        "decline" to "👎",
        "claim" to "✋",
        "progress" to "📌",
        "complete" to "🎉",
        "fail" to "❌",
        "cancel" to "🚫",
        "bid" to "💰",
        "award" to "🏆",
        "submit" to "📤",
        "revise" to "🔁",
        "accept-work" to "✅",
        "forfeit" to "🏳️",
        // The two the home signs for itself. They write no companion line, so
        // they carry their glyph on a system line rather than on a card.
        "confirm" to "✔️",
        "expire" to "⌛",
    )

    fun emoji(verb: String): String = EMOJI[verb] ?: "📌"

    /**
     * The accent a card's left edge carries. Purple where the work lands on
     * someone's plate, green on a good end, red on a failure; every other verb
     * goes without, since an edge on everything is an edge that says nothing.
     */
    fun accent(verb: String): ActAccent = when (verb) {
        "offer", "award" -> ActAccent.HANDOFF
        "complete", "accept-work" -> ActAccent.SUCCESS
        "fail" -> ActAccent.FAILURE
        else -> ActAccent.NONE
    }
}

/** An accent as a role rather than a colour — each client paints it in its
 *  own theme. */
enum class ActAccent { NONE, HANDOFF, SUCCESS, FAILURE }
