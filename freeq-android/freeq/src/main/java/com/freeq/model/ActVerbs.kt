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
        // The three the home signs for itself. They write no companion line,
        // so these words are read on a system line rather than on a card.
        "confirm" to "confirmed",
        "expire" to "expired",
        "auto-accept" to "accepted (review window closed)",
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
        // The three the home signs for itself. They write no companion line,
        // so they carry their glyph on a system line rather than on a card.
        "confirm" to "✔️",
        "expire" to "⌛",
        "auto-accept" to "⏱️",
    )

    fun emoji(verb: String): String = EMOJI[verb] ?: "📌"

    /**
     * The register a card wears: the state the step it carries lands the
     * action in, as a role rather than a colour — each client paints the role
     * in its own theme.
     *
     * Read off `spec/act-transitions.json`: the `to` of the row the verb
     * matched, except that a step landing where it started is in-progress
     * whatever state that is. A row whose `who` is `system` writes no card and
     * so has no register; a verb with no row at all falls to the neutral end.
     */
    private val REGISTER = mapOf<String, ActRegister?>(
        // lands open / offered
        "offer" to ActRegister.NEW,
        // lands assigned / under_review, and the two additive steps
        "accept" to ActRegister.IN_PROGRESS,
        "claim" to ActRegister.IN_PROGRESS,
        "award" to ActRegister.IN_PROGRESS,
        "submit" to ActRegister.IN_PROGRESS,
        "revise" to ActRegister.IN_PROGRESS,
        "progress" to ActRegister.IN_PROGRESS,
        "bid" to ActRegister.IN_PROGRESS,
        // lands completed / accepted
        "complete" to ActRegister.ENDED_WELL,
        "accept-work" to ActRegister.ENDED_WELL,
        // lands failed / forfeited / cancelled / declined
        "fail" to ActRegister.DID_NOT_END_WELL,
        "forfeit" to ActRegister.DID_NOT_END_WELL,
        "cancel" to ActRegister.DID_NOT_END_WELL,
        "decline" to ActRegister.DID_NOT_END_WELL,
        // The rows a home signs for itself. No card, so no register.
        "confirm" to null,
        "expire" to null,
        "auto-accept" to null,
    )

    fun register(verb: String): ActRegister? =
        if (REGISTER.containsKey(verb)) REGISTER[verb] else ActRegister.NEUTRAL_END

    /**
     * Who the rules file lets take this step — the `who` of the row the verb
     * matched, and the key the seal panel picks its sentence by.
     *
     * An opening verb has no transition row of its own and reports `opener`. A
     * system row and an unteached verb report nothing, because neither has a
     * rule about a person to state.
     */
    private val WHO = mapOf<String, String?>(
        "offer" to "opener",
        "accept" to "offeree",
        "decline" to "offeree",
        "claim" to "anyone",
        "bid" to "anyone",
        "progress" to "assignee",
        "complete" to "assignee",
        "fail" to "assignee",
        "submit" to "assignee",
        "forfeit" to "assignee",
        "cancel" to "offerer",
        "award" to "offerer",
        "revise" to "offerer",
        "accept-work" to "offerer",
        "confirm" to null,
        "expire" to null,
        "auto-accept" to null,
    )

    fun whoRole(verb: String): String? = WHO[verb]
}

/**
 * The register a card wears, as a role rather than a colour — each client
 * paints it in its own theme.
 */
enum class ActRegister { NEW, IN_PROGRESS, ENDED_WELL, DID_NOT_END_WELL, NEUTRAL_END }
