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
}
