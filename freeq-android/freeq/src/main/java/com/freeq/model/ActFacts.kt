package com.freeq.model

import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The facts grid: an act card labels the machine fields it understands,
 * instead of listing them raw — audience, money, deadlines, capabilities, the
 * note, the context link and its hash, and the payment and revision fields.
 * The labels live in the bundled copy of `spec/act-card-copy.json`; the card
 * body is the title and this one grid, so no value is ever drawn without its
 * key. A field with no label still draws, under its own key ([unknownFields]),
 * so nothing signed is ever invisible. Mirrors the web `act-facts.ts`.
 */
object ActFacts {

    private val copy: JSONObject by lazy {
        val text = ActFacts::class.java.classLoader!!
            .getResourceAsStream("act-card-copy.json")!!
            .reader(Charsets.UTF_8).readText()
        JSONObject(text).getJSONObject("facts")
    }

    private fun time(unixSeconds: String): String? {
        val n = unixSeconds.toLongOrNull() ?: return null
        if (n <= 0) return null
        return SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()).format(Date(n * 1000))
    }

    /**
     * The labelled facts for one event, in a fixed order: audience, winner,
     * money, deadlines, capabilities, then the note, the context link and its
     * hash, then pay to, payment, replaces and scope. [isOpener] is whether the
     * event created the action — only an opener is offered to anyone.
     */
    fun facts(
        fields: Map<String, String>,
        isOpener: Boolean,
        resolve: (String) -> String = { it },
        winnerDid: String? = null,
    ): List<Pair<String, String>> = buildList {
        val to = fields["act-to"]
        if (to != null) add(copy.getString("offered_to") to resolve(to))
        else if (isOpener) add(copy.getString("offered_to") to copy.getString("anyone"))
        if (winnerDid != null) add(copy.getString("awarded_to") to resolve(winnerDid))
        fields["act-price"]?.let { add(copy.getString("price") to it) }
        fields["act-bid"]?.let { add(copy.getString("bid") to it) }
        fields["act-deadline"]?.let { d -> time(d)?.let { add(copy.getString("deadline") to it) } }
        fields["act-bid-deadline"]?.let { d -> time(d)?.let { add(copy.getString("bid_deadline") to it) } }
        fields["act-caps"]?.let { add(copy.getString("caps") to it) }
        fields["act-note"]?.let { add(copy.getString("note") to it) }
        fields["act-ctx"]?.let { add(copy.getString("ctx") to it) }
        // The hash is what the signature covers, so it rides along for anyone
        // checking the bytes they fetched.
        fields["act-ctx-h"]?.let { add(copy.getString("ctx_h") to it) }
        // `act-pay-to` may be a DID or a plain payment address, so only a DID
        // goes through the resolver; anything else is shown exactly as sent.
        fields["act-pay-to"]?.let {
            add(copy.getString("pay_to") to if (it.startsWith("did:")) resolve(it) else it)
        }
        fields["act-tx"]?.let { add(copy.getString("tx") to it) }
        fields["act-replaces"]?.let { add(copy.getString("replaces") to it) }
        fields["act-scope"]?.let { add(copy.getString("scope") to it) }
    }

    /** The label the context row carries, so a renderer can draw that one value
     *  as a link without holding the word itself. */
    val ctxLabel: String get() = copy.getString("ctx")

    /** The `act-*` fields the card labels or consumes structurally. */
    private val KNOWN = setOf(
        "act", "act-verb", "act-id", "act-title", "act-to", "act-note", "act-ctx", "act-ctx-h",
        "act-deadline", "act-bid-deadline", "act-caps", "act-price", "act-bid",
        "act-accepts", "act-subject", "act-pay-to", "act-tx", "act-replaces", "act-scope",
    )

    /** Fields the card has no label for, under their raw keys — the
     *  unknown-verb law's sibling. */
    fun unknownFields(fields: Map<String, String>): List<Pair<String, String>> =
        fields.entries
            .filter { it.key.startsWith("act-") && it.key !in KNOWN }
            .map { it.key.removePrefix("act-") to it.value }
}
