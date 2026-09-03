package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Test

class ActFactsTest {
    private val resolve = { k: String -> if (k == "did:key:zWORKER") "cardworker2" else k }

    @Test fun a_directed_offer_names_its_recipient_resolved() {
        assertEquals(
            listOf("offered to" to "cardworker2"),
            ActFacts.facts(mapOf("act-to" to "did:key:zWORKER"), true, resolve),
        )
    }

    @Test fun an_opener_is_offered_to_anyone_and_a_follow_up_claims_nothing() {
        assertEquals(listOf("offered to" to "anyone"), ActFacts.facts(emptyMap(), true, resolve))
        assertEquals(emptyList<Pair<String, String>>(), ActFacts.facts(emptyMap(), false, resolve))
    }

    @Test fun money_is_labelled_price_on_offers_and_bid_on_bids() {
        assertEquals(
            listOf("offered to" to "anyone", "price" to "250 USD"),
            ActFacts.facts(mapOf("act-price" to "250 USD"), true, resolve),
        )
        assertEquals(
            listOf("bid" to "200 USD"),
            ActFacts.facts(mapOf("act-bid" to "200 USD"), false, resolve),
        )
    }

    @Test fun deadlines_carry_a_time_value_and_garbage_is_skipped() {
        val f = ActFacts.facts(mapOf("act-deadline" to "1788000000"), true, resolve)
        assertEquals("offered to" to "anyone", f[0])
        assertEquals("deadline", f[1].first)
        assert(f[1].second.isNotEmpty())
        assertEquals(
            emptyList<Pair<String, String>>(),
            ActFacts.facts(mapOf("act-deadline" to "soon"), false, resolve),
        )
    }

    @Test fun a_bid_deadline_gets_its_own_label() {
        val f = ActFacts.facts(mapOf("act-bid-deadline" to "1788000000"), true, resolve)
        assertEquals("bids close", f[1].first)
    }

    @Test fun capabilities_are_labelled_as_required_skills() {
        assertEquals(
            listOf("offered to" to "anyone", "skills required" to "demo"),
            ActFacts.facts(mapOf("act-caps" to "demo"), true, resolve),
        )
    }

    @Test fun the_awards_winner_gets_an_awarded_to_line() {
        assertEquals(
            listOf("awarded to" to "cardworker2"),
            ActFacts.facts(emptyMap(), false, resolve, "did:key:zWORKER"),
        )
    }

    @Test fun the_note_is_a_row_of_the_grid_not_a_line_under_it() {
        assertEquals(
            listOf("note" to "two days"),
            ActFacts.facts(mapOf("act-note" to "two days"), false, resolve),
        )
    }

    @Test fun the_context_link_is_a_row() {
        assertEquals(
            listOf("context" to "https://example.org/a"),
            ActFacts.facts(mapOf("act-ctx" to "https://example.org/a"), false, resolve),
        )
    }

    @Test fun the_context_hash_is_a_row() {
        assertEquals(
            listOf("hash" to "sha256:9f00"),
            ActFacts.facts(mapOf("act-ctx-h" to "sha256:9f00"), false, resolve),
        )
    }

    @Test fun the_payee_is_a_row_a_did_resolves_and_anything_else_is_shown_as_sent() {
        assertEquals(
            listOf("pay to" to "cardworker2"),
            ActFacts.facts(mapOf("act-pay-to" to "did:key:zWORKER"), false, resolve),
        )
        assertEquals(
            listOf("pay to" to "0xdeadbeef"),
            ActFacts.facts(mapOf("act-pay-to" to "0xdeadbeef"), false, resolve),
        )
    }

    @Test fun the_payment_is_a_row() {
        assertEquals(
            listOf("payment" to "eth:0xdemo"),
            ActFacts.facts(mapOf("act-tx" to "eth:0xdemo"), false, resolve),
        )
    }

    @Test fun the_action_a_revision_replaces_is_a_row_under_its_raw_id() {
        assertEquals(
            listOf("replaces" to "01JOLD"),
            ActFacts.facts(mapOf("act-replaces" to "01JOLD"), false, resolve),
        )
    }

    @Test fun the_scope_is_a_row() {
        assertEquals(
            listOf("scope" to "room"),
            ActFacts.facts(mapOf("act-scope" to "room"), false, resolve),
        )
    }

    @Test fun the_seven_follow_the_labelled_facts_in_their_own_fixed_order() {
        assertEquals(
            listOf(
                "offered to" to "anyone",
                "price" to "250 USD",
                "skills required" to "url_fetch",
                "note" to "two days",
                "context" to "https://example.org/a",
                "hash" to "sha256:9f00",
                "pay to" to "did:key:zW",
                "payment" to "eth:0xdemo",
                "replaces" to "01JOLD",
                "scope" to "room",
            ),
            ActFacts.facts(
                mapOf(
                    "act-price" to "250 USD", "act-caps" to "url_fetch", "act-note" to "two days",
                    "act-ctx" to "https://example.org/a", "act-ctx-h" to "sha256:9f00",
                    "act-pay-to" to "did:key:zW", "act-tx" to "eth:0xdemo",
                    "act-replaces" to "01JOLD", "act-scope" to "room",
                ),
                true,
                resolve,
            ),
        )
    }

    @Test fun unlabelled_fields_keep_their_keys_and_known_ones_never_do() {
        assertEquals(listOf("mystery" to "y"), ActFacts.unknownFields(mapOf("act-mystery" to "y")))
        assertEquals(emptyList<Pair<String, String>>(), ActFacts.unknownFields(mapOf(
            "act-pay-to" to "did:key:zW", "act-tx" to "eth:0xabc",
            "act-replaces" to "01JOLD", "act-scope" to "room",
        )))
        assertEquals(emptyList<Pair<String, String>>(), ActFacts.unknownFields(mapOf(
            "act" to "handoff", "act-verb" to "offer", "act-id" to "X", "act-to" to "d",
            "act-title" to "t", "act-note" to "n", "act-ctx" to "u", "act-ctx-h" to "h", "act-deadline" to "1",
            "act-bid-deadline" to "1", "act-caps" to "c", "act-price" to "p",
            "act-bid" to "b", "act-accepts" to "e", "act-subject" to "s",
            "act-pay-to" to "p2", "act-tx" to "tx", "act-replaces" to "r", "act-scope" to "sc",
        )))
    }
}
