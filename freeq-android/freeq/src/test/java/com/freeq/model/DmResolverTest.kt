package com.freeq.model

import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Learning who a bare nick is before the first DM goes to them.
 *
 * A DM addressed to a nick is a venue nothing can sign — the signature covers
 * the venue, and a nick is not an identity. So the first DM to a stranger has
 * to ask before it sends. It also must not hang on the asking: a peer whose
 * server never answers still gets their message, unsigned, with no error shown.
 */
class DmResolverTest {
    private val asked = mutableListOf<String>()

    private fun resolver(
        known: Map<String, String> = emptyMap(),
        timeoutMs: Long = 50,
    ) = DmResolver(
        nickToDid = { known[it.lowercase()] },
        askWhois = { asked.add(it) },
        timeoutMs = timeoutMs,
    )

    @Test fun a_did_target_is_already_resolved() = runBlocking {
        val r = resolver()
        assertEquals("did:plc:abc", r.resolve("did:plc:abc"))
        assertEquals(emptyList<String>(), asked)
    }

    @Test fun a_channel_target_is_left_alone() = runBlocking {
        val r = resolver()
        assertEquals("#freeq", r.resolve("#freeq"))
        assertEquals(emptyList<String>(), asked)
    }

    @Test fun a_nick_we_already_know_needs_no_question() = runBlocking {
        val r = resolver(known = mapOf("bob" to "did:plc:bob"))
        assertEquals("did:plc:bob", r.resolve("Bob"))
        assertEquals(emptyList<String>(), asked)
    }

    @Test fun an_unknown_nick_is_asked_about_and_the_answer_is_used() = runBlocking {
        val r = resolver()
        val venue = async { r.resolve("bob") }
        yield() // let resolve get as far as waiting
        assertEquals(listOf("bob"), asked)
        r.learned("bob", "did:plc:bob")
        assertEquals("did:plc:bob", venue.await())
    }

    @Test fun an_answer_under_a_different_case_still_counts() = runBlocking {
        val r = resolver()
        val venue = async { r.resolve("bob") }
        yield()
        r.learned("BoB", "did:plc:bob")
        assertEquals("did:plc:bob", venue.await())
    }

    @Test fun silence_means_the_nick_stands_in() = runBlocking {
        // No error, no blocked send — the message goes to the nick and travels
        // unsigned, which is what it would have done before we asked at all.
        val r = resolver()
        assertEquals("bob", r.resolve("bob"))
    }

    @Test fun a_nick_that_did_not_answer_is_not_asked_again() = runBlocking {
        val r = resolver()
        assertEquals("bob", r.resolve("bob"))
        assertEquals("bob", r.resolve("bob"))
        assertEquals(listOf("bob"), asked)
    }

    @Test fun a_binding_learned_later_is_used_without_asking_again() = runBlocking {
        // The answer can arrive after the first message already left as a nick
        // — from a join, an account tag, or the WHOIS finally landing.
        val r = resolver()
        assertEquals("bob", r.resolve("bob"))
        r.learned("bob", "did:plc:bob")
        assertEquals("did:plc:bob", r.resolve("bob"))
        assertEquals(listOf("bob"), asked)
    }

    @Test fun probing_early_means_the_send_does_not_wait() = runBlocking {
        // Opening the thread asks; by send time the answer is already in hand.
        val r = resolver()
        r.probe("bob")
        assertEquals(listOf("bob"), asked)
        r.learned("bob", "did:plc:bob")
        assertEquals("did:plc:bob", r.resolve("bob"))
        assertEquals(listOf("bob"), asked)
    }
}
