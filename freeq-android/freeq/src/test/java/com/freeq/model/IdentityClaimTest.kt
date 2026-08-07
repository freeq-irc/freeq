package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * What this client is willing to say about who someone is. Every surface that
 * makes an identity claim — the message row's mark, the profile card's mark,
 * the proof view behind them — asks this one question, so none of them can
 * claim more than another.
 */
class IdentityClaimTest {

    @Test fun a_server_bound_did_is_an_at_protocol_identity() {
        assertEquals(
            IdentityClaim.AT_PROTOCOL,
            SenderIdentity.claim("did:plc:k2n3e2vsihf3farequ44t5j7", null)
        )
    }

    @Test fun a_self_issued_key_carries_no_at_protocol_claim() {
        // did:key is live here for bots and guests. The key is real; nothing on
        // the AT Protocol stands behind it.
        assertEquals(
            IdentityClaim.SELF_ISSUED_KEY,
            SenderIdentity.claim("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", null)
        )
    }

    @Test fun a_relayed_sender_gets_no_claim_at_all() {
        // Peer-vouched, not verified here — the DID arrived with the message
        // from another server, and this one checked nothing.
        assertEquals(
            IdentityClaim.NONE,
            SenderIdentity.claim("did:plc:k2n3e2vsihf3farequ44t5j7", "irc.example.org")
        )
        assertEquals(
            IdentityClaim.NONE,
            SenderIdentity.claim("did:key:z6Mkabc", "irc.example.org")
        )
    }

    @Test fun no_identifier_is_no_claim() {
        assertEquals(IdentityClaim.NONE, SenderIdentity.claim(null, null))
        assertEquals(IdentityClaim.NONE, SenderIdentity.claim("", null))
        assertEquals(IdentityClaim.NONE, SenderIdentity.claim("   ", null))
    }

    @Test fun only_an_at_protocol_identity_earns_the_mark() {
        // The mark is the claim, so it appears exactly where the claim holds.
        assertEquals(true, SenderIdentity.claim("did:plc:abc", null).showsMark)
        assertEquals(false, SenderIdentity.claim("did:key:z6Mkabc", null).showsMark)
        assertEquals(false, SenderIdentity.claim("did:plc:abc", "peer.example").showsMark)
        assertEquals(false, SenderIdentity.claim(null, null).showsMark)
    }
}
