package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Tests for TAGMSG buffer-routing. Bugs in this rule cause edits /
 * deletes / reactions to apply to the wrong message or get silently
 * dropped — easy to miss in manual testing because the optimistic
 * client-side update masks them on the acting device.
 */
class TagMsgRouterTest {

    @Test fun channel_target_routes_to_that_channel() {
        assertEquals("#freeq", TagMsgRouter.routeTo(target = "#freeq", from = "alice", selfNick = "me"))
    }

    @Test fun dm_target_routes_to_sender() {
        // The wire-level target on an inbound DM is OUR nick (we're the
        // recipient); the buffer is named after the sender.
        assertEquals("alice", TagMsgRouter.routeTo(target = "me", from = "alice", selfNick = "me"))
    }

    @Test fun dm_key_wins_when_present() {
        assertEquals(
            "did:plc:abc",
            TagMsgRouter.routeTo(target = "me", from = "alice", selfNick = "me", dmKey = "did:plc:abc")
        )
    }

    @Test fun own_event_from_another_device_routes_by_target() {
        // Same DID on two devices shares a nick. A delete/reaction made on
        // the other device arrives here with from == our nick and target ==
        // the peer; it must APPLY, not be treated as an echo — this exact
        // drop left cross-device deletes invisible until a history refetch.
        assertEquals("echo-bot", TagMsgRouter.routeTo(target = "echo-bot", from = "me", selfNick = "me"))
        assertEquals(
            "did:key:z6Mkabc",
            TagMsgRouter.routeTo(target = "did:key:z6Mkabc", from = "me", selfNick = "me")
        )
    }

    @Test fun own_channel_event_routes_to_the_channel() {
        // A true server echo of our own channel TAGMSG re-applies an
        // idempotent op — harmless. Dropping it also dropped our other
        // devices' events, which is not.
        assertEquals("#freeq", TagMsgRouter.routeTo(target = "#freeq", from = "me", selfNick = "me"))
    }

    @Test fun self_match_is_case_insensitive() {
        assertEquals("echo-bot", TagMsgRouter.routeTo(target = "echo-bot", from = "ME", selfNick = "me"))
        assertEquals("echo-bot", TagMsgRouter.routeTo(target = "echo-bot", from = "Me", selfNick = "me"))
    }

    @Test fun ampersand_local_channel_routes_as_dm() {
        // `&local` is technically an IRC channel prefix but freeq's
        // current code only treats `#` as channel-shaped. Any change
        // to that policy should update both BufferRouter and this
        // routing rule together — test pins the current behavior.
        assertEquals("alice", TagMsgRouter.routeTo(target = "&local", from = "alice", selfNick = "me"))
    }
}
