package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Tests for JoinTarget.parse().
 *
 * A channel key belongs in the JOIN parameter, not in the channel name. The
 * name is what the server's JOIN echo carries and what navigation matches on.
 */
class JoinTargetTest {

    @Test fun key_goes_on_the_wire_but_not_into_the_channel_name() {
        val target = JoinTarget.parse("#general hunter2")!!
        assertEquals("#general", target.channel)
        assertEquals("#general hunter2", target.line)
    }

    @Test fun a_channel_with_no_key_is_left_alone() {
        val target = JoinTarget.parse("#general")!!
        assertEquals("#general", target.channel)
        assertEquals("#general", target.line)
    }

    @Test fun a_bare_name_gets_its_hash() {
        val target = JoinTarget.parse("general hunter2")!!
        assertEquals("#general", target.channel)
        assertEquals("#general hunter2", target.line)
    }

    @Test fun a_list_joins_whole_but_navigates_to_the_first() {
        val target = JoinTarget.parse("#a,#b k1,k2")!!
        assertEquals("#a", target.channel)
        assertEquals("#a,#b k1,k2", target.line)
    }

    @Test fun surrounding_space_is_not_a_key() {
        val target = JoinTarget.parse("  #general  ")!!
        assertEquals("#general", target.channel)
        assertEquals("#general", target.line)
    }

    @Test fun nothing_to_join_is_null() {
        assertNull(JoinTarget.parse(""))
        assertNull(JoinTarget.parse("   "))
        assertNull(JoinTarget.parse("#"))
        assertNull(JoinTarget.parse("# hunter2"))
    }
}
