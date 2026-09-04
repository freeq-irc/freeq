package com.freeq.model

import com.freeq.ffi.ActorClassEntry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Agent badge and live activity, at parity with iOS (`e16a2b98`).
 *
 * The first six pin the same behaviour as the Swift tests of the same
 * names; three more cover the unmapped states and the away line the server
 * sends beside every presence; the last three cover the apply functions,
 * which live on `ChannelState` here because `AppState` has no JVM test
 * harness.
 */
class AgentPresenceTest {

    private fun member(
        nick: String = "bot",
        isOp: Boolean = false,
        awayMsg: String? = null,
        did: String? = null,
        actorClass: String? = null,
        presenceState: String? = null,
        presenceStatus: String? = null,
    ) = MemberInfo(
        nick = nick, isOp = isOp, isHalfop = false, isVoiced = false,
        awayMsg = awayMsg, did = did, actorClass = actorClass,
        presenceState = presenceState, presenceStatus = presenceStatus
    )

    // ── Derived values ──

    /** An unlabelled member is a person. The server reports only the
     *  exceptions, so "not stated" must keep reading as human. */
    @Test fun unlabelledMemberIsNotAnAgent() {
        val m = member(nick = "chad")
        assertFalse(m.isAgent)
        assertNull(m.activityLabel)
    }

    @Test fun agentClassesAreRecognised() {
        for (cls in listOf("agent", "external_agent")) {
            assertTrue("$cls should read as an agent", member(actorClass = cls).isAgent)
        }
        assertFalse(member(nick = "p", actorClass = "human").isAgent)
    }

    /** A status the agent published wins over a generic state word. */
    @Test fun activityLabelPrefersTheAgentsOwnStatus() {
        val m = member(
            actorClass = "agent", presenceState = "executing",
            presenceStatus = "answering chad"
        )
        assertEquals("answering chad", m.activityLabel)
    }

    @Test fun activityLabelFallsBackToAReadableState() {
        val cases = listOf(
            "executing" to "working",
            "waiting_for_input" to "waiting for input",
            "blocked_on_permission" to "needs approval",
            "paused" to "paused",
            "degraded" to "degraded",
            "rate_limited" to "rate limited",
        )
        for ((state, expected) in cases) {
            val m = member(actorClass = "agent", presenceState = state)
            assertEquals("state $state", expected, m.activityLabel)
        }
    }

    /** An idle agent says nothing. A row that always carries a label teaches
     *  people to stop reading it. */
    @Test fun idleAgentShowsNoActivityLabel() {
        assertNull(member(actorClass = "agent").activityLabel)
        for (state in listOf("active", "online", "idle")) {
            assertNull(
                "state $state should be quiet",
                member(actorClass = "agent", presenceState = state).activityLabel
            )
        }
    }

    /** A human never gets an activity line even if a state leaks through. */
    @Test fun humansNeverShowAnActivityLabel() {
        val m = member(nick = "chad", actorClass = "human", presenceState = "executing")
        assertNull(m.activityLabel)
    }

    /** A state we have no words for still says something: the state itself,
     *  readable. An empty row under an agent's name reads as a bug. */
    /** A state with no word shows the state itself, underscores as spaces. */
    @Test fun unmappedStateShowsTheStateWord() {
        val cases = listOf(
            "blocked_on_budget" to "blocked on budget",
            "sandboxed" to "sandboxed",
            "revoked" to "revoked",
            "offline" to "offline",
        )
        for ((state, expected) in cases) {
            assertEquals("state $state", expected, member(actorClass = "agent", presenceState = state).activityLabel)
        }
    }

    /** The line under the name: the activity label wins over the away text,
     *  and the Away pill still shows. */
    @Test fun awayTextYieldsToTheActivityLabel() {
        val m = member(actorClass = "agent", awayMsg = "executing", presenceState = "executing")
        assertTrue(m.isAway)
        assertNull(m.awayText)
        assertEquals("working", m.activityLabel)

        val noLabel = member(actorClass = "agent", awayMsg = "brb")
        assertTrue(noLabel.isAway)
        assertEquals("brb", noLabel.awayText)
        assertNull(noLabel.activityLabel)
    }

    @Test fun awayStillShowsWithoutPresence() {
        val human = member(nick = "chad", awayMsg = "lunch")
        assertTrue(human.isAway)
        assertEquals("lunch", human.awayText)

        val agent = member(actorClass = "agent", awayMsg = "brb")
        assertTrue(agent.isAway)
        assertEquals("brb", agent.awayText)

        val present = member(nick = "chad")
        assertFalse(present.isAway)
    }

    // ── Apply functions ──

    @Test fun applyActorClassesMatchesNickCaseInsensitively() {
        val ch = ChannelState("#work")
        ch.members.add(member(nick = "Bot"))
        ch.members.add(member(nick = "chad"))

        ch.applyActorClasses(
            listOf(
                ActorClassEntry("bOT", "agent"),
                ActorClassEntry("nobody", "agent"),
            )
        )

        assertEquals("agent", ch.members[0].actorClass)
        assertTrue(ch.members[0].isAgent)
        // A name we do not hold is skipped, and nobody else is touched.
        assertEquals(2, ch.members.size)
        assertNull(ch.members[1].actorClass)
    }

    @Test fun applyPresenceMarksAnUnlabelledMemberAsAgent() {
        val ch = ChannelState("#work")
        ch.members.add(member(nick = "Bot"))
        ch.members.add(member(nick = "ext", actorClass = "external_agent"))

        ch.applyPresence("bot", "executing", "answering chad")
        ch.applyPresence("EXT", "paused", null)
        ch.applyPresence("stranger", "executing", null)

        // Publishing presence is itself proof this is an agent.
        assertEquals("agent", ch.members[0].actorClass)
        assertEquals("answering chad", ch.members[0].activityLabel)
        // An already-classed agent keeps the class it was given.
        assertEquals("external_agent", ch.members[1].actorClass)
        assertEquals("paused", ch.members[1].activityLabel)
        // A nick not in the channel adds nobody.
        assertEquals(2, ch.members.size)
    }

    @Test fun applyPresenceDoesNotTouchOtherFields() {
        val ch = ChannelState("#work")
        ch.members.add(
            member(nick = "bot", isOp = true, awayMsg = "brb", did = "did:plc:bot")
        )

        ch.applyPresence("bot", "executing", null)

        val m = ch.members[0]
        assertEquals("bot", m.nick)
        assertTrue(m.isOp)
        assertEquals("brb", m.awayMsg)
        assertEquals("did:plc:bot", m.did)
        assertEquals("working", m.activityLabel)
    }
}
