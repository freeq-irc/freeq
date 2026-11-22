package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Agent status decoding, at parity with web (`freeq-app/src/lib/status.test.ts`)
 * and macOS/iOS (`AgentStatusTests.swift`). Then how the member row reads it.
 */
class AgentStatusTest {

    private val raw = "project=phoenix-agent doing=answering+chad-bot-phoenix+in+#phoenix+·+0s"

    private fun member(
        nick: String = "bot",
        awayMsg: String? = null,
        actorClass: String? = "agent",
        presenceState: String? = null,
        presenceStatus: String? = null,
    ) = MemberInfo(
        nick = nick, isOp = false, isVoiced = false, awayMsg = awayMsg,
        actorClass = actorClass, presenceState = presenceState, presenceStatus = presenceStatus
    )

    // ── Decoder ──

    @Test fun decodesKeyValueStatus() {
        assertEquals(
            AgentStatus(project = "phoenix-agent", doing = "answering chad-bot-phoenix in #phoenix · 0s"),
            AgentStatus.parse(raw)
        )
    }

    @Test fun takesStateOffAwayReason() {
        val s = AgentStatus.parse("executing: $raw model=opus branch=main")!!
        assertEquals("executing", s.state)
        assertEquals("phoenix-agent", s.project)
        assertEquals("opus", s.model)
        assertEquals("main", s.branch)
        assertEquals("phoenix-agent @main · opus", s.context)
        assertEquals("Working · answering chad-bot-phoenix in #phoenix · 0s", s.summary)
    }

    @Test fun sessionIsNeverShownAndEmptyValuesAreSkipped() {
        val s = AgentStatus.parse("session=abc123 project= model=opus")!!
        assertEquals(AgentStatus(model = "opus"), s)
        assertEquals(listOf("Model" to "opus"), s.facts)
    }

    @Test fun leavesPeopleAlone() {
        assertNull(AgentStatus.parse("out to lunch"))
        assertNull(AgentStatus.parse("back at 3: see you"))
        assertNull(AgentStatus.parse("{\"status\":\"lunch\"}"))
        assertNull(AgentStatus.parse("a=b c=d"))
        assertNull(AgentStatus.parse("project=x and some words"))
        assertNull(AgentStatus.parse("Project=x"))
        assertNull(AgentStatus.parse(""))
        assertNull(AgentStatus.parse("   "))
        assertNull(AgentStatus.parse(null))
    }

    @Test fun displayAwayReadsAgentsAsWordsAndPeopleAsIs() {
        assertEquals(
            "Working · answering chad-bot-phoenix in #phoenix · 0s",
            AgentStatus.displayAway("executing: $raw")
        )
        assertEquals("Working · x · m", AgentStatus.displayAway("executing: project=x model=m"))
        assertEquals("Working · x", AgentStatus.displayAway("executing: project=x"))
        assertEquals("lunch", AgentStatus.displayAway("lunch"))
        assertNull(AgentStatus.displayAway(""))
        assertNull(AgentStatus.displayAway(null))
    }

    @Test fun namesStatesAndContext() {
        val cases = mapOf(
            "executing" to "Working", "active" to "Available", "online" to "Available",
            "idle" to "Idle", "waiting_for_input" to "Waiting for input",
            "blocked_on_permission" to "Needs approval", "blocked_on_budget" to "Out of budget",
            "rate_limited" to "Rate limited", "degraded" to "Degraded", "paused" to "Paused",
            "sandboxed" to "Sandboxed", "revoked" to "Revoked", "offline" to "Offline",
            "something_new" to "something new",
        )
        for ((state, words) in cases) assertEquals(state, words, AgentStatus.label(state))
        assertNull(AgentStatus.label(null))
        assertEquals("p @b · m", AgentStatus(project = "p", branch = "b", model = "m").context)
        assertNull(AgentStatus().context)
        assertNull(AgentStatus().summary)
    }

    // ── Member rows ──

    @Test fun activityLabelIsDecoded() {
        assertEquals(
            "answering chad-bot-phoenix in #phoenix · 0s",
            member(presenceStatus = raw).activityLabel
        )
        // Pairs with no `doing` fall back to the state word.
        assertEquals("working", member(presenceStatus = "project=p", presenceState = "executing").activityLabel)
        // A status in no known form is shown as it came.
        assertEquals("answering chad", member(presenceStatus = "answering chad").activityLabel)
    }

    @Test fun agentWhoseAwayIsItsStatusIsWorkingNotAway() {
        val m = member(awayMsg = "executing: $raw")
        assertTrue(m.isWorking)
        assertEquals("Working · answering chad-bot-phoenix in #phoenix · 0s", m.awayText)
        assertEquals("answering chad-bot-phoenix in #phoenix · 0s", m.agentStatus?.doing)

        // A person's away, or an agent's free-text one, is still away.
        assertFalse(member(nick = "chad", actorClass = null, awayMsg = "lunch").isWorking)
        assertFalse(member(awayMsg = "brb").isWorking)
        assertEquals("brb", member(awayMsg = "brb").awayText)
        // A person never reads as working, even with pairs in the away text.
        assertFalse(member(actorClass = null, awayMsg = "executing: project=x").isWorking)
    }

    @Test fun presenceDecidesWorking() {
        assertTrue(member(presenceState = "executing").isWorking)
        assertFalse(member(presenceState = "idle", awayMsg = "executing: project=x").isWorking)
    }

    @Test fun agentStatusPrefersPresenceAndTakesItsState() {
        val m = member(
            presenceState = "waiting_for_input",
            presenceStatus = "project=live doing=asking",
            awayMsg = "executing: project=stale"
        )
        assertEquals(AgentStatus(state = "waiting_for_input", project = "live", doing = "asking"), m.agentStatus)
        // A person with no agent status has none.
        assertNull(member(actorClass = null, awayMsg = "lunch").agentStatus)
    }
}
