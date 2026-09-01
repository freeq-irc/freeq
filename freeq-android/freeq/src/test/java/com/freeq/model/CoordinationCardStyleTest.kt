package com.freeq.model

import com.freeq.ffi.CoordinationEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

private fun ev(
    type: String,
    taskId: String? = null,
    phase: String? = null,
    evidenceType: String? = null,
    payload: String? = null,
) = CoordinationEvent(type, taskId, phase, evidenceType, null, payload)

class CoordinationCardStyleTest {

    @Test
    fun knownEventStyles() {
        val newTask = CoordinationCardStyle.style(ev("task_request"))
        assertEquals("📋", newTask.icon)
        assertEquals("New Task", newTask.label)
        assertEquals(ActAccent.HANDOFF, newTask.accent)
        assertFalse(newTask.expandablePayload)

        val accepted = CoordinationCardStyle.style(ev("task_accept"))
        assertEquals("👍", accepted.icon)
        assertEquals("Task Accepted", accepted.label)
        assertEquals(ActAccent.NONE, accepted.accent)

        val complete = CoordinationCardStyle.style(ev("task_complete"))
        assertEquals("🎉", complete.icon)
        assertEquals(ActAccent.SUCCESS, complete.accent)

        val failed = CoordinationCardStyle.style(ev("task_failed"))
        assertEquals("❌", failed.icon)
        assertEquals(ActAccent.FAILURE, failed.accent)

        assertEquals("🔀", CoordinationCardStyle.style(ev("delegation_notice")).icon)
        assertEquals("💬", CoordinationCardStyle.style(ev("status_update")).icon)
    }

    @Test
    fun updateUsesPhaseIconAndLabel() {
        val building = CoordinationCardStyle.style(ev("task_update", phase = "building"))
        assertEquals("🔨", building.icon)
        assertEquals("Building", building.label)

        val bare = CoordinationCardStyle.style(ev("task_update"))
        assertEquals("📌", bare.icon)
        assertEquals("Update", bare.label)
    }

    @Test
    fun evidenceIsExpandableWithTypedIconAndHumanLabel() {
        val typed = CoordinationCardStyle.style(ev("evidence_attach", evidenceType = "test_result"))
        assertEquals("🧪", typed.icon)
        assertEquals("test result", typed.label)
        assertTrue(typed.expandablePayload)

        val bare = CoordinationCardStyle.style(ev("evidence_attach"))
        assertEquals("📎", bare.icon)
        assertEquals("evidence", bare.label)
    }

    @Test
    fun unknownEventShowsItselfWithThePin() {
        val s = CoordinationCardStyle.style(ev("mystery_event"))
        assertEquals("📌", s.icon)
        assertEquals("mystery_event", s.label)
        assertEquals(ActAccent.NONE, s.accent)
    }

    @Test
    fun prettyPayloadFormatsJsonAndPassesThroughTheRest() {
        val pretty = CoordinationCardStyle.prettyPayload("""{"a":1,"b":2}""")
        assertTrue(pretty!!.contains("\n"))
        assertTrue(pretty.contains("\"a\""))
        assertEquals("not json", CoordinationCardStyle.prettyPayload("not json"))
        assertNull(CoordinationCardStyle.prettyPayload(null))
        assertNull(CoordinationCardStyle.prettyPayload("  "))
    }
}
