package com.freeq.model

import com.freeq.ffi.CoordinationEvent

/**
 * Presentation policy for an agent coordination card (`+freeq.at/event`
 * family) — the Android twin of the web `CoordinationCards` dispatcher and
 * the Apple `CoordinationCard` policy. Pure mapping (event → icon, label,
 * accent) so the decision tree is unit-testable without Compose.
 */
object CoordinationCardStyle {
    data class Style(
        val icon: String,
        val label: String,
        val accent: ActAccent,
        /** Evidence cards expose a disclosure for their JSON payload. */
        val expandablePayload: Boolean,
    )

    /** Phase → glyph (matches the web `PhaseIcon` and Apple `phaseIcon`). */
    fun phaseIcon(phase: String?): String = when (phase) {
        "specifying" -> "📝"
        "designing" -> "🏗"
        "building" -> "🔨"
        "reviewing" -> "🔍"
        "testing" -> "🧪"
        "deploying" -> "🚀"
        "monitoring" -> "📊"
        else -> "📌"
    }

    /** Evidence type → glyph (matches the web `EvidenceIcon`). */
    fun evidenceIcon(type: String?): String = when (type) {
        "spec_document" -> "📄"
        "architecture_doc" -> "📐"
        "file_manifest" -> "📁"
        "code_review" -> "🔍"
        "test_result" -> "🧪"
        "deploy_log" -> "🚀"
        "commit" -> "📦"
        "artifact_link" -> "🔗"
        else -> "📎"
    }

    // The old family's agent accent renders as HANDOFF — the same purple the
    // act cards' offers wear, so one accent language covers both families.
    fun style(ev: CoordinationEvent): Style = when (ev.eventType) {
        "task_request" -> Style("📋", "New Task", ActAccent.HANDOFF, false)
        "task_accept" -> Style("👍", "Task Accepted", ActAccent.NONE, false)
        "task_update" -> Style(
            phaseIcon(ev.phase),
            ev.phase?.replaceFirstChar { it.uppercase() } ?: "Update",
            ActAccent.NONE, false)
        "task_complete" -> Style("🎉", "Task Complete", ActAccent.SUCCESS, false)
        "task_failed" -> Style("❌", "Task Failed", ActAccent.FAILURE, false)
        "evidence_attach" -> Style(
            evidenceIcon(ev.evidenceType),
            (ev.evidenceType ?: "evidence").replace('_', ' '),
            ActAccent.NONE, true)
        "delegation_notice" -> Style("🔀", "Delegation", ActAccent.NONE, false)
        "status_update" -> Style("💬", "Status", ActAccent.NONE, false)
        else -> Style("📌", ev.eventType, ActAccent.NONE, false)
    }

    /** Pretty-print a JSON payload for the disclosure; anything else rides raw. */
    fun prettyPayload(payload: String?): String? {
        val p = payload?.takeIf { it.isNotBlank() } ?: return null
        return try {
            org.json.JSONObject(p).toString(2)
        } catch (_: Throwable) {
            try {
                org.json.JSONArray(p).toString(2)
            } catch (_: Throwable) {
                p
            }
        }
    }
}
