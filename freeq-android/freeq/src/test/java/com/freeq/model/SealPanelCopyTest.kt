package com.freeq.model

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The seal panel's words, and the tables that pick them.
 *
 * The prose lives in `spec/act-card-copy.json` and this client bundles a copy;
 * the first test pins the two byte-identical. The register and role tables are
 * checked against `spec/act-transitions.json` itself, so a verb added to the
 * rules file cannot quietly go uncovered.
 */
class SealPanelCopyTest {

    /** The repo's `spec/` directory, found by walking up from the test's cwd. */
    private fun specFile(name: String): File {
        var dir: File? = File(System.getProperty("user.dir")!!).absoluteFile
        while (dir != null) {
            val f = File(dir, "spec/$name")
            if (f.isFile) return f
            dir = dir.parentFile
        }
        throw AssertionError("spec/$name not found above ${System.getProperty("user.dir")}")
    }

    @Test fun the_bundled_copy_is_byte_identical_to_the_canonical_one() {
        val copy = javaClass.classLoader!!.getResourceAsStream("act-card-copy.json")
            ?: throw AssertionError("act-card-copy.json is not on the classpath")
        assertEquals(
            "refresh with: cp spec/act-card-copy.json freeq-android/freeq/src/main/resources/act-card-copy.json",
            specFile("act-card-copy.json").readText(),
            copy.reader(Charsets.UTF_8).readText(),
        )
    }

    @Test fun the_header_takes_the_kind_off_the_event_tag_uppercased() {
        assertEquals("HANDOFF: Rules Enforced", SealPanelCopy.header("handoff"))
        assertEquals("BOUNTY: Rules Enforced", SealPanelCopy.header("bounty"))
        assertEquals("SOCIETY-QUESTION: Rules Enforced", SealPanelCopy.header("society-question"))
    }

    @Test fun the_link_is_labelled_from_the_spec_file() {
        assertEquals("View full history", SealPanelCopy.linkText())
    }

    @Test fun each_role_gets_its_own_sentence() {
        assertEquals(
            "This opened a task with known rules: who may take it, who may work it, who may finish it. Every later step is checked against those rules before the server accepts it — an illegal step is refused and never appears here.",
            SealPanelCopy.sentence("offer"),
        )
        val offeree = "Only the person this task was offered to could take this step. The server checked that before accepting it — this step from anyone else is refused and never appears here."
        assertEquals(offeree, SealPanelCopy.sentence("accept"))
        assertEquals(offeree, SealPanelCopy.sentence("decline"))
        val assignee = "Only the worker this task is assigned to could take this step. The server checked that before accepting it — this step from anyone else is refused and never appears here."
        for (v in listOf("progress", "complete", "fail", "submit", "forfeit")) {
            assertEquals(v, assignee, SealPanelCopy.sentence(v))
        }
        val offerer = "Only the person who posted this task could take this step. The server checked that before accepting it — this step from anyone else is refused and never appears here."
        for (v in listOf("cancel", "award", "revise", "accept-work")) {
            assertEquals(v, offerer, SealPanelCopy.sentence(v))
        }
        val anyone = "Any signed-in account could take this step, and the server checked it was legal from the task's current state before accepting it — an illegal step is refused and never appears here."
        assertEquals(anyone, SealPanelCopy.sentence("claim"))
        assertEquals(anyone, SealPanelCopy.sentence("bid"))
    }

    @Test fun a_system_verb_and_an_unknown_verb_claim_nothing() {
        for (v in listOf("confirm", "expire", "auto-accept", "nobody-taught-this")) {
            assertNull(v, SealPanelCopy.sentence(v))
        }
    }

    // ── The tables, against the rules file ──

    private data class Row(val verb: String, val from: List<String>, val to: String, val who: String)

    private fun rules(): Pair<List<Row>, Set<String>> {
        val doc = JSONObject(specFile("act-transitions.json").readText())
        val kinds = doc.getJSONObject("kinds")
        val rows = mutableListOf<Row>()
        val openers = mutableSetOf<String>()
        for (kindName in kinds.keys()) {
            val kind = kinds.getJSONObject(kindName)
            openers.add(kind.getJSONObject("opens").getString("verb"))
            val ts = kind.getJSONArray("transitions")
            for (i in 0 until ts.length()) {
                val t = ts.getJSONObject(i)
                val fromRaw = t.get("from")
                val from = if (fromRaw is org.json.JSONArray)
                    (0 until fromRaw.length()).map { fromRaw.getString(it) }
                else listOf(fromRaw as String)
                rows.add(Row(t.getString("verb"), from, t.getString("to"), t.getString("who")))
            }
        }
        return rows to openers
    }

    @Test fun every_opening_verb_lands_in_the_new_register() {
        val (_, openers) = rules()
        assertTrue(openers.isNotEmpty())
        for (verb in openers) assertEquals(verb, ActRegister.NEW, ActVerbs.register(verb))
    }

    @Test fun the_register_is_the_register_of_the_state_the_step_lands_in() {
        val byState = mapOf(
            "open" to ActRegister.NEW, "offered" to ActRegister.NEW,
            "assigned" to ActRegister.IN_PROGRESS, "under_review" to ActRegister.IN_PROGRESS,
            "completed" to ActRegister.ENDED_WELL, "accepted" to ActRegister.ENDED_WELL,
            "failed" to ActRegister.DID_NOT_END_WELL, "forfeited" to ActRegister.DID_NOT_END_WELL,
            "cancelled" to ActRegister.DID_NOT_END_WELL, "declined" to ActRegister.DID_NOT_END_WELL,
        )
        val (rows, _) = rules()
        for (row in rows) {
            if (row.who == "system") {
                assertNull(row.verb, ActVerbs.register(row.verb))
                continue
            }
            // An additive step — one that lands where it started — is
            // in-progress whatever state it sits in.
            val additive = row.to in row.from
            val want = if (additive) ActRegister.IN_PROGRESS else byState[row.to]
            assertNotNull("no register for state ${row.to}", want)
            assertEquals(row.verb, want, ActVerbs.register(row.verb))
        }
    }

    @Test fun the_two_additive_verbs_are_in_progress() {
        assertEquals(ActRegister.IN_PROGRESS, ActVerbs.register("bid"))
        assertEquals(ActRegister.IN_PROGRESS, ActVerbs.register("progress"))
    }

    @Test fun a_verb_nobody_taught_it_falls_to_the_neutral_end() {
        assertEquals(ActRegister.NEUTRAL_END, ActVerbs.register("escalate"))
        assertEquals(ActRegister.NEUTRAL_END, ActVerbs.register(""))
    }

    @Test fun every_non_system_row_reports_its_own_who_as_the_role() {
        val (rows, openers) = rules()
        for (verb in openers) assertEquals(verb, "opener", ActVerbs.whoRole(verb))
        for (row in rows) {
            if (row.who == "system") assertNull(row.verb, ActVerbs.whoRole(row.verb))
            else assertEquals(row.verb, row.who, ActVerbs.whoRole(row.verb))
        }
    }

    @Test fun every_role_the_rules_file_uses_has_a_sentence() {
        val copy = JSONObject(specFile("act-card-copy.json").readText())
            .getJSONObject("seal_panel").getJSONObject("sentences")
        val (rows, _) = rules()
        val roles = mutableSetOf("opener")
        for (row in rows) if (row.who != "system") roles.add(row.who)
        for (role in roles) assertTrue(role, copy.optString(role).isNotEmpty())
    }
}
