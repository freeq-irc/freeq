package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The payload rule every event card renders through — the same rule the web,
 * macOS and iOS clients apply, so one payload reads the same on all four.
 */
class EventCardPayloadTest {

    /** The wire form: percent-encoded in the tag. */
    private fun enc(s: String): String {
        val out = StringBuilder()
        for (b in s.toByteArray(Charsets.UTF_8)) {
            val c = b.toInt().toChar()
            if (c.isLetterOrDigit() || c in "-_.!~*'()") out.append(c)
            else out.append('%').append("%02X".format(b.toInt() and 0xFF))
        }
        return out.toString()
    }

    private fun rows(raw: String?) = EventCardPayload.rows(raw)

    @Test fun an_object_gives_one_row_per_top_level_key_in_order() {
        assertEquals(
            listOf(PayloadRow("to", "bob"), PayloadRow("why", "capacity")),
            rows(enc("""{"to":"bob","why":"capacity"}""")),
        )
    }

    @Test fun a_string_value_shows_as_itself_and_the_rest_as_compact_json() {
        assertEquals(
            listOf(
                PayloadRow("note", "half done"),
                PayloadRow("n", "3"),
                PayloadRow("ok", "true"),
                PayloadRow("tags", """["a","b"]"""),
                PayloadRow("deep", """{"x":1}"""),
                PayloadRow("nil", "null"),
            ),
            rows(enc("""{"note":"half done","n":3,"ok":true,"tags":["a","b"],"deep":{"x":1},"nil":null}""")),
        )
    }

    @Test fun a_number_keeps_the_spelling_the_document_gave_it() {
        assertEquals(listOf(PayloadRow("load", "0.3")), rows(enc("""{"load":0.3}""")))
        assertEquals(listOf(PayloadRow("n", "1.0")), rows(enc("""{"n":1.0}""")))
        assertEquals(listOf(PayloadRow("big", "1e2")), rows(enc("""{"big":1e2}""")))
    }

    @Test fun a_nested_object_shows_as_written_in_its_own_key_order() {
        assertEquals(
            listOf(PayloadRow("deep", """{"b":1,"a":2}""")),
            rows(enc("""{"deep":{"b":1,"a":2}}""")),
        )
    }

    @Test fun whitespace_between_tokens_goes_but_not_inside_a_string() {
        assertEquals(
            listOf(PayloadRow("deep", """{"b":"x y"}""")),
            rows(enc("""{ "deep" : { "b" : "x y" } }""")),
        )
    }

    @Test fun an_array_or_a_scalar_payload_keeps_its_spelling() {
        assertEquals(listOf(PayloadRow("payload", "[1.0,2]")), rows(enc("[1.0, 2]")))
        assertEquals(listOf(PayloadRow("payload", "1e2")), rows(enc("1e2")))
    }

    @Test fun an_empty_object_gives_no_rows() {
        assertEquals(emptyList<PayloadRow>(), rows(enc("{}")))
    }

    @Test fun an_array_is_one_row_keyed_payload() {
        assertEquals(
            listOf(PayloadRow("payload", """[1,"two",{"three":3}]""")),
            rows(enc("""[1,"two",{"three":3}]""")),
        )
    }

    @Test fun a_scalar_is_one_row_keyed_payload() {
        assertEquals(listOf(PayloadRow("payload", "42")), rows(enc("42")))
        assertEquals(listOf(PayloadRow("payload", "true")), rows(enc("true")))
        assertEquals(listOf(PayloadRow("payload", "null")), rows(enc("null")))
        assertEquals(listOf(PayloadRow("payload", "just words")), rows(enc("\"just words\"")))
    }

    @Test fun text_that_is_not_json_rides_raw_in_the_payload_row() {
        assertEquals(
            listOf(PayloadRow("payload", "half the build is red")),
            rows(enc("half the build is red")),
        )
    }

    @Test fun a_malformed_percent_escape_keeps_the_tag_value() {
        assertEquals(listOf(PayloadRow("payload", "100%-sure")), rows("100%-sure"))
    }

    @Test fun a_plus_sign_stays_a_plus_sign() {
        // Percent-decoding is not form decoding: `+` is not a space.
        assertEquals(listOf(PayloadRow("payload", "a+b")), rows("a+b"))
    }

    @Test fun no_payload_at_all_gives_no_rows() {
        assertEquals(emptyList<PayloadRow>(), rows(null))
        assertEquals(emptyList<PayloadRow>(), rows(""))
        assertEquals(emptyList<PayloadRow>(), rows("   "))
    }
}
