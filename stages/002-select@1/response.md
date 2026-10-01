## Choice

**File:** `freeq-tui/src/main.rs` (Rust, crate `freeq-tui`). It's inside the CI-covered surface and avoids the AV crates.

The tests will go in a new `#[cfg(test)]` module of display and parsing helpers. They'll sit next to the existing test module that starts at line 3501.

### Why this file

- **Hotspot score:** `bash scripts/hotspots.sh --top 25` lists it at 4187 lines and 79 functions, gamma 4. It's smaller than the top entries but far from trivial.
- **The CLAUDE.md "undertested" list is stale.** I checked each named file:
  - `freeq-app/src/irc/client.ts` now has about a dozen `client-*.test.ts` files.
  - `freeq-sdk/src/client.rs` has 176 tests across 6 test modules.
  - `freeq-sdk-js/src/client.ts` already has a 4000-line test file.
  - `server.rs`, `db.rs` and `web.rs` are huge and need a running server, so they don't suit one focused change.
- **Where the gap is in `main.rs`:** the existing 35 tests cover verification verdicts, key-set parsing and `parse_join_prefix`. The rendering and input helpers have no direct tests. A grep shows `format_file_size`, `format_link_preview`, `format_media_display`, `parse_timestamp_ms`, `format_timestamp`, `try_nick_complete` and `ctcp_action` are only called from production code. `ctcp_action` appears once in the tests, at line 3877, only as a fixture. The other helpers have no test calls at all.
- **A likely real bug:** `format_link_preview` (line 3404) truncates with `&desc[..120]` on a byte index. A description with a multibyte character straddling byte 120 would panic the TUI. Anyone who can post a link can supply that description.

### Behaviors to pin

1. **`format_file_size`:**
   - 1023 gives `1023B`, 1024 gives `1.0KB`, and 1048575 gives `1024.0KB`.
   - 1048576 gives `1.0MB`, and 0 gives `0B`.
   - The 1048575 case is a rounding oddity at the KB/MB boundary.
2. **`format_link_preview`:**
   - Title, description and URL are joined in the right order, and a missing title or description is omitted.
   - A description of exactly 120 bytes is not truncated, and a longer one gets `…`.
   - A multibyte character crossing byte 120 should not panic. If it does, I'll write the test to expose that and fix it with a char-boundary-safe truncation.
3. **`format_media_display`:**
   - The icon depends on the type: image, video, audio, or `📎` for anything else.
   - Alt text, `W×H` and size appear only when present.
   - `W×H` needs both width and height, so one alone is omitted.
   - The URL is always last.
4. **`parse_timestamp_ms` and `format_timestamp`:**
   - A valid RFC3339 `time` tag gives the exact epoch milliseconds, for example `2024-01-01T00:00:00Z` gives `1704067200000`.
   - A missing or malformed tag falls back to a value near now, asserted within a tolerance.
5. **`ctcp_action`:** it wraps text as `\x01ACTION …\x01`, and empty text is still framed.
6. **`try_nick_complete`:** this is the highest-value case and needs a small `App` fixture. I'll reuse the `app.rs` test helpers if they're accessible, and otherwise cut this case. It should cover:
   - completion at the start of a line versus mid-line
   - an empty fragment being a no-op
   - case-insensitive prefix matching
   - a multibyte character before the cursor not panicking on the `&text[..cursor]` slice

### Convention to follow

- The sibling module is `#[cfg(test)] mod tests` in `freeq-tui/src/main.rs` (from line 3501). It uses descriptive behavior-style names, such as `parse_join_prefix_rejects_control_chars_in_host` and `a_verdict_reads_as_who_vouches_for_the_message`.
- It also has small local helpers, like `tags(&[(&str,&str)])`. I'll build `MediaAttachment` and `LinkPreview` fixtures in the same way.
- Tests are pure synchronous `#[test]` functions with no network or server. `app.rs` (from line 1325) has the `App` construction pattern to borrow for the nick-completion tests.
- I'll run them with `cargo test -p freeq-tui`.