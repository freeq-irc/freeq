I added 23 tests for the display and input helpers in `freeq-tui/src/main.rs`, and the full gate (`bash .fabro/verify.sh`) passes. They're in the existing `tests` module, using its naming style and the existing `tags()` helper, with no production code changed. `cargo test -p freeq-tui` passes (150 tests), and clippy with `-D warnings` and `cargo fmt --check` are clean.

The first gate run timed out on the tool's limit, so I reran it in the background and it passed.

The tests cover:
- **`format_file_size`:** the boundaries at 0, 1023, 1024 and 1 MiB, plus fractional KB and MB values.
- **`format_link_preview`:**
  - Title, description and URL come out in order, and a missing title or description is left out.
  - A description of exactly 120 bytes is kept whole, and 121 bytes is cut with `…`.
  - A description of 61 two-byte characters is cut on a character boundary.
- **`format_media_display`:**
  - The icon matches the type (image, video, audio, other).
  - An undeclared type is judged by the URL.
  - Alt text, size and `W×H` appear in order with the URL last, and `W×H` needs both width and height.
- **`parse_timestamp_ms` and `format_timestamp`:**
  - Valid RFC3339 tags give exact epoch milliseconds, including fractional seconds and `+01:00` offsets.
  - A missing or malformed tag falls back to a time within the bounds I read before and after the call.
  - The displayed time is the same for the same instant sent in different offsets, so it doesn't depend on the machine's time zone.
- **`try_nick_complete`:**
  - A nick at the start of the line completes with `: `, and one mid-line completes with a space and keeps the rest.
  - Case and the `@`/`+` prefixes are ignored, and the first match wins.
  - Nothing happens when there's no match, an empty fragment, an empty line or no active buffer.
  - Only the text before the cursor is considered, and a wide character earlier in the line doesn't break it.

**Panic risk left untested:** I didn't write a test that triggers the panic in `format_link_preview`, because fixing it would change production behavior. The truncation is `&desc[..120]` by byte index. A description whose 120th byte falls inside a multibyte character, for example one ASCII byte followed by two-byte characters, will panic the TUI. Anyone who can post a link can supply that text. The fix is a one-line change to cut on a character boundary, and I can make it with a regression test as a separate change if you want.

I also didn't run `ctcp_action` again, since it's already covered at line 3877.