**Chosen file:** `freeq-auth-broker/src/lib.rs`. It's Rust, in the `freeq-auth-broker` crate, which CI covers because it isn't one of the excluded AV crates. The next step adds tests to its existing `#[cfg(test)]` block at about line 2204.

**Why it's high-risk and undertested**
- The file is 2,396 lines with 74 functions. It sits in the top 25 of `scripts/hotspots.sh`, but it isn't one of the three files `CLAUDE.md` names.
- I skipped the three files `CLAUDE.md` flags as undertested. `freeq-app/src/irc/client.ts` now has about 14 sibling test files and 600+ lines in `client.test.ts` alone. `MessageList.tsx` has about 12 test files. `sdk/client.rs` has about 176 tests across six `#[cfg(test)]` modules, so the `CLAUDE.md` note looks stale.
- By contrast, this file has only 9 tests. They cover the SSRF provider, the session stores, the origin guard and enrollment refusal.
- None of the pure security primitives have a test. They cover crypto, HMAC request auth, redirect validation and SSRF IP classification, so a regression in any of them is a security bug rather than a cosmetic one.

**Behaviors to pin** (all pure functions, no network or server needed)
1. **`verify_signed_body` / `sign_body`**
   - A signed body round-trips.
   - It is rejected when a header is missing, the timestamp is non-numeric, the timestamp is more than 60 s old or in the future (testing 59 s versus 61 s), or the body or secret is tampered with.
   - The MAC covers the timestamp, so a valid signature can't be reused with a different `ts`.
2. **`encrypt_field` / `decrypt_field`**
   - Encrypt then decrypt returns the original text.
   - Two encryptions of the same text differ because the nonce is random.
   - Decrypting fails with the wrong key, with flipped ciphertext bits, with input shorter than 13 bytes, and with invalid base64.
   - `derive_encryption_key` is deterministic and depends on the secret.
3. **`is_valid_return_to`**
   - Allowed: the exact allowlisted `https` hosts, and `http://localhost` or `127.0.0.1` on any port.
   - Rejected: the prefix-bypass `https://irc.freeq.at.evil.example` (the C-6 regression), `//host`, `/\host`, `http://irc.freeq.at` (wrong scheme), `javascript:` URLs, and unparseable input.
   - Relative paths like `/foo` are allowed.
4. **`is_private_ip`**
   - Private: loopback, RFC1918, link-local, broadcast, unspecified, CGNAT 100.64/10, IPv6 ULA and IPv6 link-local.
   - Boundaries: `100.63.x` and `100.128.x` are public.
   - A public IPv4 and a public IPv6 address are not private.
5. **`token_hash`**: The output is lowercase 64-character hex and matches the known SHA-256 of `"abc"`.
6. **Small helpers**
   - `is_truthy` accepts `1`, `true` and `yes`, and rejects `None`, `0` and `TRUE`.
   - `pds_endpoint` returns the `AtprotoPersonalDataServer` service, ignores other service types, and returns `None` when there is none.

**Convention to follow:** the existing `mod tests` at the bottom of `freeq-auth-broker/src/lib.rs`. It uses plain `#[test]` for pure functions and `#[tokio::test]` for async ones, with behavior-sentence names such as `a_retirement_must_be_dated_now` and `a_device_record_may_carry_an_old_date`. The `freeq-tui/src/main.rs` tests use the same naming style. I'd add no new dependencies, since `hmac`, `sha2` and `base64` are already in the crate.

One caveat: `is_private_ip` and `pds_endpoint` are private, but the in-file test module can reach them. I haven't run any of this, since this step is read-only.