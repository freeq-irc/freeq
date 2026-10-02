I added 18 tests to the existing `mod tests` block in `freeq-auth-broker/src/lib.rs`. It's the only file changed, and no production code was touched. The crate's unit tests went from 9 to 27 and all pass. `cargo fmt`, `cargo clippy -p freeq-auth-broker --tests -- -D warnings` and `bash .fabro/verify.sh` are all clean.

I overstated the gap in my earlier report. `tests/characterization.rs` already covers the return_to allowlist, the encrypt/decrypt round-trip and tamper cases, and the `sign_body` wire format. I left those alone and tested what was actually missing:

- **`verify_signed_body`**
  - A body signed by `sign_body` verifies.
  - It refuses a missing signature or timestamp header, and non-numeric timestamps.
  - The 60-second window is checked both ways with no sleeping: 50 seconds off passes, and 120 seconds off or a timestamp of 0 is expired.
  - It refuses a tampered body, a wrong secret, a garbage signature, and a valid MAC reused with a different timestamp.
- **`encrypt_field` / `decrypt_field` / `derive_encryption_key`**
  - Nonces are fresh on every call.
  - The empty string round-trips.
  - Bad base64, empty input, a nonce with no ciphertext, and junk ciphertext are each refused with the right error.
  - Different secrets derive different keys.
- **`is_valid_return_to`**
  - It refuses the `irc.freeq.at@evil.example` userinfo trick, `javascript:`, `data:`, `ftp:`, empty input and `https://`.
  - It refuses `localhost.evil.example` and `sub.irc.freeq.at`.
  - It accepts an uppercase host.
- **`is_private_ip`**
  - It flags private IPv4 and IPv6 ranges, including `100.64.0.0/10` (carrier-grade NAT) and the metadata IP `169.254.169.254`.
  - It does not flag the public addresses just outside each boundary, such as `172.15.x`, `172.32.x`, `100.63.x` and `100.128.x`.
- **Small helpers:** `token_hash` is checked against the known SHA-256 of `"abc"`, plus lowercase hex output. `is_truthy` is pinned to `1`, `true` and `yes`. `pds_endpoint` takes the first matching service, returns none when there isn't one, and matches case-sensitively.

I left out `fec0::1`. The deprecated IPv6 site-local range isn't blocked by `is_private_ip`, and a test asserting that would lock in a questionable behavior. It may be worth a separate look.