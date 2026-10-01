The bug is real and now fixed: the test failed before the fix, passes after it, and the full gate (`bash .fabro/verify.sh`) passed.

**The bug:** on a `+i` channel, a guest invited by nick was refused if the inviter typed the nick in different case. `INVITE bob #room` stored the token `nick:bob`, but when `Bob` joined, the server looked for `nick:Bob` and returned `473`. Nicks are case-insensitive everywhere else in the server, so invites were the odd one out. The same mismatch meant a used one-shot invite was never deleted from the DB, so it came back after a restart.

**The proof:** the new test `s2s_nick_invite_matches_join_case_insensitively` in `server.rs` sends a peer invite for `nick:bob` to a `+i` channel, then a peer join as `Bob`. Before the fix it failed for the right reason: `an invite for \`bob\` must admit \`Bob\` through the +i gate`, meaning the join was rejected at the `+i` check. After the fix, Bob is admitted and the invite is used up.

**The fix** touches only `freeq-server`:
- **New helper** `invite_nick_token(nick)` in `server.rs` builds `nick:{nick.to_lowercase()}`, the same lowercasing the nick table uses.
- **`connection/channel.rs`:** every place that builds or checks the token now uses the helper. That covers the local JOIN check, removing the used invite from memory and the DB, and both INVITE paths (local and remote target).
- **`server.rs`, peer messages:** the incoming Join check and consume use the helper. Incoming Invite tokens starting with `nick:` are lowercased, so invites from servers without this fix still match. DID tokens are untouched.

**Checks run:**
- `cargo test -p freeq-server --lib invite`: 16 passed.
- `cargo test -p freeq-server --test integration invite`: 10 passed.
- `cargo fmt --all` and `cargo clippy -p freeq-server --tests` are clean, with no new `#[allow]`.

**Not changed:** I didn't touch `load_invites`, so mixed-case invite rows already in a DB stay as they are. After the fix they can't match any join, so they can't let anyone in; at worst such an invite simply stops working.