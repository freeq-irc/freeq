I found one real bug and I'm confident in it. Nothing was edited in this step. I haven't written or run the test yet; the plan for it is below.

## Bug: nick-based invite tokens are case-sensitive, so a valid INVITE to a guest can be refused

**Where**
- **Stored in the case the inviter typed:**
  - `freeq-server/src/connection/channel.rs:1538`: the token sent to peers (S2S) and saved to the DB for a local guest.
  - `channel.rs:1590` and `:1594`: a remote guest.
- **Checked against the joiner's own display nick, exact match:**
  - `channel.rs:116`: local JOIN check.
  - `server.rs:7155`: JOIN arriving from a peer (S2S).
- **Consumed the same way:** `channel.rs:180`, `:192` and `server.rs:7203`.
- **Accepted from peers without normalising:** `server.rs:8376` (S2S `Invite`) and `server.rs:7917` (SyncResponse).

**The defect.** IRC nicks are case-insensitive, and the server agrees elsewhere: `NickMap` and `resolve_network_target` (`helpers.rs:115`) look nicks up case-insensitively. So `INVITE bob #priv` correctly finds a guest whose nick is `Bob`. But the grant is stored as `nick:bob`, while the join checks for `nick:Bob`. The two never match, and the invited user gets `473 ERR_INVITEONLYCHAN`.

DID-based invites aren't affected. This hits guests (no DID), which is exactly who `nick:` tokens exist for.

**How to trigger it (federated)**
1. Server A: `alice` is op of `#priv`, which is `+i`. Server B: guest `Bob` is visible to A as a remote member.
2. Alice sends `INVITE bob #priv`. A gets 341, stores `nick:bob`, and sends S2S `Invite{invitee:"nick:bob"}`. B stores `nick:bob`.
3. Bob sends `JOIN #priv` on B. The check at `channel.rs:116` looks for `nick:Bob` and fails, so Bob gets 473.
4. Even if B let him in, A's check at `server.rs:7155` would reject the incoming S2S `Join{nick:"Bob"}`, so the two servers' member lists would disagree.

**Same bug on one server, across a restart.** For a local guest, the in-memory grant is keyed by session ID, so it works until the server restarts. What gets saved to the DB is `nick:bob` (`channel.rs:1538` → `add_invite`), and it's reloaded at `server.rs:1972`. After a restart, `Bob` reconnects and is refused, even though the invite's whole purpose is to survive restarts.

**Correct behaviour:** an invite to `bob` admits `Bob`, the same as every other nick lookup on the server.

## The failing test
I'll add it to the in-process S2S test module in `server.rs`, using the same harness as `s2s_invite_*` near line 11870 (`test_state`, `test_manager`, `setup_authenticated_peer`, `setup_channel`):
1. Set up `#invcase` as `+i`, with `founder_did = FOUNDER_DID`.
2. Deliver S2S `Invite { invitee: "nick:bob", invited_by_did: Some(FOUNDER_DID), .. }`.
3. Deliver S2S `Join { nick: "Bob", did: None, .. }`.
4. Assert `Bob` is in `remote_members`, and that the `nick:` invite was used up.

On current `main` the join is rejected at `server.rs:7155`, so `Bob` is missing and the test fails. If the harness allows it, a second test will cover the local JOIN check at `channel.rs:116` (S2S `Invite` for `nick:bob`, then a local guest `Bob` joins). Otherwise I'll put that one in the integration tests.

## A minimal fix
- Add one helper, e.g. `fn nick_invite_token(nick: &str) -> String { format!("nick:{}", nick.to_lowercase()) }`, and use it at every place listed above that builds a `nick:` token.
- Lowercase incoming `nick:`-prefixed tokens where they're accepted from peers (`server.rs:8376`, `:7917`), so a peer that sends mixed case still works.
- DID tokens, the auth logic and the DB schema stay unchanged.

**Confidence:** high. I read both sides of the mismatch, and the unequal casing comes straight from user input that the rest of the server treats as case-insensitive. One open question to settle while fixing: should tokens already in the DB be lowercased when loaded (`server.rs:1972`)? It's a one-line change, and I'd lean towards doing it.