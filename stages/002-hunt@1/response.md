I found one real bug: **nick-based invite tokens are matched case-sensitively, but nicks in freeq are case-insensitive.** On a `+i` channel, a guest invited as `bob` cannot join while their nick is `Bob`. A one-shot invite that was spent can also stay in the DB and come back after a restart. I haven't edited anything or run any tests yet.

## Where it is

Tokens are written with the nick exactly as the inviter typed it:
- `freeq-server/src/connection/mod.rs:1257` passes `msg.params[0]` to `handle_invite` unchanged.
- `connection/channel.rs:1538`: when a local target has no DID, it persists `nick:{target_nick}` to the DB and sends it to peers.
- `connection/channel.rs:1590, 1594`: for a remote target, it stores `nick:{target_nick}` in memory and broadcasts it.
- `server.rs:8376`: the S2S Invite receiver inserts the peer's token as-is.

Tokens are checked and consumed with the joiner's actual nick casing:
- Local JOIN check at `connection/channel.rs:116`, and consumption at `:185` (DB) and `:192` (memory).
- S2S Join check at `server.rs:7155` and consumption at `server.rs:7203`.

Everywhere else nicks are case-insensitive: `NickMap` (`server.rs:724`), `resolve_network_target` (`helpers.rs:116`), `remote_member()`, and ban matching, where `wildcard_match` lowercases both sides (`server.rs:609`). So `INVITE bob` correctly finds `Bob`, then stores a token that `Bob` can never match.

## What triggers it

1. **Federated guest.** Alice is an op of `+i #room` on server A. Guest `Bob` is on server B. Alice sends `INVITE bob #room`.
   - Both A and B store `nick:bob`.
   - When Bob joins on B, the local check looks for `nick:Bob` and he gets `473 ERR_INVITEONLYCHAN`.
   - Even if B let him in, A's S2S Join handler would drop the event at `server.rs:7155`.
2. **Local guest: a spent invite comes back.** `INVITE bob #room` for local guest `Bob`.
   - In memory, the session ID is stored too, so the join works.
   - Consuming the invite removes `nick:Bob` from the DB, but the row is `nick:bob`, so it is never deleted.
   - After a restart, `load_invites` brings back a one-shot invite that was already used. That is exactly what the comment at `channel.rs:175` says the code prevents, and it reopens `+i` for anyone who later takes the nick `bob`.

**Correct behaviour:** the invite is matched no matter how either side cases the nick, and using it removes it from both memory and the DB.

## The failing test

I'll add a unit test in `server.rs`'s test module, using the existing `test_state()`, `test_manager()` and `setup_authenticated_peer()` helpers, modelled on `s2s_invite_accepted_from_founder_who_has_already_left` (`server.rs:11852`):
1. Create `#invcase` with `invite_only = true` and `founder_did = FOUNDER`.
2. Process `S2sMessage::Invite { invitee: "nick:bob", invited_by_did: Some(FOUNDER), .. }`.
3. Process `S2sMessage::Join { nick: "Bob", did: None, .. }`.
4. Assert `ch.has_remote_member("Bob")` and that the invite was used up.

On current `main` this fails because the join is rejected at `server.rs:7155`. I can also add an integration test with `start_test_server_with_db` (`tests/integration.rs:3392`) that sends `INVITE <lowercased nick>` and checks the guest gets in. That would cover the local JOIN path.

## Keeping the fix small

- Add one helper, e.g. `invite_nick_token(nick) -> String`, that builds `nick:{nick.to_lowercase()}` using the same lowercasing as `NickMap`.
- Use it at the eight places that build the token: `channel.rs:116, 185, 192, 1538, 1590, 1594` and `server.rs:7155, 7203`.
- At `server.rs:8376`, lowercase incoming `nick:` tokens so invites from older peers still match. DID tokens stay untouched.

DB rows already written in mixed case would stay as they are unless I also lowercase them in `load_invites`. That's a one-line change; I'd include it only if you want existing rows fixed too.

**Confidence: high.** The mismatch is plain from reading the code, and ban matching already handles case correctly, so invites are the odd one out.

A smaller issue I noticed but am not proposing: `irc.rs:169` keeps the `\` on unknown tag escapes, while the IRCv3 spec says to drop it. It has much less impact.