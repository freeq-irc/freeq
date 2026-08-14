# Plan: Implement IRCv3 `account-tag` capability

**Status:** code complete, ready to commit + push + deploy
**Date:** 2026-04-09
**Motivation:** Bots receiving DMs see `sender_did: None` because the server never emits an `account` tag on PRIVMSG. The `account-tag` IRCv3 cap is unimplemented (verified: missing from `freeq-server/src/connection/messaging.rs`, marked ❌ in `docs/Features.md:126`). The SDK bot framework already reads `tags.get("account")` at `freeq-sdk/src/bot.rs:327`.

## Spec

`account-tag` (https://ircv3.net/specs/extensions/account-tag): server adds `account=<accountname>` tag to messages from authenticated users, **only** to clients that negotiated the cap.

## Steps

- [x] Verify bug premise (asymmetry claim was wrong — missing on both channel and DM)
- [x] Read existing CAP negotiation, tag-line build pattern, deploy flow
- [x] Add `cap_account_tag: Mutex<HashSet<String>>` to `SharedState`
- [x] Add `cap_account_tag: bool` to `Connection`
- [x] Advertise `account-tag` in CAP LS
- [x] Accept `account-tag` in CAP REQ
- [x] Clean up `cap_account_tag` on disconnect
- [x] In `handle_privmsg` channel branch: build extra `tagged_line_with_account` and `tagged_line_with_time_and_account` variants when sender has DID; deliver to recipients per cap
- [x] In `handle_privmsg` DM branch: same
- [x] Tests:
  - [x] account-tag cap negotiation succeeds
  - [x] PRIVMSG to channel: recipient with account-tag cap sees `account=<did>`; recipient without does not
  - [x] PRIVMSG DM: recipient with cap sees account; recipient without does not
  - [x] Guest sender (no DID): no account tag added regardless
- [x] Update `docs/Features.md` (and `freeq-site/docs/Features.md` mirror) to mark `account-tag` as ✅
- [x] `cargo build` clean
- [x] `cargo test -p freeq-server` clean
- [x] Lint check
- [ ] Commit (attribute to Chad only, no Claude co-author per global rules)
- [ ] Push to GitHub (user already authorized in this turn)
- [ ] Deploy: ssh to the production host, run `./deploy/deploy.sh`
- [ ] Verify service is up

## Out of scope

- Edits (`+draft/edit`) and TAGMSG/reactions paths — separate flow, follow up if requested. Bot SDK only reads `account` from PRIVMSG, so this satisfies the immediate need.
- S2S relay: incoming S2S Privmsg constructs its own lines on the receiving server; that path also needs to inject account tag for federated DMs but is a separate change because it requires looking up the remote sender's DID. Note as follow-up.
