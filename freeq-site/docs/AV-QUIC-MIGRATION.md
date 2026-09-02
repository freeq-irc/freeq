# AV QUIC / WebTransport Migration

Plan to make freeq AV usable by moving its media transport off WebSocket.

## Problem

freeq AV audio is staticky for **every** client — humans and bots alike. The
cause is the media transport, not TTS or encoding.

The SFU (`freeq-server/src/av_sfu.rs`, a `moq_relay::Cluster`) is reachable two
ways:

- **QUIC / WebTransport** — UDP `:8080` (the SFU binds `web_addr`'s port;
  production runs `--web-addr 0.0.0.0:8080`). The separate `staging.freeq.at`
  deployment uses `:4443` — do not confuse the two.
- **MoQ-over-WebSocket** — TCP, via nginx `:443 → /av/moq → :8080`

QUIC is unusable for browsers today because the QUIC listener presents a
self-signed `localhost` certificate. So every client falls back to
MoQ-over-WebSocket/TCP — and that path collapses under sustained real-time
media: the instant a client's audio encoder starts publishing, the connection
floods `transport error: connection closed` ~50×/sec and audio degrades to
static.

**Evidence.** The eliza agent over WebSocket logged *thousands* of
`connection closed`. The same bot over QUIC (`--sfu-url
https://irc.freeq.at:8080/av/moq`) logged **zero**.

## Goal

All AV media over QUIC/WebTransport. WebSocket remains only as a last-resort
fallback (moq-native already races the two and keeps whichever connects).

## Open question — QUIC ↔ WebSocket interop

An earlier test had a QUIC client and a WebSocket client fail to see each other,
but they were on **different SFU deployments** (the QUIC client hit
`staging.freeq.at:4443`; the WebSocket client hit production) — so it proves
nothing about within-cluster interop. Whether a QUIC client and a WebSocket
client interconnect through one production `moq_relay::Cluster` is unresolved;
they negotiate different moq-lite versions (QUIC v03, WebSocket v02). Phase 2
re-tests this against the production SFU. If they bridge, the migration can be
gradual; if not, clients must cut over together.

## Phases

### Phase 0 — Cert plumbing  (`av-deploy.sh cert`; no code)

`freeq-server` runs as a non-root service user; Let's Encrypt's `privkey.pem`
is root-only. Copy the cert to a service-user-readable directory and keep it
fresh on renewal.

- Copy `/etc/letsencrypt/live/<your-domain>/{fullchain,privkey}.pem`
  → `/srv/freeq-certs/` (owned by the service user, mode `600`).
- Install `/etc/letsencrypt/renewal-hooks/deploy/freeq-av-cert.sh` to re-copy
  the cert and restart `freeq-server` on each renewal.
- **Verify:** the two `.pem` files exist, are service-user-owned, mode `600`.

### Phase 1 — SFU QUIC on the real cert  (`freeq-server/src/av_sfu.rs`)

In `run_quic_accept`, replace `server_config.tls.generate = ["localhost"]` with
the real cert when it is configured:

```rust
match (std::env::var("FREEQ_AV_TLS_CERT"), std::env::var("FREEQ_AV_TLS_KEY")) {
    (Ok(cert), Ok(key)) => {
        server_config.tls.cert = vec![cert.into()];
        server_config.tls.key  = vec![key.into()];
    }
    // Dev fallback: self-signed, browsers can't use it.
    _ => server_config.tls.generate = vec!["localhost".to_string()],
}
```

`moq_native::ServerTlsConfig` takes `cert: Vec<PathBuf>` + `key: Vec<PathBuf>`,
zipped pairwise (see moq-native `tls.rs::load_certs`).

Add to the systemd `EnvironmentFile` (e.g. `/etc/freeq/secrets`):

```
FREEQ_AV_TLS_CERT=/srv/freeq-certs/fullchain.pem
FREEQ_AV_TLS_KEY=/srv/freeq-certs/privkey.pem
```

Deploy + restart. **Verify:** a native client connects to
`https://irc.freeq.at:8080/av/moq` *with cert verification enabled* and the
handshake succeeds — proving the cert is publicly trusted.

### Phase 2 — Native clients on QUIC

- Transcriber bot: run with `--sfu-url https://irc.freeq.at:8080/av/moq`
  (already supported).
- iOS (`freeq-sdk-ffi`): point the MoQ URL at QUIC `:8080` instead of deriving
  `:443/av/moq`.
- **Verify:** `connection closed` stays ~0 under publish load.

### Phase 3 — Web client on WebTransport  (`freeq-app`)

Point the moq-watch / moq-publish components at `https://irc.freeq.at:8080/...`.

**Investigate first:** how `freeq-app` configures the moq components' endpoint,
and confirm moq-watch/moq-publish negotiate WebTransport (HTTP/3) when handed an
`https://host:8080` URL. **Verify** in browser DevTools: an HTTP/3 / WebTransport
session, not a `ws://` one.

### Phase 4 — Cross-client interop check

All three client types in one call. Confirm they see and hear each other (the
v02/v03 split was QUIC-vs-WebSocket; all-QUIC should be uniform — verify). If a
version split remains, pin the moq-lite version across clients.

### Phase 5 — Cutover + acceptance

Make QUIC the default endpoint for web/iOS/bot; keep WebSocket as the
moq-native-raced fallback. Acceptance:

- human ↔ human call: no static, sustained 5 minutes.
- bot voice reply: clean.
- `connection closed` stays ~0 under load.

## Risks / open questions

- moq-watch/moq-publish WebTransport support, and how `freeq-app` sets the
  endpoint URL (Phase 3).
- Whether all-QUIC fully resolves the moq-lite v02/v03 split (Phase 4).
- QUIC `:8080` is UDP; `ufw` is inactive on the host, but some client networks
  block non-443 UDP — the WebSocket fallback must stay.

## Rollback

- Client URL changes: revert → clients fall back to WebSocket (staticky but
  functional).
- `av_sfu.rs`: backward-compatible — unset the env vars → self-signed fallback.
- Redeploy with `deploy/av-deploy.sh deploy`.

## Automation

`deploy/av-deploy.sh [cert|deploy|verify|all]` — pushes the current branch, then
over SSH pulls/builds/restarts `freeq-server` on `$FREEQ_SERVER` and
health-checks the SFU.
