---
title: "`ATPROTO-CHALLENGE` SASL mechanism"
layout: spec
work-in-progress: true
copyrights:
  -
    name: "Chad Fowler"
    period: "2026"
---

## Notes for implementing work-in-progress version

This is a draft specification. It is presented in the style of an IRCv3
working group document but has not been submitted to or adopted by the IRCv3
working group. The mechanism name and payload formats may change. Software
implementing this work-in-progress specification MUST NOT identify it as a
ratified IRCv3 extension.

This document is licensed under the
[Creative Commons Attribution 4.0 International License (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).

## Introduction

IRC account systems have historically been server-local: an account
registered with one network's services has no meaning anywhere else, and
proving ownership of it requires sending a password to the server. The
[AT Protocol](https://atproto.com/) provides portable, cryptographically
verifiable identities — [DIDs](https://www.w3.org/TR/did-core/) (Decentralized
Identifiers) — whose public keys are published in globally resolvable DID
documents.

This specification defines `ATPROTO-CHALLENGE`, a SASL mechanism for the
IRCv3 [`sasl`](https://ircv3.net/specs/extensions/sasl-3.1) capability that
lets a client authenticate to any participating IRC server by proving control
of an AT Protocol identity. The server issues a fresh challenge; the client
signs it with a private key listed in its DID document; the server verifies
the signature against the publicly resolvable DID document. No password,
token, or other long-lived secret is ever sent to the IRC server, and no
prior relationship between the client's identity provider and the IRC server
is required.

The authenticated account is the DID itself. The IRC nickname becomes a
display alias for that identity.

## Motivation

* **No shared secrets.** Password-based SASL mechanisms (`PLAIN`,
  `SCRAM-*`) require the server to hold or learn a per-account secret.
  A challenge–signature mechanism over public DID documents removes the
  server from the secret-handling path entirely.
* **Portable accounts.** A user's identity is the same on every server that
  implements this mechanism. Bans, grants, and reputation can attach to a
  stable cryptographic identity rather than a nick or hostmask.
* **No registration step.** Any AT Protocol identity can authenticate to any
  participating server on first contact.
* **Bot and agent friendly.** Software agents can hold an ed25519 or
  secp256k1 keypair directly (for example via `did:key` or a `did:web`
  document they control) and authenticate without any interactive flow.

## Architecture

### Dependencies

This mechanism builds on the
[`sasl` 3.1](https://ircv3.net/specs/extensions/sasl-3.1) capability and the
`AUTHENTICATE` command defined there, including its abort (`AUTHENTICATE *`)
and payload-chunking rules. It is compatible with
[`sasl` 3.2](https://ircv3.net/specs/extensions/sasl-3.2) capability values
and reauthentication.

Servers supporting this mechanism MUST advertise the `sasl` capability.
Servers that implement `sasl` 3.2 SHOULD include `ATPROTO-CHALLENGE` in the
capability's value, e.g. `sasl=ATPROTO-CHALLENGE,PLAIN`, and SHOULD reply
with `RPL_SASLMECHS` (`908`) when a client requests an unsupported
mechanism.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in
[RFC 2119](https://tools.ietf.org/html/rfc2119).

### Terminology

* **DID** — a Decentralized Identifier such as
  `did:plc:ewvi7nxzyoun6zhxrhs64oiz` or `did:web:example.org`. The DID is
  the account name produced by this mechanism.
* **DID document** — the publicly resolvable JSON document describing a
  DID, including its verification keys
  ([DID Core](https://www.w3.org/TR/did-core/)).
* **Handle** — a human-readable AT Protocol name (e.g.
  `alice.example.org`) that resolves to a DID. Handles are a client-side
  convenience; they never appear in the SASL exchange.
* **base64url** — the URL-safe base64 alphabet of
  [RFC 4648 §5](https://tools.ietf.org/html/rfc4648#section-5), **without**
  padding, unless stated otherwise.

### Overview

```
Client                                Server
  |  CAP REQ :sasl                      |
  |------------------------------------>|
  |  CAP ACK :sasl                      |
  |<------------------------------------|
  |  AUTHENTICATE ATPROTO-CHALLENGE     |
  |------------------------------------>|
  |  AUTHENTICATE <base64url challenge> |
  |<------------------------------------|
  |  AUTHENTICATE <base64url response>  |
  |------------------------------------>|
  |        (server resolves DID document,
  |         verifies signature)         |
  |  900 RPL_LOGGEDIN                   |
  |  903 RPL_SASLSUCCESS                |
  |<------------------------------------|
```

This document specifies one normative verification method, `crypto`
(direct signature with a DID-document key). The `method` field of the
response is extensible; deployment-specific methods are discussed in
[Appendix A](#appendix-a-deployment-specific-verification-methods-informative),
which is informative only.

## The challenge

When a client sends `AUTHENTICATE ATPROTO-CHALLENGE`, the server MUST
generate a fresh challenge and send it to the client as a single SASL
payload (see [Payload chunking](#payload-chunking)).

The challenge payload is the base64url encoding of a UTF-8 JSON object with
the following members:

| Field        | Type    | Description |
|--------------|---------|-------------|
| `session_id` | string  | An identifier for this connection, unique per transport connection on this server. |
| `nonce`      | string  | base64url encoding of at least 32 bytes from a cryptographically secure random number generator. |
| `timestamp`  | integer | Challenge issue time, Unix epoch seconds. |

Requirements:

* The `nonce` MUST be generated from a cryptographically secure random
  number generator and MUST contain at least 32 bytes of entropy.
* The `session_id` MUST be unique per transport connection, binding the
  challenge to the connection it was issued on. A challenge issued on one
  connection MUST NOT be accepted on another.
* Each challenge MUST be single-use: the server MUST invalidate it when a
  response is processed (whether verification succeeds or fails) and when
  the connection closes.
* The server MUST retain the exact byte sequence it encoded (the serialized
  JSON before base64url encoding). Signature verification is performed over
  these exact bytes; re-serializing the JSON is not guaranteed to reproduce
  them.
* Challenges MUST expire. The expiry window is measured between the
  challenge `timestamp` and the time the response is processed; a window of
  **60 seconds** is RECOMMENDED. Servers SHOULD treat the window as
  symmetric (rejecting timestamps too far in the future as well as the
  past) to bound the effect of clock errors.

Example decoded challenge (shown pretty-printed; the wire form is compact
JSON):

```json
{
  "session_id": "c0a8f3b2-4d11-4e0e-9c2f-7d52a1b6e803",
  "nonce": "BwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSY",
  "timestamp": 1718100000
}
```

Clients MUST treat the challenge as an opaque byte string for signing
purposes: decode the base64url payload and sign the resulting bytes exactly
as received. Clients MAY additionally parse the JSON (for example to read
the `nonce`), but MUST NOT re-serialize it before signing.

## The response

The client answers with a single SASL payload: the base64url encoding of a
UTF-8 JSON object with the following members:

| Field       | Type   | Presence | Description |
|-------------|--------|----------|-------------|
| `did`       | string | REQUIRED | The DID being authenticated. MUST begin with `did:`. |
| `signature` | string | REQUIRED | For the `crypto` method: unpadded base64url encoding of the signature over the raw challenge bytes. |
| `method`    | string | OPTIONAL | Verification method. Absent or `"crypto"` selects the method defined in this document. Other values are extension methods (see Appendix A). |

Additional members MAY be present for extension methods; servers MUST
ignore members they do not recognize for the selected method.

Requirements:

* The `did` field MUST be a DID, not a handle. Clients that accept handles
  from users MUST resolve the handle to a DID before authenticating (via
  the handle's `/.well-known/atproto-did` document or DNS TXT record, per
  AT Protocol identity resolution). Servers MUST reject identifiers that do
  not begin with `did:`.
* For the `crypto` method, `signature` MUST be the unpadded base64url
  encoding of the raw signature bytes (see
  [Signature algorithms](#signature-algorithms)) computed over the exact
  decoded challenge bytes. The challenge bytes are signed as-is; the client
  MUST NOT apply any additional hashing, canonicalization, or framing
  beyond what is intrinsic to the signature algorithm.
* If the server cannot decode the payload as base64url JSON, or the
  selected `method` is not supported, it MUST fail the exchange with
  `ERR_SASLFAIL` (`904`).

Example decoded response:

```json
{
  "did": "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
  "signature": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw",
  "method": "crypto"
}
```

## Payload chunking

Challenge and response payloads are carried in `AUTHENTICATE` parameters
under the rules of the base SASL specification:

* A payload longer than 400 bytes MUST be split into 400-byte chunks, each
  sent as its own `AUTHENTICATE` command, in order.
* If a payload's length is an exact multiple of 400 bytes (including zero),
  the sender MUST send one final `AUTHENTICATE +` to signal the end of the
  payload.
* A receiver MUST buffer chunks until it receives a chunk shorter than 400
  bytes (or `AUTHENTICATE +`), then process the concatenation as one
  payload.

This matters in practice: while a typical `crypto` response is under 400
bytes, extension methods can carry tokens and proofs that exceed it.

## Server verification (`crypto` method)

On receiving a complete response payload, the server MUST perform the
following steps. If any step fails, the server MUST fail the exchange with
`ERR_SASLFAIL` (`904`).

1. **Consume the challenge.** Look up the outstanding challenge for this
   connection and invalidate it. If there is no outstanding challenge, or
   it has expired, fail.
2. **Validate the identifier.** The `did` field MUST begin with `did:` and
   use a DID method the server supports.
3. **Resolve the DID document:**
   * `did:plc` — fetch the current DID document from a PLC directory
     (e.g. `https://plc.directory/<did>`) over HTTPS.
   * `did:web` — fetch `https://<domain>/.well-known/did.json` (or the
     path form `https://<domain>/<path>/did.json` for
     `did:web:<domain>:<path…>`) over HTTPS. Servers SHOULD apply
     SSRF protections when fetching `did:web` documents: resolve the
     hostname first, reject private and link-local addresses, and pin the
     checked addresses for the actual fetch.
   * `did:key` — servers MAY support `did:key`, in which case the DID
     document is synthesized locally from the public key embedded in the
     identifier; no network fetch is performed.
4. **Verify document identity.** The resolved document's `id` MUST equal
   the claimed `did` exactly.
5. **Select acceptable keys.** Acceptable verification keys are those
   referenced from the document's `authentication` section. Servers MAY
   additionally accept keys referenced from `assertionMethod` as a
   fallback. Entries may be string references into `verificationMethod` or
   inline verification method objects; both forms MUST be supported.
   Servers MUST NOT accept keys referenced only from other verification
   relationships (such as `capabilityDelegation`, `capabilityInvocation`,
   or `keyAgreement`). If no acceptable keys are found, fail.
6. **Verify the signature.** Decode `signature` as unpadded base64url.
   Attempt verification of the signature over the stored raw challenge
   bytes against each acceptable key in turn. If any key verifies, the
   client is authenticated as the claimed DID. If none verifies, fail.

### Signature algorithms

Servers MUST support verification with both of the following key types, and
clients MUST use the algorithm corresponding to their key's type:

* **ed25519** (`Multikey`/`publicKeyMultibase` prefix `z6Mk`) — pure
  Ed25519 per [RFC 8032](https://tools.ietf.org/html/rfc8032) (not
  Ed25519ph). The signature is 64 bytes.
* **secp256k1** (`publicKeyMultibase` prefix `zQ3s`) — ECDSA over
  secp256k1 with SHA-256 as the message digest, as standard for this
  curve in AT Protocol. The signature is the 64-byte compact `r || s`
  form (not DER). Signatures SHOULD use the low-S normalization.

In both cases the message is the raw challenge bytes; there is no
pre-hashing or framing beyond what the algorithm itself defines (SHA-256
is intrinsic to ECDSA signing and is not an additional application-level
hash).

The key type is determined by the key material in the DID document, and
verification MUST be performed with the algorithm matching that key type.
Verification of a signature produced under one algorithm against a key of
the other type MUST fail; implementations MUST NOT fall back to trying a
key under a different algorithm than its type denotes.

## Results and account semantics

### Numerics

On success the server MUST:

* Bind the connection's account identity to the verified DID.
* Send `RPL_LOGGEDIN` (`900`) with the DID as the account parameter:

      :irc.example.org 900 alice alice!alice@example-cloak did:plc:ewvi7nxzyoun6zhxrhs64oiz :You are now logged in as did:plc:ewvi7nxzyoun6zhxrhs64oiz

* Send `RPL_SASLSUCCESS` (`903`).

On failure the server MUST send `ERR_SASLFAIL` (`904`) and terminate the
SASL exchange cleanly. Failure of this mechanism MUST NOT terminate the
connection (except as described under
[Abuse limits](#replay-expiry-and-abuse-limits)) and MUST NOT prevent the
client from completing registration unauthenticated: servers MUST continue
to accept clients that never request SASL or that do not support this
mechanism, with unchanged IRC behavior.

### The DID is the account

The account name established by this mechanism is the DID string itself.
This account name is used consistently wherever the IRCv3 ecosystem
surfaces accounts:

* **`account-notify`** — on successful authentication the server MUST
  broadcast `ACCOUNT did:…` to clients sharing a channel with the user (per
  that capability).
* **`extended-join`** — the account field of extended `JOIN` messages
  carries the DID.
* **`account-tag`** — the `account` message tag carries the DID.
* **`WHOIS`** — `RPL_WHOISACCOUNT` (`330`) carries the DID. Servers MAY
  additionally expose a resolved AT Protocol handle (from the DID
  document's `alsoKnownAs`) via a nonstandard numeric or `WHOIS` text, but
  the handle is display metadata, not the account.

The nickname is a display alias. Servers MAY bind nicknames to DIDs for
ownership enforcement, but such policy is outside the scope of this
specification.

### Reauthentication (`sasl` 3.2)

Servers implementing `sasl` 3.2 MAY accept `AUTHENTICATE
ATPROTO-CHALLENGE` after registration. A reauthentication exchange follows
this specification unchanged: a fresh challenge MUST be issued and MUST be
single-use. On success the connection's account is replaced with the newly
verified DID and the change is broadcast via `account-notify` as usual. On
failure the connection's previous account status MUST be unchanged.

## Replay, expiry, and abuse limits

* **Single-use challenges.** A challenge MUST be invalidated the first
  time a response is processed against it, regardless of outcome. A second
  response on the same connection without a fresh `AUTHENTICATE
  ATPROTO-CHALLENGE` MUST fail.
* **Expiry.** Responses to challenges older than the configured window
  (RECOMMENDED 60 seconds) MUST be rejected.
* **Connection binding.** Challenges are looked up by connection; a
  challenge issued to one connection MUST NOT verify a response on
  another.
* **Failure limit.** Servers SHOULD limit the number of failed SASL
  attempts per connection. A limit of **3** failures is RECOMMENDED, after
  which the server SHOULD send an `ERROR` and close the connection.
  Subsequent `AUTHENTICATE` commands past the limit MUST be ignored or
  cause disconnection.

## Examples

A successful authentication. Payloads are the actual base64url encodings of
the JSON shown in earlier sections (each payload here is under 400 bytes
and therefore fits in a single `AUTHENTICATE` parameter):

    C: CAP LS 302
    C: NICK alice
    C: USER alice 0 * :Alice
    S: :irc.example.org CAP * LS :sasl=ATPROTO-CHALLENGE multi-prefix server-time
    C: CAP REQ :sasl
    S: :irc.example.org CAP alice ACK :sasl
    C: AUTHENTICATE ATPROTO-CHALLENGE
    S: AUTHENTICATE eyJzZXNzaW9uX2lkIjoiYzBhOGYzYjItNGQxMS00ZTBlLTljMmYtN2Q1MmExYjZlODAzIiwibm9uY2UiOiJCd2dKQ2dzTURRNFBFQkVTRXhRVkZoY1lHUm9iSEIwZUh5QWhJaU1rSlNZIiwidGltZXN0YW1wIjoxNzE4MTAwMDAwfQ
    C: AUTHENTICATE eyJkaWQiOiJkaWQ6cGxjOmV3dmk3bnh6eW91bjZ6aHhyaHM2NG9peiIsInNpZ25hdHVyZSI6IkFBRUNBd1FGQmdjSUNRb0xEQTBPRHhBUkVoTVVGUllYR0JrYUd4d2RIaDhnSVNJakpDVW1KeWdwS2lzc0xTNHZNREV5TXpRMU5qYzRPVG83UEQwLVB3IiwibWV0aG9kIjoiY3J5cHRvIn0
    S: :irc.example.org 900 alice alice!alice@example-cloak did:plc:ewvi7nxzyoun6zhxrhs64oiz :You are now logged in as did:plc:ewvi7nxzyoun6zhxrhs64oiz
    S: :irc.example.org 903 alice :SASL authentication successful
    C: CAP END

A failed authentication (bad signature), followed by the client falling
back to guest registration:

    C: AUTHENTICATE ATPROTO-CHALLENGE
    S: AUTHENTICATE eyJzZXNzaW9uX2lkIjoi…
    C: AUTHENTICATE eyJkaWQiOiJkaWQ6cGxjOi…
    S: :irc.example.org 904 alice :SASL authentication failed
    C: CAP END

Aborting an exchange:

    C: AUTHENTICATE ATPROTO-CHALLENGE
    S: AUTHENTICATE eyJzZXNzaW9uX2lkIjoi…
    C: AUTHENTICATE *
    S: :irc.example.org 906 alice :SASL authentication aborted

## Security considerations

* **TLS.** This mechanism does not itself provide confidentiality or
  integrity for the IRC connection. Connections using this mechanism
  SHOULD be protected by TLS (or an equivalent secure transport).
  Although the signature scheme never exposes a reusable secret —
  observing an exchange does not let an attacker authenticate later — an
  active attacker on a cleartext connection can hijack the session after
  authentication completes.
* **Challenge relay.** The challenge as specified binds to a nonce,
  timestamp, and per-connection session identifier, but does not include
  the server's identity. A malicious server could, in principle, relay a
  challenge it received from another server to a connecting client and
  forward the signature, authenticating to the victim server as that
  client — but only within the expiry window and only if the client is
  simultaneously willing to authenticate to the attacker. TLS with server
  certificate verification prevents the attacker from impersonating the
  victim server to the client. Including the server's canonical name in
  the challenge, and requiring clients to verify it against the server
  they intended to reach, would close this channel cryptographically and
  is an open consideration for a future revision of this mechanism (see
  Editor's notes).
* **DID resolution trust.** Verification is only as trustworthy as DID
  document resolution. For `did:plc`, the server trusts the PLC directory
  it queries; the PLC operation log is publicly auditable, and operators
  with stronger requirements can verify the audit log or run a directory
  mirror. For `did:web`, trust reduces entirely to HTTPS/WebPKI for the
  DID's domain: a compromised web host or CA can substitute keys. Servers
  MUST validate TLS certificates when resolving DID documents and SHOULD
  apply SSRF protections to `did:web` fetches (see step 3 of
  verification).
* **Key rotation and revocation.** A DID's keys can rotate at any time.
  This mechanism verifies the key at authentication time only; an
  established session remains valid after the signing key is removed from
  the DID document. Sessions SHOULD be revalidated or invalidated when a
  server learns that a DID document's authentication keys have changed.
  How servers learn this (polling, PLC log subscription, push) is
  unspecified and remains an open consideration.
* **Resolution availability.** Authentication fails closed if DID
  resolution is unavailable. Servers MAY cache DID documents briefly to
  smooth over directory outages, balancing availability against rotation
  latency; caches MUST respect the single-use and expiry rules for
  challenges regardless.
* **Guest fallback.** Servers MUST NOT require this mechanism for
  connection. Clients without AT Protocol identities, and standard IRC
  clients with no SASL support at all, must retain full unauthenticated
  access under whatever guest policy the server applies. Identity
  upgrades; it does not gate.
* **Nonce and randomness.** Challenge nonces MUST come from a
  cryptographically secure RNG. Predictable nonces enable pre-computation
  of responses and weaken replay protections.
* **Resource exhaustion.** Outstanding challenges consume server memory
  keyed by connection. Servers SHOULD bound outstanding challenges (one
  per connection suffices — issuing a new challenge SHOULD replace any
  outstanding one) and enforce the SASL failure limit.

## Implementation considerations

* **Sign the bytes you received.** The single most common implementation
  error is re-serializing the challenge JSON before signing or verifying.
  JSON serialization is not canonical: key order, whitespace, and number
  formatting can differ. Clients sign the decoded payload bytes exactly;
  servers verify against the byte sequence they originally encoded, which
  they must retain alongside the parsed challenge.
* **Trying multiple keys.** DID documents may list several acceptable
  keys. Servers should attempt each acceptable key and succeed on the
  first match; a non-matching key is not an error until all keys are
  exhausted.
* **Clock skew.** The RECOMMENDED 60-second window is generous for the
  intended flow (sign immediately upon receipt). Implementations should
  not tighten it below a few seconds of expected client-side signing
  latency, including remote-signer round trips.
* **JSON strictness.** Servers should parse the response leniently with
  respect to unknown fields (required for method extensibility) but
  strictly with respect to required fields and types.
* **Mechanism advertisement.** Listing `ATPROTO-CHALLENGE` in the `sasl`
  capability value (3.2) lets clients avoid a doomed round trip when the
  mechanism is absent.

## Appendix A: deployment-specific verification methods (informative)

*This appendix is non-normative.* The `method` field exists so that
deployments can verify DID control by means other than a direct key
signature, without changing the framing of the exchange. Two such methods
are in production use; they are documented here as existence proofs of the
extension point, not as part of this specification. A future revision may
specify extension methods (or split them into separate SASL mechanism
names) if there is interest.

Both methods rely on the AT Protocol's delegation of authentication to the
user's PDS (Personal Data Server): rather than holding a DID-document
signing key, ordinary user clients hold a PDS session, and the IRC server
asks the PDS to vouch for it. Because nothing signs the challenge in these
flows, the response carries an extra `challenge_nonce` field echoing the
challenge's `nonce`, which the server checks against the challenge it
issued — without this, a stolen PDS token could be replayed against any
server. The response also carries a `pds_url` field, which the server
verifies against the PDS service endpoint declared in the resolved DID
document before contacting it.

### `pds-session` — app-password session token

The client authenticates to its PDS with an app password and places the
resulting access JWT in the `signature` field with
`"method": "pds-session"`. The server:

1. Checks `challenge_nonce` against the issued challenge.
2. Resolves the DID document and confirms the claimed `pds_url` matches
   the document's PDS service endpoint.
3. Calls `com.atproto.server.getSession` on the PDS with the token as a
   Bearer credential.
4. Confirms the DID returned by the PDS equals the claimed DID.

### `pds-oauth` — DPoP-bound OAuth token

For OAuth sessions, the access token is DPoP-bound and cannot be used as a
plain Bearer token. The client sends the access token in `signature`, sets
`"method": "pds-oauth"`, and includes a `dpop_proof` field: a DPoP proof
JWT it pre-signed for `GET <pds_url>/xrpc/com.atproto.server.getSession`,
bound to the access token. The server forwards both
(`Authorization: DPoP <token>` plus the `DPoP` header) to the PDS's
`getSession` endpoint and confirms the returned DID.

PDS implementations rotate DPoP server nonces. When the PDS rejects the
proof with `use_dpop_nonce`, the server extracts the fresh nonce from the
`DPoP-Nonce` response header, communicates it to the client out of band
(the production deployment uses a server `NOTICE` of the form
`DPOP_NONCE <nonce>`), and re-issues a fresh challenge so the client can
retry with a proof signed over the new nonce. Retries are capped (3 per
SASL attempt in the production deployment) to prevent loops.

One deployment additionally implements a `web-token` method, in which a
co-deployed OAuth broker performs the full PDS OAuth flow in a browser,
pushes a short-lived (5-minute), single-use token to the IRC server out of
band, and the web client presents that token in the `signature` field.
This is a pure deployment convenience — verification happened before the
SASL exchange — and is even further from candidate standardization than
the PDS methods.

## Editor's notes: divergences in the reference implementation

The reference implementation (see Implementations) diverges from this
draft and from its own in-repo documentation in the following ways. Where
this draft and the implementation differ, the draft text above states the
intended behavior; this section records reality.

1. **Partial payload chunking.** The reference server reassembles a chunked
   client response and honors a client-sent `AUTHENTICATE +`. The TypeScript
   and Rust clients chunk their responses; the Swift client sends a single
   oversized parameter. Server challenges are not chunked.
2. **No server-identity binding in the challenge.** The implemented
   challenge contains only `session_id`, `nonce`, and `timestamp`. The
   relay consideration in Security considerations is mitigated there by
   TLS, expiry, and connection binding only.
3. **Abort numeric.** The reference server replies to `AUTHENTICATE *`
   with `ERR_SASLFAIL` (`904`) rather than `ERR_SASLABORTED` (`906`), and
   replies to unsupported mechanism names with `904` without
   `RPL_SASLMECHS` (`908`).
4. **Capability value.** The reference server advertises bare `sasl` with
   no mechanism list in CAP 302 negotiation.
5. **Curve requirement levels.** The project's protocol notes describe
   secp256k1 as required and ed25519 as recommended (inherited from the
   original project brief, which made ed25519 a SHOULD). The
   implementation verifies both unconditionally, and this draft requires
   both (see Signature algorithms).
6. **PLC resolution endpoint.** Resolution fetches the resolved DID
   document from `https://plc.directory/<did>` directly; it does not fetch
   or verify the PLC audit log (`/log/audit`). Audit-log verification is
   mentioned in Security considerations as an option for higher-assurance
   deployments, not as implemented behavior.
7. **An extra response member.** On the `crypto` method the reference
   server also reads a `delegation` member: a certificate naming the DID
   that the authenticating agent acts for. It lets a server admit an agent
   by its owner. This draft does not define the member; servers that do not
   implement it ignore it.
8. **Response fields undocumented in protocol notes.** The project's
   protocol notes omit the `challenge_nonce` and `dpop_proof` response
   fields (both required by the PDS methods of Appendix A) and the
   `web-token` method entirely; the implementation defines all three.
9. **Key rotation.** Sessions are not revalidated on DID-document key
   changes; the SHOULD in Security considerations is aspirational and
   noted there as an open consideration.

## Implementations

*This section is non-normative.*

* **freeq** — server implementation in Rust, with client implementations
  of the `crypto`, `pds-session`, and `pds-oauth` methods in Rust (SDK and
  TUI), TypeScript (web), and Swift (iOS).
