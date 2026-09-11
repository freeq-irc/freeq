# S2S Federation Authentication

## Architecture

Freeq's server-to-server (S2S) federation uses a layered security model:

```
Layer 1: Transport Identity (iroh QUIC)     — WHO is connecting
Layer 2: Mutual Hello/HelloAck              — BOTH sides agree to peer
Layer 3: Signed Message Envelopes           — messages can't be tampered
Layer 4: Capability-Based Trust             — WHAT each peer can do
Layer 5: Key Rotation & Revocation          — operational safety
Layer 6: DID-Based Server Identity          — the did:web document and key set
```

All layers are implemented and active.

---

## Layer 1: Transport Identity

S2S connections use **iroh QUIC**, which provides ed25519 keypair identity at the transport level. Each server has a persistent keypair (`iroh-key.secret` in the data directory). The QUIC handshake cryptographically proves the peer's identity — spoofing is impossible.

- `conn.remote_id()` returns the peer's public key (endpoint ID)
- This is the root of trust for everything else

## Layer 2: Mutual HelloAck

When two servers connect:

1. Both send `Hello` with their endpoint ID, server name, protocol version, and trust level
2. Each side verifies the peer is in their `--s2s-allowed-peers` allowlist
3. Each side responds with `HelloAck { accepted: bool, trust_level }`
4. If either side sends `accepted: false`, the link is torn down

This ensures **both servers** explicitly consent to peering. A rogue server cannot join the federation by connecting to one server — the other servers will reject it.

**Config:**
```bash
# Server A
--s2s-peers <B_endpoint_id> --s2s-allowed-peers <B_endpoint_id>

# Server B
--s2s-peers <A_endpoint_id> --s2s-allowed-peers <A_endpoint_id>
```

Starting with `--s2s-peers` but without `--s2s-allowed-peers` is a **startup error**.

## Layer 3: Signed Message Envelopes

Every S2S message (except Hello, HelloAck, and KeyRotation) is wrapped in a `Signed` envelope:

```json
{
  "type": "signed",
  "payload": "<base64url-encoded JSON of inner message>",
  "signature": "<base64url ed25519 signature over payload bytes>",
  "signer": "<endpoint ID of signing server>"
}
```

The receiving server:
1. Verifies `signer` matches the transport-authenticated peer ID
2. Verifies the ed25519 signature over the raw payload bytes
3. Deserializes the inner message only if signature is valid

Messages with invalid signatures are dropped with a warning log.

This provides **non-repudiation**: you can prove which server originated a message, even in multi-hop scenarios.

## Layer 4: Capability-Based Trust

Each peer is assigned a trust level that controls what operations they can perform:

| Trust Level | Messages | Presence | Modes/Kick/Ban | Channel Create |
|-------------|----------|----------|----------------|----------------|
| `full`      | ✓        | ✓        | ✓              | ✓              |
| `relay`     | ✓        | ✓        | ✗              | ✗              |
| `readonly`  | ✗        | ✗        | ✗              | ✗              |

**Config:**
```bash
# Give partner-server full trust, community-server relay-only
--s2s-peer-trust "abc123...:full,def456...:relay"
```

Peers not listed default to `full` (backward compatible). Trust is enforced server-side — a relay peer's MODE/KICK/BAN messages are silently dropped.

## Layer 5: Key Rotation & Revocation

### Key Rotation

Key rotation uses two complementary mechanisms for safety:

**In-band (continuity proof):**
1. Server sends `KeyRotation { old_id, new_id, timestamp, signature }` to all peers
2. Signature is by the **old** key over `rotate:{old_id}:{new_id}:{timestamp}`
3. Peers verify, record the pending rotation, accept new ID on reconnect
4. Rotation signatures must be within 5 minutes of current time (replay protection)

**Out-of-band (authoritative):**
1. Update the DID document (`/.well-known/did.json`) with the new public key
2. Peers re-resolve the DID on signature mismatch

**Acceptance rule:** Peers accept a new key if either:
- The DID document says so (authoritative — domain controls identity), **OR**
- The old key signed the rotation AND the DID document eventually matches (24h grace period)

This protects against both "peer missed the in-band message" and "domain was temporarily compromised but the in-band rotation was legitimate."

### Peer Revocation

Server operators can immediately revoke a peer's access:

```
OPER admin <password>
REVOKEPEER <endpoint_id>
```

This:
- Disconnects the peer immediately
- Removes them from authenticated peers
- Clears their dedup state
- Logs the revocation

To permanently block a peer, remove them from `--s2s-allowed-peers` and restart.

## Layer 6: DID-Based Server Identity

A server's identity is `did:web:<server-name>`. It comes from `--server-name`; there is no separate setting.

The server publishes a DID document at `/.well-known/did.json`. The document carries two things:

- the key the server signs task receipts and expiries with, under `#freeq`;
- a pointer to the server's full key set, `/api/v1/signing-keys/did:web:<server-name>`, which lists every key the server has had, with dates, including retired ones.

The peering handshake does not carry the DID. Who may peer is decided by the transport key and the allowlist, layers 1 and 2. A handshake that proves the DID, which would allow peering by domain rather than by transport id, is not supported at this time.

A `did:plc` for a server is not supported at this time.

---

## Startup Validation

The server enforces safe defaults at startup:

1. If `--s2s-peers` is set, `--s2s-allowed-peers` is **required** (prevents accidental open federation)
2. If iroh is enabled without an allowlist, a **warning** is logged
3. If an outbound peer isn't in the allowlist, a **warning** is logged (config mismatch)

## Rate Limiting

S2S events are rate-limited to 100 events/sec per peer. Excess events are dropped with a warning log.
