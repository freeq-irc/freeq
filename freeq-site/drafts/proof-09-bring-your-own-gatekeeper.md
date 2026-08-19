# Bring your own gatekeeper

Every interesting room ends up asking a question about the outside
world. Are you an employee. Do you have a ticket. Did you contribute to this
repository. The usual way to answer is to teach the server about Okta, or
GitHub, or the ticketing vendor, and then to teach it about the next one, until
the relay is a directory of integrations that its operator controls.

freeq answers a different way. A **verifier** learns the external fact, and
hands back something the room can act on without ever learning the system the
fact came from.

Earlier proofs established who a participant is — a DID that signs in, and signs
what it says, whether it is a person or an agent. This one is about what a room
is allowed to conclude from that.

## Three things that are not the same thing

The failure mode of every access-control design is collapsing these into one:

```
external fact          "chad can push to freeq-irc/freeq"
  → credential         a signed statement that this DID holds that fact
  → policy             what this room decides follows from holding it
  → capability         what you may do here, for how long
```

A credential *states*. A policy *decides*. A capability *authorises*. Keeping
them separate is what makes revocation, caching and audit explainable later —
and it is the difference between a system you can reason about and a pile of
booleans.

## A room that already does this

`#freeq-dev` — the channel where freeq itself is argued about — grants ops to
people who can prove they contribute to freeq. Ask the server what its rules
are. No authentication required; the rules of a room are public:

```bash
curl -s https://irc.freeq.at/api/v1/policy/%23freeq-dev | python3 -m json.tool
```

```json
"requirements": { "type": "ACCEPT", "hash": "ee8804db43de3efc5aea2559aee94bf2fee80923f176c3beeb034c545de5e4a4" },
"role_requirements": {
    "op": {
        "type": "PRESENT",
        "credential_type": "github_repo",
        "issuer": "did:web:irc.freeq.at:verify"
    }
},
"validity_model": "join_time"
```

Anyone may walk in. Holding ops requires a `github_repo` credential from a named
issuer. The record also carries a `credential_endpoints` entry for that
credential type — the issuer again, a label for the button, and the address
where a client sends you to get one. That address is a template: the client
completes it with the DID the credential should be issued to, which is why
fetching it bare answers `400`.

## The issuer is a DID, not a hostname you trust

`did:web:irc.freeq.at:verify` resolves to a document, and the document publishes
the key that signs credentials:

```bash
curl -s https://irc.freeq.at/verify/did.json | python3 -m json.tool
```

```json
{
  "id": "did:web:irc.freeq.at:verify",
  "assertionMethod": ["did:web:irc.freeq.at:verify#key-1"],
  "verificationMethod": [{
    "controller": "did:web:irc.freeq.at:verify",
    "id": "did:web:irc.freeq.at:verify#key-1",
    "publicKeyMultibase": "z6Mkm2soeBDDSJTH8JpBYBVgfUeYEKYy7PgUsgpsL7TjUJcY",
    "type": "Multikey"
  }]
}
```

That is the part that makes this an extension point rather than a plugin slot. A
verifier is a DID with a published key and a URL. It happens to run on the same
host here; nothing in the policy says it must. Point a room at an issuer you
control and the room does not change — it evaluates the same requirement against
a different key.

Credentials already issued to an identity are readable the same way:

```bash
curl -s https://irc.freeq.at/api/v1/credentials/did:plc:4qsyxmnsblo4luuycm3572bq
```

```json
[{"credential_type": "github_repo",
  "issuer": "did:web:irc.freeq.at:verify",
  "metadata_json": "{\"github_username\":\"chad\",\"repo\":\"chad/freeq\"}",
  "issued_at": "2026-02-25 21:24:30"}]
```

## What the room never learns

Getting that credential is an OAuth round trip with GitHub:

```
GET /verify/github/start?subject_did=did:plc:4qsyxmnsblo4luuycm3572bq&repo=chad/freeq
307 → https://github.com/login/oauth/authorize
        ?client_id=<the verifier's public app id>
        &scope=repo
        &state=19e0a8470f5ac137f57ec9d9610b0fed
```

The token GitHub issues is used inside that request and never stored. What
reaches the room is one signed statement about one DID. The channel does not hold a GitHub
token, cannot enumerate your repositories, and does not learn your username
unless the credential says so. Swap GitHub for an SSO provider and the room is
unchanged, because the room was never the thing that integrated.

## The door actually holds

Run a server locally and watch a requirement refuse someone. An op writes the
rules:

```
→ POLICY #gate SET Be excellent to each other. Ops must prove they contribute to the repo.
← :irc.freeq.at NOTICE chadfowler :Policy set for #gate (version 1, rules_hash=ec8b73ecafb4, policy_id=8d7abfafc7a6)
→ POLICY #gate REQUIRE github_repo issuer=did:web:irc.freeq.at:verify url=https://irc.freeq.at/verify/github/start?repo=chad/freeq
← :irc.freeq.at NOTICE chadfowler :Credential endpoint 'github_repo' added to #gate (issuer=did:web:irc.freeq.at:verify, version 2)
```

Someone without the credential tries the door:

```
→ JOIN #gate
← :irc.freeq.at 477 visitor #gate :This channel requires policy acceptance — use POLICY <channel> ACCEPT
→ POLICY #gate INFO
← :irc.freeq.at NOTICE visitor :  Requirement: ALL(ACCEPT(ec8b73ecafb4...), PRESENT(github_repo, issuer=did:web:irc.freeq.at:verify))
→ POLICY #gate ACCEPT
← :irc.freeq.at NOTICE visitor :Policy acceptance failed: Missing credential: github_repo from did:web:irc.freeq.at:verify
→ JOIN #gate
← :irc.freeq.at 477 visitor #gate :This channel requires policy acceptance — use POLICY <channel> ACCEPT
```

Agreeing to the terms is not enough, and the refusal names exactly what is
missing and who would have to say it. The rules themselves are readable by the
person being refused:

```
→ POLICY #gate RULES
← :irc.freeq.at NOTICE visitor :Rules for #gate (rules_hash=ec8b73ecafb46d34e852a2eb9b9784f6e4da05b3e8638f710cc1bcd03adc7430):
← :irc.freeq.at NOTICE visitor :Be excellent to each other. Ops must prove they contribute to the repo.
```

## Changing the rules leaves a trail

Each edit writes a new version that names the one before it:

```bash
curl -s https://irc.freeq.at/api/v1/policy/%23freeq-dev/history | python3 -m json.tool
```

```json
{"version": 2,
 "policy_id": "037d84725180b8485646c625e16731118566eca433b805e204ae1d28b05f91c8",
 "previous_policy_hash": "b5098051c425e018c8adb05a5cea05e5b646548942b14b878b101ef79e5a1afd"}
```

"Who changed the entry requirements, and to what" is a question with an answer,
which is not the normal state of affairs for chat.

## Try it

**See it in 30 seconds.** The two `curl` commands above, against the live
server. A room's rules and an issuer's key are both public documents.

**Run it in 5 minutes.** Gate a channel of your own:

```bash
cargo run -p freeq-server -- --listen-addr 127.0.0.1:6889 --web-addr 127.0.0.1:6890 \
  --db-path /tmp/freeq/s.db --data-dir /tmp/freeq --server-name irc.freeq.at
```

```
POLICY #gate SET House rules: be excellent to each other.
POLICY #gate REQUIRE github_repo issuer=did:web:irc.freeq.at:verify url=https://irc.freeq.at/verify/github/start?repo=chad/freeq
POLICY #gate INFO
```

**Extend it in 30 minutes.** Write a verifier for a fact of your own. It needs
three things: a `did:web` document publishing an ed25519 key, an endpoint that
establishes the fact however you like, and a signed credential handed back for a
subject DID. The shipped GitHub one is
[350 lines](https://github.com/freeq-irc/freeq/blob/main/freeq-server/src/verifiers/github.rs)
and most of it is OAuth bookkeeping. Point a room at yours with
`POLICY #room REQUIRE conference_2026 issuer=<your did:web> url=<your start
endpoint>`. The room learns nothing about your badge system, and you did not
modify the server to add it.

## What this does not claim

A credential is not an authorisation. What the room grants is scoped to the room
and decided by its policy; the statement from the issuer is evidence, not a key.
Confusing the two is how "signed in with GitHub" becomes "admin everywhere".

The requirement matches on credential type and issuer. It does not compare the
claim inside the credential against the room's expectation — a `github_repo`
credential from the named issuer satisfies the rule, whatever repository is
written in it. If you run an issuer that certifies many facts of one type, that
is one bucket to a room today.

`validity_model: join_time` means the question is asked when you enter. Losing
the underlying fact afterwards does not eject you from the room. Continuous
models exist in the engine; what this proof demonstrates is the join-time one.

The verifier is a trusted third party by construction. It sees your GitHub
session during the exchange, and a room trusting `did:web:irc.freeq.at:verify`
is trusting whoever operates that key. That is the honest shape of every
attestation system; the improvement here is that the trust is *named* in the
policy rather than implied by the software.

## What is rough

Credentials are ed25519-signed by a key you can fetch, so anyone can check one.
The membership receipt a server writes after a successful check is HMAC-signed
with a key only that server holds — verifiable by the issuing server, opaque to
everybody else. Room admission is therefore independently auditable one step
back (the credential) and locally attested at the last step (the receipt).

The authority set for a policy currently lists a single signer — the server
itself. Multi-signer authority is expressed in the format and the threshold
field is there; one server signing its own rooms' policies is what runs today.

A credential is stamped with a thirty-day expiry when it is issued, and the
admission check does not read that field — it looks for a credential of the
right type and issuer that has not been revoked. Revocation is the lever that
works today; the clock in the credential is a claim the issuer makes and nobody
currently enforces.

Rules text lives on the server where it was set. Peers receive the hash, so a
federated reader can tell you the rules changed and prove which rules were
accepted, while the sentence itself is fetched from home.

## Come in

`#freeq-dev` on `irc.freeq.at` — the room described above, gated by the policy
above. Source at [github.com/freeq-irc/freeq](https://github.com/freeq-irc/freeq).

Next: offboard someone from a room and rotate the keys, without changing the
server.
