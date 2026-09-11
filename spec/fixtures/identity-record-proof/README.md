# Identity record proof fixture

Fetched 2026-09-10, unauthenticated, for the account `did:plc:lc2sd5msatepbr55mhtwgdvy` (`at://bandaco.bsky.social`), whose PDS is `https://fibercap.us-west.host.bsky.network`.

- `did.json`: the account's DID document from plc.directory. Its `#atproto` key signs the repository's commits.
- `record.json`: the `com.atproto.repo.getRecord` answer for `at.freeq.deviceKey/3mv2l5ebug2ql`, including the CID the PDS reports for it.
- `proof.car`: the `com.atproto.sync.getRecord` answer for the same record: a CAR holding the signed commit and the tree path from it to the record.

The record is in an older experimental shape: its `did` is the device's did:key, it has no `kid`, and its signature is over a DID alone. It does not fold as an identity record. It is here for the proof path only: the commit signature, the tree walk, and the record's CID.
