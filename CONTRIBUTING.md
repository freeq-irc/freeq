# Contributing to freeq

Thanks for your interest in contributing to freeq! This project treats IRC as
infrastructure — contributions should be clear, auditable, and avoid cleverness.

## Getting Started

```bash
git clone https://github.com/freeq-irc/freeq
cd freeq
cargo build
cargo test
```

The web client:
```bash
cd freeq-app
npm install
npm run dev
```

## Development Setup

- **Rust** (stable, 2024 edition)
- **Node.js** 20+ (for freeq-app)
- **SQLite** (bundled via rusqlite)

## How to Contribute

### Bug Reports

Open a GitHub issue with:
- What you expected
- What happened
- Steps to reproduce
- Server/client version and transport (TCP/WS/iroh)

### Feature Requests

Open a GitHub issue. Describe the use case, not just the solution. Features
that align with the project philosophy (decentralized identity, open protocol,
no lock-in) are most likely to be accepted.

### Pull Requests

1. Fork the repo and create a branch from `main`
2. Write clear commit messages
3. Add tests for new functionality
4. Run `cargo test` and `cargo clippy` before submitting
5. Update docs if you change behavior
6. Keep PRs focused — one feature or fix per PR

### Code Style

- Follow existing patterns in the codebase
- Use `tracing` for logging (not `println!` or `eprintln!`)
- Prefer explicit error handling over `.unwrap()` in library code
- Comment non-obvious logic, especially protocol behavior

### What We're Looking For

Check the [TODO list](CLAUDE.md) for current priorities. High-impact areas:

- S2S federation improvements
- Search (FTS5)
- Auto-reconnection
- Documentation improvements
- Test coverage

## Architecture

```
freeq-server/    Rust IRC server (async tokio, SQLite, iroh)
freeq-sdk/       Rust client SDK (connect, auth, events, E2EE)
freeq-app/       React web client (Vite + Tailwind)
freeq-tui/       Terminal client (ratatui)
freeq-bots/      Example bots using the SDK
freeq-auth-broker/ OAuth broker for AT Protocol
freeq-site/      Marketing site (freeq.at)
```

## Database migrations

All durable database changes — schema and data alike — go through the
migration ladder in `freeq-server/src/migrations/`, tracked in SQLite's
`PRAGMA user_version` (the integer version slot SQLite reserves for the
application) via `rusqlite_migration`.

One migration per numbered file: `001_schema_baseline.rs`,
`002_root_msgid_backfill.rs`, … Each exposes `migration() -> M` describing
itself completely — the up step (plain SQL via a sibling `.sql` file, or a
Rust hook when the migration needs code) and the down step where one
meaningfully exists. A data migration with no inverse defines no down and
documents itself as irreversible; migrating below it fails loudly. To add
migration N: create `00N_name.rs`, declare it in `migrations/mod.rs`, and
append one line to the ladder list there.

Migrations run in list order at server boot, and each commits atomically
with its version stamp — exactly once per database, no idempotency
required. The ladder is **append-only**: never insert, reorder, renumber,
or edit a shipped migration — databases in the wild are stamped with the
versions they've passed.

`Db::init()` itself keeps only per-connection pragmas and two deliberate
exceptions documented at their call sites (a legacy shape-guarded
signing-keys migration that manages its own transaction, and the FTS
index, whose existence depends on the at-rest encryption key).

## License

By contributing, you agree that your contributions will be licensed under
the [MIT License](LICENSE).
