//! Migration 1: the schema baseline.
//!
//! Up: every CREATE (the sibling `.sql` file), then the ALTER convergence
//! loop for databases that predate some columns, then the indexes on
//! ALTER-added columns. A hook rather than plain SQL because of the ALTER
//! loop: SQLite has no `ADD COLUMN IF NOT EXISTS`, so convergence relies on
//! running each ALTER and suppressing its "duplicate column" error — per
//! statement, in code. A plain SQL migration would abort wholesale on the
//! first duplicate, i.e. on every database that had already run the old
//! boot-time replay.
//!
//! Down: drop everything the baseline creates — version 0 is an empty
//! database.

use rusqlite::{Connection, Result as SqlResult, Transaction};
use rusqlite_migration::{HookResult, M};

pub(super) fn migration() -> M<'static> {
    M::up_with_hook("", |tx: &Transaction| -> HookResult {
        up(tx)?;
        Ok(())
    })
    // Children of av_sessions drop first: foreign_keys is ON.
    .down(
        "DROP TABLE IF EXISTS av_artifacts;
         DROP TABLE IF EXISTS av_participants;
         DROP TABLE IF EXISTS av_sessions;
         DROP TABLE IF EXISTS reactions;
         DROP TABLE IF EXISTS media;
         DROP TABLE IF EXISTS pins;
         DROP TABLE IF EXISTS coordination_events;
         DROP TABLE IF EXISTS channel_budgets;
         DROP TABLE IF EXISTS agent_spend;
         DROP TABLE IF EXISTS spawned_agents;
         DROP TABLE IF EXISTS agent_manifests;
         DROP TABLE IF EXISTS pending_approvals;
         DROP TABLE IF EXISTS governance_log;
         DROP TABLE IF EXISTS agent_capability_grants;
         DROP TABLE IF EXISTS user_favorites;
         DROP TABLE IF EXISTS read_markers;
         DROP TABLE IF EXISTS user_channels;
         DROP TABLE IF EXISTS signing_keys;
         DROP TABLE IF EXISTS group_keys;
         DROP TABLE IF EXISTS prekey_bundles;
         DROP TABLE IF EXISTS identities;
         DROP TABLE IF EXISTS messages;
         DROP TABLE IF EXISTS invite_exceptions;
         DROP TABLE IF EXISTS bans;
         DROP TABLE IF EXISTS channels;",
    )
}

fn up(conn: &Connection) -> SqlResult<()> {
    conn.execute_batch(include_str!("001_schema_baseline.sql"))?;

    // Columns added to live deployments over time. Not folded into the
    // baseline CREATEs: a database old enough to be missing some of these
    // converges here, exactly as it did when init() replayed this list.
    let alters = [
        "ALTER TABLE channels ADD COLUMN no_ext_msg INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE channels ADD COLUMN moderated INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE channels ADD COLUMN founder_did TEXT",
        "ALTER TABLE channels ADD COLUMN did_ops_json TEXT NOT NULL DEFAULT '[]'",
        "ALTER TABLE channels ADD COLUMN encrypted_only INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE messages ADD COLUMN msgid TEXT",
        "ALTER TABLE messages ADD COLUMN replaces_msgid TEXT",
        "ALTER TABLE messages ADD COLUMN root_msgid TEXT",
        "ALTER TABLE messages ADD COLUMN deleted_at INTEGER",
        "ALTER TABLE messages ADD COLUMN sender_did TEXT",
        "ALTER TABLE identities ADD COLUMN last_auth_at INTEGER",
    ];
    for sql in &alters {
        // "duplicate column name" means it already exists — the success case.
        let _ = conn.execute(sql, []);
    }

    // These index ALTER-added columns, so they come after the loop. All
    // three back hot paths that would otherwise full-scan `messages` under
    // the global DB lock (DID→last-nick history; `root_of` on every
    // reaction/pin/delete; the delete sweep's revision-family select).
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_sender_did ON messages(sender_did)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_msgid ON messages(msgid)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_root_msgid ON messages(root_msgid)",
        [],
    )?;
    Ok(())
}
