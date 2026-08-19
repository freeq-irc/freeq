//! Migration 3: one row per msgid, enforced by the schema.
//!
//! Everything that resolves a message id — edits, deletes, pins, reactions,
//! client-minted eventid adoption — assumes a msgid names at most one row.
//! Until now that held only by a pre-insert lookup, which nothing enforces
//! across concurrent connections or a peer re-delivering an event. A partial
//! unique index makes the invariant a property of the database itself.
//!
//! Up: collapse any duplicate msgids to their earliest row (they can only
//! exist as double deliveries of the same event), drop the collapsed rows
//! from the search index if one exists, then add the unique index. Rows with
//! NULL msgid (pre-msgid history) are untouched; SQLite indexes skip NULLs
//! and the partial predicate states that on purpose.
//!
//! Down: swap the unique index back for the plain lookup index. The
//! collapsed duplicates stay collapsed — they were double-filings of the
//! same event, and a pre-3 binary is equally correct without them — so the
//! schema inverse is the whole inverse.

use rusqlite::Transaction;
use rusqlite_migration::{HookResult, M};

pub(super) fn migration() -> M<'static> {
    M::up_with_hook("", |tx: &Transaction| -> HookResult {
        // The FTS table lives outside the ladder (state, not schema) and is
        // absent on encrypted databases — clean it only if it exists.
        let has_fts: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master
             WHERE type = 'table' AND name = 'messages_fts')",
            [],
            |r| r.get(0),
        )?;
        if has_fts {
            tx.execute(
                "DELETE FROM messages_fts WHERE rowid IN (
                    SELECT id FROM messages
                    WHERE msgid IS NOT NULL AND id NOT IN (
                        SELECT MIN(id) FROM messages
                        WHERE msgid IS NOT NULL GROUP BY msgid
                    )
                )",
                [],
            )?;
        }
        tx.execute(
            "DELETE FROM messages
             WHERE msgid IS NOT NULL AND id NOT IN (
                 SELECT MIN(id) FROM messages
                 WHERE msgid IS NOT NULL GROUP BY msgid
             )",
            [],
        )?;
        // The baseline ships `idx_messages_msgid` as a plain lookup index;
        // the unique index serves those same lookups, so replace rather than
        // carry both.
        tx.execute("DROP INDEX IF EXISTS idx_messages_msgid", [])?;
        tx.execute(
            "CREATE UNIQUE INDEX idx_messages_msgid ON messages(msgid)
             WHERE msgid IS NOT NULL",
            [],
        )?;
        Ok(())
    })
    .down(
        "DROP INDEX idx_messages_msgid;
         CREATE INDEX idx_messages_msgid ON messages(msgid);",
    )
}

#[cfg(test)]
mod tests {
    use crate::migrations::migration_ladder;
    use rusqlite::Connection;

    /// Duplicate msgids collapse to their earliest row and the index refuses
    /// any later claim. NULL-msgid rows (pre-msgid history) are left alone.
    #[test]
    fn dedups_and_enforces_msgid_uniqueness() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 2).unwrap();
        conn.execute_batch(
            "INSERT INTO messages (channel, sender, text, timestamp, msgid, root_msgid) VALUES
               ('#c', 'a', 'first', 1, 'DUP', 'DUP'),
               ('#c', 'a', 'second', 2, 'DUP', 'DUP'),
               ('#c', 'a', 'n1', 3, NULL, NULL),
               ('#c', 'a', 'n2', 4, NULL, NULL);",
        )
        .unwrap();

        migration_ladder().to_version(&mut conn, 3).unwrap();

        let (n, text): (i64, String) = conn
            .query_row(
                "SELECT COUNT(*), MIN(text) FROM messages WHERE msgid = 'DUP'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(n, 1, "duplicates collapse to one row");
        assert_eq!(text, "first", "the earliest row survives");

        let nulls: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE msgid IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(nulls, 2, "NULL msgids are not deduped");

        let dup_again = conn.execute(
            "INSERT INTO messages (channel, sender, text, timestamp, msgid) VALUES
               ('#c', 'a', 'again', 5, 'DUP')",
            [],
        );
        assert!(
            dup_again.is_err(),
            "the index refuses a spent msgid at the schema layer"
        );
    }

    /// The down migration restores the version-2 schema: plain lookup index,
    /// duplicates permitted again. The collapsed rows stay collapsed.
    #[test]
    fn migrating_down_restores_the_plain_index() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 3).unwrap();
        conn.execute(
            "INSERT INTO messages (channel, sender, text, timestamp, msgid, root_msgid)
             VALUES ('#c', 'a', 'kept', 1, 'KEEP', 'KEEP')",
            [],
        )
        .unwrap();

        migration_ladder().to_version(&mut conn, 2).unwrap();

        let index_sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_messages_msgid'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            !index_sql.contains("UNIQUE"),
            "the lookup index is back: {index_sql}"
        );

        // Data written under version 3 survives, and duplicates are tolerated
        // again, as any pre-3 binary expects.
        conn.execute(
            "INSERT INTO messages (channel, sender, text, timestamp, msgid, root_msgid)
             VALUES ('#c', 'a', 'dup ok again', 2, 'KEEP', 'KEEP')",
            [],
        )
        .unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE msgid = 'KEEP'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 2);
    }
}
