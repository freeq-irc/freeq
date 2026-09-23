//! Migration 16: instant rooms.
//!
//! A room is a channel minted for one collaboration and shared as a single
//! URL. It is ordinary channel state plus three things a channel never had:
//! a lifetime (`rooms`), link invites that admit whoever holds them
//! (`room_invites`), and a persistent roster (`room_members`) so a member
//! can reconnect without presenting the link again.
//!
//! `channels.is_room` is the flag `handle_join` branches on; it is a column
//! rather than a join against `rooms` because channel admission already
//! reads the channel row and must not need a second table to decide.
//!
//! Only the SHA-256 of an invite token is stored. The raw token travels in
//! the URL fragment, which never reaches the server, so a database leak
//! does not leak invites.
//!
//! Down: drop the three tables and the column. Rooms become plain `+iE`
//! channels that nobody without the founder can enter — which is the safe
//! failure, since the invites that admitted people are gone.

use rusqlite::Transaction;
use rusqlite_migration::{HookResult, M};

pub(super) fn migration() -> M<'static> {
    M::up_with_hook("", |tx: &Transaction| -> HookResult {
        match tx.execute(
            "ALTER TABLE channels ADD COLUMN is_room INTEGER NOT NULL DEFAULT 0",
            [],
        ) {
            Ok(_) => {}
            Err(e) if e.to_string().contains("duplicate column name") => {}
            Err(e) => return Err(e.into()),
        }
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS rooms (
                 channel       TEXT PRIMARY KEY,
                 founder_did   TEXT NOT NULL,
                 created_at    INTEGER NOT NULL,
                 last_activity INTEGER NOT NULL,
                 expires_at    INTEGER NOT NULL,
                 warned_at     INTEGER
             );
             CREATE TABLE IF NOT EXISTS room_invites (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 channel     TEXT NOT NULL,
                 token_hash  TEXT NOT NULL UNIQUE,
                 created_by  TEXT NOT NULL,
                 created_at  INTEGER NOT NULL,
                 expires_at  INTEGER NOT NULL,
                 max_uses    INTEGER,
                 uses        INTEGER NOT NULL DEFAULT 0,
                 revoked_at  INTEGER
             );
             CREATE INDEX IF NOT EXISTS room_invites_channel ON room_invites(channel);
             CREATE TABLE IF NOT EXISTS room_members (
                 channel     TEXT NOT NULL,
                 did         TEXT NOT NULL,
                 joined_at   INTEGER NOT NULL,
                 removed_at  INTEGER,
                 PRIMARY KEY (channel, did)
             );",
        )?;
        Ok(())
    })
    .down(
        "DROP TABLE IF EXISTS room_members;
         DROP TABLE IF EXISTS room_invites;
         DROP TABLE IF EXISTS rooms;
         ALTER TABLE channels DROP COLUMN is_room;",
    )
}

#[cfg(test)]
mod tests {
    use crate::migrations::migration_ladder;
    use rusqlite::Connection;

    fn has_table(conn: &Connection, name: &str) -> bool {
        conn.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1")
            .unwrap()
            .query_map([name], |_| Ok(()))
            .unwrap()
            .next()
            .is_some()
    }

    fn channel_columns(conn: &Connection) -> Vec<String> {
        conn.prepare("SELECT name FROM pragma_table_info('channels')")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn up_creates_the_tables_and_column_and_down_removes_them() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 16).unwrap();
        for t in ["rooms", "room_invites", "room_members"] {
            assert!(has_table(&conn, t), "missing table {t}");
        }
        assert!(channel_columns(&conn).iter().any(|c| c == "is_room"));

        migration_ladder().to_version(&mut conn, 15).unwrap();
        for t in ["rooms", "room_invites", "room_members"] {
            assert!(!has_table(&conn, t), "table {t} survived the down step");
        }
        assert!(!channel_columns(&conn).iter().any(|c| c == "is_room"));
    }

    /// A converged schema whose stamp was lost still climbs.
    #[test]
    fn the_rung_survives_a_database_that_already_has_the_schema() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 16).unwrap();
        conn.execute_batch("PRAGMA user_version = 15").unwrap();
        migration_ladder()
            .to_version(&mut conn, 16)
            .expect("a converged schema with a lost stamp climbs anyway");
    }

    /// Existing channel rows are not rooms: the column defaults to 0, so a
    /// database full of ordinary channels keeps its ordinary admission.
    #[test]
    fn existing_channels_are_not_rooms() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 15).unwrap();
        conn.execute("INSERT INTO channels (name) VALUES ('#old')", [])
            .unwrap();
        migration_ladder().to_version(&mut conn, 16).unwrap();
        let is_room: i64 = conn
            .query_row("SELECT is_room FROM channels WHERE name='#old'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(is_room, 0);
    }

    /// The token hash is unique across every room, so one token can never
    /// open two of them.
    #[test]
    fn invite_token_hashes_are_unique() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut conn, 16).unwrap();
        let insert =
            "INSERT INTO room_invites (channel, token_hash, created_by, created_at, expires_at)
                      VALUES (?1, 'h', 'did:key:z', 1, 2)";
        conn.execute(insert, ["#r-a-b-c"]).unwrap();
        assert!(conn.execute(insert, ["#r-d-e-f"]).is_err());
    }
}
