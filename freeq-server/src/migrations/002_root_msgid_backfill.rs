//! Migration 2: a message's identity is its original msgid for life.
//!
//! Up: stamp `root_msgid` on rows that predate the column, then re-file
//! reactions and pins under the root they annotate. Before `root_msgid`
//! existed, an operation could name either end of an edit chain, so the
//! same logical message could collect reactions and pins under two
//! different ids; re-filing them under the root is what makes those
//! tallies agree afterwards.
//!
//! Down: none — IRREVERSIBLE. Once roots are stamped, rows the backfill
//! touched are indistinguishable from rows stamped at insert time, and the
//! reaction/pin re-file collapses duplicates. Migrating below version 2
//! fails loudly, by design.

use rusqlite::{Connection, Result as SqlResult, Transaction, params};
use rusqlite_migration::{HookResult, M};

pub(super) fn migration() -> M<'static> {
    M::up_with_hook("", |tx: &Transaction| -> HookResult {
        backfill_root_msgids(tx)?;
        Ok(())
    })
}

/// Idempotent (`WHERE root_msgid IS NULL`, and the re-file is a no-op once
/// every id is already a root), so re-running is safe — pre-ladder
/// deployments ran this on every boot. A fresh database is born with the
/// column and stamps every row at insert, so the guard matches zero rows
/// and none of this executes.
///
/// An id with no message row — an unpersisted guest-DM message — is its own
/// root and is left untouched everywhere.
pub(crate) fn backfill_root_msgids(conn: &Connection) -> SqlResult<()> {
    // Originals: identity is the msgid itself.
    conn.execute(
        "UPDATE messages SET root_msgid = msgid
         WHERE root_msgid IS NULL AND msgid IS NOT NULL
           AND (replaces_msgid IS NULL OR replaces_msgid = '')",
        [],
    )?;

    // Edits: walk the back-pointers.
    let pending: Vec<(String, String)> = {
        let mut stmt = conn.prepare(
            "SELECT channel, msgid FROM messages
             WHERE root_msgid IS NULL AND msgid IS NOT NULL",
        )?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<SqlResult<Vec<_>>>()?
    };
    for (channel, msgid) in pending {
        let root = migration_root_of(conn, &channel, &msgid)?;
        conn.execute(
            "UPDATE messages SET root_msgid = ?1 WHERE channel = ?2 AND msgid = ?3",
            params![root, channel, msgid],
        )?;
    }

    backfill_reaction_roots(conn)?;
    backfill_pin_roots(conn)?;
    Ok(())
}

/// Walk `replaces_msgid` back-pointers to the oldest revision. Upgrade-only:
/// rows written since `root_msgid` exists are stamped at insert time, so
/// this runs solely over rows that predate the column. Bounded — a
/// malformed back-pointer cycle must not spin.
fn migration_root_of(conn: &Connection, channel: &str, msgid: &str) -> SqlResult<String> {
    let mut root = msgid.to_string();
    for _ in 0..64 {
        let mut stmt =
            conn.prepare("SELECT replaces_msgid FROM messages WHERE channel = ?1 AND msgid = ?2")?;
        let parent: Option<String> = stmt
            .query_map(params![channel, &root], |r| r.get::<_, Option<String>>(0))?
            .next()
            .transpose()?
            .flatten();
        match parent {
            Some(p) if !p.is_empty() && p != root => root = p,
            _ => break,
        }
    }
    Ok(root)
}

/// Re-file reactions under the root of the message they annotate.
/// `reactions` is `UNIQUE(target_msgid, reactor_nick, emoji)`, so one person
/// who reacted against two revisions of the same message has two rows that
/// would collide on rewrite — the earlier row wins and the later is dropped,
/// which is the same tally the two rows were always meant to represent.
fn backfill_reaction_roots(conn: &Connection) -> SqlResult<()> {
    let rewrites: Vec<(String, String)> = {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT r.target_msgid, m.root_msgid
             FROM reactions r JOIN messages m ON m.msgid = r.target_msgid
             WHERE m.root_msgid IS NOT NULL AND m.root_msgid <> r.target_msgid",
        )?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<SqlResult<Vec<_>>>()?
    };
    for (old_id, root) in rewrites {
        // Of a colliding pair, drop the later row. The `<=` / `<` split
        // means a tie drops the revision row, never both.
        conn.execute(
            "DELETE FROM reactions WHERE target_msgid = ?1 AND EXISTS (
                 SELECT 1 FROM reactions keep
                 WHERE keep.target_msgid = ?2
                   AND keep.reactor_nick = reactions.reactor_nick
                   AND keep.emoji = reactions.emoji
                   AND keep.timestamp <= reactions.timestamp
             )",
            params![old_id, root],
        )?;
        conn.execute(
            "DELETE FROM reactions WHERE target_msgid = ?2 AND EXISTS (
                 SELECT 1 FROM reactions keep
                 WHERE keep.target_msgid = ?1
                   AND keep.reactor_nick = reactions.reactor_nick
                   AND keep.emoji = reactions.emoji
                   AND keep.timestamp < reactions.timestamp
             )",
            params![old_id, root],
        )?;
        // OR IGNORE + sweep: a surviving collision must not abort startup.
        conn.execute(
            "UPDATE OR IGNORE reactions SET target_msgid = ?1 WHERE target_msgid = ?2",
            params![root, old_id],
        )?;
        conn.execute(
            "DELETE FROM reactions WHERE target_msgid = ?1",
            params![old_id],
        )?;
    }
    Ok(())
}

/// Re-file pins under the root of the message they pin. `pins` is
/// `UNIQUE(channel, msgid)`; a message pinned under two revisions keeps the
/// earliest `pinned_at` — the moment it was actually first pinned.
fn backfill_pin_roots(conn: &Connection) -> SqlResult<()> {
    let rewrites: Vec<(String, String, String)> = {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT p.channel, p.msgid, m.root_msgid
             FROM pins p JOIN messages m ON m.msgid = p.msgid
             WHERE m.root_msgid IS NOT NULL AND m.root_msgid <> p.msgid",
        )?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<SqlResult<Vec<_>>>()?
    };
    for (channel, old_id, root) in rewrites {
        conn.execute(
            "UPDATE pins SET pinned_at = (
                 SELECT MIN(pinned_at) FROM pins
                 WHERE channel = ?1 AND msgid IN (?2, ?3)
             )
             WHERE channel = ?1 AND msgid = ?3",
            params![channel, old_id, root],
        )?;
        conn.execute(
            "UPDATE OR IGNORE pins SET msgid = ?1 WHERE channel = ?2 AND msgid = ?3",
            params![root, channel, old_id],
        )?;
        conn.execute(
            "DELETE FROM pins WHERE channel = ?1 AND msgid = ?2",
            params![channel, old_id],
        )?;
    }
    Ok(())
}
