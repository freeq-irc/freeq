//! The numbered migration ladder — the single authority for what a freeq
//! database looks like.
//!
//! One migration per numbered file in this directory. Each file exposes
//! `migration() -> M`, describing itself completely: the up step, and the
//! down step where one meaningfully exists (a data migration with no
//! inverse defines no down, and any attempt to migrate below it fails
//! loudly instead of guessing — state that in the file's doc comment).
//!
//! Tracked in SQLite's `PRAGMA user_version` (its application-owned version
//! slot) via `rusqlite_migration`. Migrations are numbered by list position
//! and **append-only**: never insert, reorder, renumber, or edit a shipped
//! migration — databases in the wild are stamped with the versions they've
//! passed. Each migration commits together with its version stamp in one
//! transaction, so a crash leaves the database exactly at the previous
//! rung, and migrations need not be idempotent. A database stamped newer
//! than this list is refused instead of guessed at.
//!
//! Adding migration N: create `00N_what_it_does.rs` (plus a sibling `.sql`
//! if the up step is plain SQL), declare it below, append one line to the
//! ladder. Rust module names cannot start with a digit, so the `#[path]`
//! attribute carries the file name and the identifier takes an `m` prefix.
//!
//! Two things deliberately live outside the ladder, in `Db::init()`:
//! `migrate_signing_keys_to_kid_history` (it manages its own transaction,
//! which the ladder's per-migration transaction cannot nest) and the FTS
//! index (whether it exists depends on the at-rest encryption key — state,
//! not schema).

use rusqlite_migration::Migrations;

#[path = "001_schema_baseline.rs"]
mod m001_schema_baseline;
#[path = "002_root_msgid_backfill.rs"]
mod m002_root_msgid_backfill;
#[path = "003_msgid_unique.rs"]
mod m003_msgid_unique;
#[path = "004_events_log.rs"]
mod m004_events_log;
#[path = "005_event_emoji.rs"]
mod m005_event_emoji;
#[path = "006_act_actions.rs"]
mod m006_act_actions;
#[path = "007_act_replaces.rs"]
mod m007_act_replaces;

// db.rs unit tests exercise the backfill directly against hand-built rows.
// Production reaches it only as a rung of the ladder below.
#[cfg(test)]
pub(crate) use m002_root_msgid_backfill::backfill_root_msgids;

/// The rungs, in order. List position is the schema version, so this vec is
/// the single source for both the ladder and its height.
fn rungs() -> Vec<rusqlite_migration::M<'static>> {
    vec![
        m001_schema_baseline::migration(),
        m002_root_msgid_backfill::migration(),
        m003_msgid_unique::migration(),
        m004_events_log::migration(),
        m005_event_emoji::migration(),
        m006_act_actions::migration(),
        m007_act_replaces::migration(),
    ]
}

/// The ladder's height, derived — so startup can announce a pending climb
/// before it begins without a hand-maintained number.
pub(crate) fn ladder_top() -> usize {
    rungs().len()
}

pub(crate) fn migration_ladder() -> Migrations<'static> {
    Migrations::new(rungs())
}

/// The schema version stamped on `conn` (0 = unstamped).
fn stamped_version(conn: &rusqlite::Connection) -> Result<usize, String> {
    use rusqlite_migration::SchemaVersion;
    match migration_ladder().current_version(conn) {
        Ok(SchemaVersion::NoneSet) => Ok(0),
        Ok(SchemaVersion::Inside(v) | SchemaVersion::Outside(v)) => Ok(v.get()),
        Err(e) => Err(e.to_string()),
    }
}

/// Run the ladder to `target` against the database file at `path` — the
/// operational entry point behind `--migrate-to`. Opens the file directly
/// rather than through `Db::open`, which always migrates to latest and so
/// can never go down. Returns (version before, version after).
///
/// A downgrade stops with an error at any rung that defines no down
/// (migration 2 is irreversible by design); the database is left at the
/// last rung reached.
pub fn migrate_to(path: &str, target: usize) -> Result<(usize, usize), String> {
    let mut conn = rusqlite::Connection::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let before = stamped_version(&conn)?;
    migration_ladder()
        .to_version(&mut conn, target)
        .map_err(|e| e.to_string())?;
    let after = stamped_version(&conn)?;
    Ok((before, after))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use rusqlite_migration::SchemaVersion;

    fn version(conn: &Connection) -> usize {
        match migration_ladder().current_version(conn).unwrap() {
            SchemaVersion::NoneSet => 0,
            SchemaVersion::Inside(v) | SchemaVersion::Outside(v) => v.get(),
        }
    }

    fn tables(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table'
                 AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .unwrap();
        let rows = stmt.query_map([], |r| r.get(0)).unwrap();
        rows.collect::<Result<Vec<String>, _>>().unwrap()
    }

    /// The ladder is climbed one rung at a time, and each rung is what it
    /// claims to be: an empty database has no schema, migration 1 puts the
    /// whole schema there, migration 2 adds no tables (it moves data).
    #[test]
    fn the_ladder_climbs_one_rung_at_a_time() {
        let mut conn = Connection::open_in_memory().unwrap();
        assert_eq!(version(&conn), 0, "a new database is unstamped");
        assert!(tables(&conn).is_empty(), "and has no schema at all");

        migration_ladder().to_version(&mut conn, 1).unwrap();
        assert_eq!(version(&conn), 1);
        let after_baseline = tables(&conn);
        for expected in ["channels", "messages", "identities", "reactions", "pins"] {
            assert!(
                after_baseline.iter().any(|t| t == expected),
                "migration 1 must create `{expected}`; got {after_baseline:?}"
            );
        }
        // The columns later migrations and queries depend on arrive here too,
        // via the ALTER convergence loop — not just the bare CREATEs.
        let cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('messages')")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for expected in [
            "msgid",
            "replaces_msgid",
            "root_msgid",
            "deleted_at",
            "sender_did",
        ] {
            assert!(
                cols.iter().any(|c| c == expected),
                "migration 1 must converge `messages.{expected}`; got {cols:?}"
            );
        }

        migration_ladder().to_version(&mut conn, 2).unwrap();
        assert_eq!(version(&conn), 2);
        assert_eq!(
            tables(&conn),
            after_baseline,
            "migration 2 moves data; it must not change the schema"
        );

        migration_ladder().to_version(&mut conn, 3).unwrap();
        assert_eq!(version(&conn), 3);
        assert_eq!(
            tables(&conn),
            after_baseline,
            "migration 3 adds an index; it must not change the tables"
        );

        migration_ladder().to_version(&mut conn, 4).unwrap();
        assert_eq!(version(&conn), 4);
        assert!(
            tables(&conn).iter().any(|t| t == "events"),
            "migration 4 adds the event log"
        );
    }

    /// Climbing straight to the top lands in the same place as stepping.
    #[test]
    fn to_latest_matches_stepping_rung_by_rung() {
        let mut stepped = Connection::open_in_memory().unwrap();
        migration_ladder().to_version(&mut stepped, 1).unwrap();
        migration_ladder().to_version(&mut stepped, 2).unwrap();
        migration_ladder().to_version(&mut stepped, 3).unwrap();
        migration_ladder().to_version(&mut stepped, 4).unwrap();
        migration_ladder().to_version(&mut stepped, 5).unwrap();
        migration_ladder().to_version(&mut stepped, 6).unwrap();
        migration_ladder().to_version(&mut stepped, 7).unwrap();

        let mut direct = Connection::open_in_memory().unwrap();
        migration_ladder().to_latest(&mut direct).unwrap();

        assert_eq!(version(&stepped), version(&direct));
        assert_eq!(tables(&stepped), tables(&direct));
        assert_eq!(
            version(&direct),
            ladder_top(),
            "the stamp must equal the rung count"
        );
    }

    /// The `--migrate-to` entry point: a real file, up to latest, down one
    /// rung, and a loud stop at the rung that defines no down.
    #[test]
    fn migrate_to_runs_the_ladder_on_a_file_and_stops_at_irreversible() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ladder.db");
        let path = path.to_str().unwrap();

        let (before, after) = super::migrate_to(path, 5).unwrap();
        assert_eq!((before, after), (0, 5), "fresh file climbs to the target");

        let (before, after) = super::migrate_to(path, 2).unwrap();
        assert_eq!((before, after), (5, 2), "the down migrations run");

        let err = super::migrate_to(path, 0).unwrap_err();
        assert!(
            !err.is_empty(),
            "descending past an irreversible rung must error, got success"
        );
        let conn = Connection::open(path).unwrap();
        assert_eq!(
            version(&conn),
            2,
            "the database stays at the last rung reached"
        );
    }

    /// Re-running the ladder against an already-current database is a no-op,
    /// which is what every server restart does.
    #[test]
    fn re_running_the_ladder_changes_nothing() {
        let mut conn = Connection::open_in_memory().unwrap();
        migration_ladder().to_latest(&mut conn).unwrap();
        let before = tables(&conn);
        migration_ladder().to_latest(&mut conn).unwrap();
        assert_eq!(version(&conn), ladder_top());
        assert_eq!(tables(&conn), before);
    }
}
