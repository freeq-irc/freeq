//! Instant rooms (`docs/INSTANT-ROOMS.md`): the server-side pieces that are
//! not admission (`connection::channel::handle_join`) and not REST
//! (`web::api_rooms_*`).
//!
//! A room is a channel minted for one collaboration and shared as a single
//! URL `https://<host>/r/<name>#<token>`. Everything here is about the two
//! things that make a room different from a channel: it is entered with a
//! link, and it dies on its own.
//!
//! What lives here:
//! - the name and token generators, and the token hash the database keys on;
//! - the in-memory activity map and its flush, so message traffic does not
//!   cost a database write per line;
//! - deletion, which must reach every table a room touched, and the sweeper
//!   that calls it.

use crate::server::SharedState;
use std::collections::HashMap;
use std::sync::Arc;

/// Default lifetime of a link invite.
pub const INVITE_TTL_DEFAULT_SECS: u64 = 7 * 86_400;
/// Longest lifetime a caller may ask for.
pub const INVITE_TTL_MAX_SECS: u64 = 30 * 86_400;
/// Rooms one founder may mint in a rolling day.
pub const ROOMS_PER_FOUNDER_PER_DAY: usize = 20;
/// How long before expiry the members are warned.
pub const WARN_BEFORE_SECS: u64 = 86_400;
/// How often the sweeper runs.
const SWEEP_EVERY_SECS: u64 = 600;
/// The reason on the KICK every live member sees when a room is deleted.
pub const EXPIRED_KICK_REASON: &str = "Room expired";

/// Short, safe, unambiguous English words. Three of them name a room; the
/// name is human-sayable, not secret, so the list only has to be large
/// enough that names do not collide in practice (200^3 = 8M).
pub const WORDS: &[&str] = &[
    "amber", "apple", "arrow", "aspen", "atlas", "autumn", "badger", "bamboo", "basil", "beacon",
    "birch", "bison", "blue", "bold", "brass", "breeze", "bright", "brook", "calm", "camel",
    "candle", "canyon", "cedar", "chalk", "cherry", "cider", "clay", "clear", "cliff", "cloud",
    "clover", "cobalt", "comet", "copper", "coral", "cotton", "crane", "creek", "crisp", "crystal",
    "daisy", "dawn", "delta", "dune", "eagle", "early", "earth", "ember", "falcon", "fern",
    "field", "finch", "flint", "forest", "fox", "frost", "garden", "gentle", "ginger", "glade",
    "gold", "granite", "grape", "green", "grove", "harbor", "hawk", "hazel", "heron", "hill",
    "honey", "horizon", "indigo", "iris", "island", "ivory", "jade", "jasper", "juniper", "kelp",
    "kind", "lagoon", "lake", "lark", "laurel", "lemon", "light", "lilac", "lily", "linen",
    "lotus", "lucky", "lunar", "maple", "marble", "meadow", "mellow", "mesa", "mint", "misty",
    "moss", "noble", "north", "oak", "ocean", "olive", "onyx", "opal", "orange", "orchid", "otter",
    "owl", "panda", "peach", "pearl", "pebble", "pepper", "pine", "plum", "polar", "poppy",
    "prairie", "quail", "quiet", "quill", "rabbit", "rain", "raven", "reef", "ridge", "river",
    "robin", "rose", "ruby", "rustic", "saffron", "sage", "sandy", "sapphire", "scarlet",
    "sequoia", "shadow", "shore", "silver", "sky", "slate", "snow", "solar", "sparrow", "spring",
    "spruce", "star", "steady", "stone", "storm", "summer", "sunny", "swift", "tawny", "teal",
    "thistle", "tiger", "timber", "topaz", "tulip", "tundra", "umber", "valley", "velvet",
    "violet", "walnut", "warm", "willow", "winter", "wolf", "wren", "yellow", "zebra", "zephyr",
    "zinc",
];

/// A fresh `#r-<word>-<word>-<word>` that names no existing channel or room.
/// Checks the live channel map and the database, because a persisted
/// channel that nobody has joined since restart is not in memory.
pub fn generate_room_name(state: &SharedState) -> Option<String> {
    use rand::seq::SliceRandom;
    let mut rng = rand::rngs::OsRng;
    for _ in 0..64 {
        let mut pick = || WORDS.choose(&mut rng).copied().unwrap_or("room");
        let name = format!("#r-{}-{}-{}", pick(), pick(), pick());
        if state.channels.lock().contains_key(&name) {
            continue;
        }
        let taken = state
            .with_db(|db| Ok(db.channel_row_exists(&name)? || db.get_room(&name)?.is_some()))
            .unwrap_or(false);
        if !taken {
            return Some(name);
        }
    }
    None
}

/// A raw invite token: 32 random bytes, base64url unpadded (43 chars).
pub fn generate_token() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The only form of a token the database ever sees.
pub fn token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// The share URL. The token rides in the fragment, which browsers and HTTP
/// clients never send, so it never lands in an access log.
pub fn room_url(server_name: &str, channel: &str, token: &str) -> String {
    format!(
        "https://{server_name}/r/{}#{token}",
        channel.trim_start_matches('#')
    )
}

/// A unix time as the ISO date shown in notices and the landing page.
pub fn iso(secs: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| secs.to_string())
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Founder or DID-op of the room: the only identities that can mint or
/// revoke invites, remove members, or start a new epoch.
pub fn is_room_authority(ch: &crate::server::ChannelState, did: &str) -> bool {
    ch.founder_did.as_deref() == Some(did) || ch.did_ops.contains(did)
}

/// The line every admitted member gets, telling them what kind of place
/// they are in and that silence until a key arrives is expected.
pub fn admission_notice(channel: &str, expires_at: u64) -> String {
    format!(
        "{channel} is an end-to-end encrypted room. A member will seal the room key to you; \
         until then you can't read or send. Expires {}.",
        iso(expires_at)
    )
}

/// Note activity on a room without touching the database. The sweeper
/// flushes it (`flush_activity`).
pub fn bump_activity(state: &SharedState, channel: &str) {
    let now = now_secs();
    let mut map = state.room_activity.lock();
    let entry = map.entry(channel.to_lowercase()).or_insert(0);
    if *entry < now {
        *entry = now;
    }
}

/// Write pending activity into `rooms`. Each bump pushes the expiry out by
/// the idle TTL from the time of the bump, never shortening it.
pub fn flush_activity(state: &SharedState) {
    let pending: HashMap<String, u64> = std::mem::take(&mut *state.room_activity.lock());
    if pending.is_empty() {
        return;
    }
    let idle = state.config.room_idle_secs;
    state.with_db(|db| {
        for (channel, at) in &pending {
            db.touch_room(channel, *at, at.saturating_add(idle))?;
        }
        Ok(())
    });
}

/// Record activity right now, in the database, and return the room's new
/// expiry. JOIN and `keep` go this way; they are rare enough to afford it,
/// and both want to report the resulting expiry.
pub fn touch_now(state: &SharedState, channel: &str) -> Option<u64> {
    let now = now_secs();
    let expires_at = now.saturating_add(state.config.room_idle_secs);
    state
        .with_db(|db| {
            db.touch_room(channel, now, expires_at)?;
            Ok(db.get_room(channel)?.map(|r| r.expires_at))
        })
        .flatten()
}

/// Send one line to one session, if it is connected.
fn send_to_session(state: &SharedState, session_id: &str, line: &str) {
    if let Some(tx) = state.connections.lock().get(session_id) {
        let _ = tx.try_send(line.to_string());
    }
}

/// Send `body` as a server NOTICE to every live member of `channel`.
pub fn notice_members(state: &SharedState, channel: &str, body: &str) {
    let members: Vec<String> = state
        .channels
        .lock()
        .get(channel)
        .map(|ch| ch.members.iter().cloned().collect())
        .unwrap_or_default();
    // Lock order: channels → nick_to_session → connections. Held one at a
    // time here, since nothing needs two views to agree.
    let nicks: Vec<(String, String)> = {
        let n2s = state.nick_to_session.lock();
        members
            .iter()
            .filter_map(|sid| n2s.get_nick(sid).map(|n| (sid.clone(), n.to_string())))
            .collect()
    };
    let server = &state.server_name;
    for (sid, nick) in nicks {
        send_to_session(state, &sid, &format!(":{server} NOTICE {nick} :{body}\r\n"));
    }
}

/// Kick every live session of `did` out of `channel` in the server's own
/// name. Returns the nicks kicked. Used by member removal and deletion,
/// where there is no operator session to speak as.
pub fn kick_did(state: &SharedState, channel: &str, did: &str, reason: &str) -> Vec<String> {
    let sessions: Vec<String> = state
        .did_sessions
        .lock()
        .get(did)
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();
    kick_sessions(state, channel, &sessions, reason)
}

/// Kick the given sessions (those that are members) out of `channel`,
/// announcing each KICK to everyone in the channel first so the roster
/// every client holds agrees with the server's.
pub fn kick_sessions(
    state: &SharedState,
    channel: &str,
    sessions: &[String],
    reason: &str,
) -> Vec<String> {
    let (present, audience): (Vec<String>, Vec<String>) = {
        let channels = state.channels.lock();
        match channels.get(channel) {
            Some(ch) => (
                sessions
                    .iter()
                    .filter(|s| ch.members.contains(*s))
                    .cloned()
                    .collect(),
                ch.members.iter().cloned().collect(),
            ),
            None => return Vec::new(),
        }
    };
    if present.is_empty() {
        return Vec::new();
    }
    let nicks: Vec<(String, String)> = {
        let n2s = state.nick_to_session.lock();
        present
            .iter()
            .filter_map(|sid| n2s.get_nick(sid).map(|n| (sid.clone(), n.to_string())))
            .collect()
    };
    let server = &state.server_name;
    for (_, nick) in &nicks {
        let line = format!(":{server} KICK {channel} {nick} :{reason}\r\n");
        for sid in &audience {
            send_to_session(state, sid, &line);
        }
    }
    {
        let mut channels = state.channels.lock();
        if let Some(ch) = channels.get_mut(channel) {
            for sid in &present {
                ch.members.remove(sid);
                ch.ops.remove(sid);
                ch.voiced.remove(sid);
                ch.halfops.remove(sid);
            }
        }
    }
    // Kicked is kicked: a reconnect must not put them straight back in.
    let dids: Vec<String> = {
        let sd = state.session_dids.lock();
        present.iter().filter_map(|s| sd.get(s).cloned()).collect()
    };
    for did in dids {
        let (d, c) = (did, channel.to_string());
        state.with_db(|db| db.remove_user_channel(&d, &c));
    }
    nicks.into_iter().map(|(_, n)| n).collect()
}

/// Delete a room completely: kick the live members, drop the channel from
/// memory, and remove every row it owned. The messages are ciphertext and
/// the sealed keys go with them, so after this nothing can be recovered.
pub fn delete_room(state: &SharedState, channel: &str, reason: &str) {
    let channel = channel.to_lowercase();
    let members: Vec<String> = state
        .channels
        .lock()
        .get(&channel)
        .map(|ch| ch.members.iter().cloned().collect())
        .unwrap_or_default();
    kick_sessions(state, &channel, &members, reason);
    state.channels.lock().remove(&channel);
    state.room_names.lock().remove(&channel);
    state.room_activity.lock().remove(&channel);
    let c = channel.clone();
    state.with_db(move |db| {
        db.delete_channel(&c)?;
        db.prune_messages(&c, 0)?;
        db.delete_group_keys(&c)?;
        db.delete_pins(&c)?;
        db.delete_user_channel_rows(&c)?;
        db.delete_room(&c)
    });
    tracing::info!(channel = %channel, reason, "room deleted");
}

/// What one sweep did, for logs and tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub deleted: Vec<String>,
    pub warned: Vec<String>,
}

/// One pass of the sweeper at time `now`: flush activity, delete rooms
/// that are unclaimed or past expiry, warn rooms about to expire.
pub fn sweep_once(state: &SharedState, now: u64) -> SweepReport {
    flush_activity(state);
    let mut report = SweepReport::default();
    let rooms = state.with_db(|db| db.list_rooms()).unwrap_or_default();
    let unclaimed_secs = state.config.room_unclaimed_secs;
    for room in rooms {
        let members = state
            .with_db(|db| db.room_member_count(&room.channel))
            .unwrap_or(0);
        // A room only its founder ever entered is noise once the day is
        // out; the founder can mint another in one call.
        let unclaimed = members < 2 && room.created_at.saturating_add(unclaimed_secs) < now;
        if unclaimed || room.expires_at < now {
            delete_room(state, &room.channel, EXPIRED_KICK_REASON);
            report.deleted.push(room.channel);
            continue;
        }
        if room.warned_at.is_none() && room.expires_at.saturating_sub(now) < WARN_BEFORE_SECS {
            notice_members(
                state,
                &room.channel,
                &format!(
                    "{} expires {} unless someone speaks or a member calls POST /api/v1/rooms/{}/keep.",
                    room.channel,
                    iso(room.expires_at),
                    room.channel.trim_start_matches('#')
                ),
            );
            state.with_db(|db| db.set_room_warned(&room.channel, now));
            report.warned.push(room.channel);
        }
    }
    if !report.deleted.is_empty() || !report.warned.is_empty() {
        tracing::info!(
            deleted = report.deleted.len(),
            warned = report.warned.len(),
            "room sweep"
        );
    }
    report
}

/// Run `sweep_once` every ten minutes for the life of the server. The
/// first tick is skipped so a restart does not sweep before clients have
/// reconnected.
pub fn spawn_room_sweeper(state: Arc<SharedState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(SWEEP_EVERY_SECS));
        interval.tick().await;
        loop {
            interval.tick().await;
            sweep_once(&state, now_secs());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_word_list_is_large_lowercase_and_unique() {
        assert!(WORDS.len() >= 180, "{} words", WORDS.len());
        let mut seen = std::collections::HashSet::new();
        for w in WORDS {
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase()),
                "{w} is not plain lowercase"
            );
            assert!(w.len() <= 8, "{w} is too long to say");
            assert!(seen.insert(*w), "{w} appears twice");
        }
    }

    #[test]
    fn a_token_is_43_chars_of_base64url_and_hashes_to_hex_sha256() {
        let t = generate_token();
        assert_eq!(t.len(), 43);
        assert!(
            t.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_ne!(generate_token(), t, "tokens are random");
        let h = token_hash("abc");
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn the_share_url_carries_the_token_in_the_fragment() {
        assert_eq!(
            room_url("irc.freeq.at", "#r-quiet-copper-fox", "TOK"),
            "https://irc.freeq.at/r/r-quiet-copper-fox#TOK"
        );
    }

    #[test]
    fn a_generated_name_has_the_room_shape_and_avoids_live_channels() {
        let state = crate::server::test_state_with_db();
        let name = generate_room_name(&state).unwrap();
        let parts: Vec<&str> = name.trim_start_matches("#r-").split('-').collect();
        assert!(name.starts_with("#r-"), "{name}");
        assert_eq!(parts.len(), 3, "{name}");
        for p in parts {
            assert!(WORDS.contains(&p), "{p} is not on the list");
        }
        // Fill the map with the name and it must not come back.
        state
            .channels
            .lock()
            .insert(name.clone(), Default::default());
        for _ in 0..50 {
            assert_ne!(generate_room_name(&state).unwrap(), name);
        }
    }

    #[test]
    fn the_expiry_date_is_iso_utc() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert!(admission_notice("#r-a-b-c", 86_400).ends_with("Expires 1970-01-02T00:00:00Z."));
    }
}

#[cfg(test)]
mod sweeper_tests {
    //! The room sweeper: unclaimed and expired rooms go, rooms about to
    //! expire are warned once, and deletion reaches every table.
    use super::*;

    const F: &str = "did:key:zF";
    const M: &str = "did:key:zM";

    fn state() -> Arc<SharedState> {
        crate::server::test_state_with_config(crate::config::ServerConfig {
            room_idle_secs: 1_000,
            room_unclaimed_secs: 100,
            ..Default::default()
        })
    }

    /// A room created at `created_at` with the given roster, expiring at
    /// `expires_at`, present in memory and on disk with a message, a pin,
    /// a key and an invite.
    fn room(state: &SharedState, name: &str, created_at: u64, expires_at: u64, roster: &[&str]) {
        let ch = crate::server::ChannelState {
            room: true,
            invite_only: true,
            encrypted_only: true,
            founder_did: Some(F.into()),
            created_at,
            ..Default::default()
        };
        state.channels.lock().insert(name.to_string(), ch.clone());
        state
            .with_db(|db| {
                db.save_channel(name, &ch)?;
                db.create_room(name, F, created_at, expires_at)?;
                for did in roster {
                    db.upsert_room_member(name, did, created_at)?;
                }
                db.add_room_invite(name, &format!("h-{name}"), F, created_at, expires_at, None)?;
                db.save_group_key(name, F, 1, "EGK1:a")?;
                db.insert_message(
                    name,
                    "f!f@h",
                    "EG1:1:x",
                    created_at,
                    &HashMap::new(),
                    Some(&format!("01{}", name.len())),
                    Some(F),
                )?;
                db.store_pin(name, &format!("01{}", name.len()), "f", created_at)?;
                db.add_user_channel(F, name)
            })
            .unwrap();
    }

    fn has_room(state: &SharedState, name: &str) -> bool {
        state.with_db(|db| db.get_room(name)).flatten().is_some()
    }

    #[test]
    fn unclaimed_rooms_die_after_the_grace_and_claimed_ones_live() {
        let state = state();
        // Expiries far enough out that the warning window is not in play.
        room(&state, "#r-lonely-a-a", 1000, 500_000, &[F]);
        room(&state, "#r-shared-a-a", 1000, 500_000, &[F, M]);
        room(&state, "#r-fresh-a-a", 1090, 500_000, &[F]);

        let report = sweep_once(&state, 1150);
        assert_eq!(report.deleted, vec!["#r-lonely-a-a".to_string()]);
        assert!(report.warned.is_empty());
        assert!(!has_room(&state, "#r-lonely-a-a"));
        assert!(!state.channels.lock().contains_key("#r-lonely-a-a"));
        assert!(has_room(&state, "#r-shared-a-a"), "two members is claimed");
        assert!(has_room(&state, "#r-fresh-a-a"), "still inside the grace");
    }

    #[test]
    fn expired_rooms_die_and_deletion_reaches_every_table() {
        let state = state();
        let name = "#r-old-a-a";
        room(&state, name, 1000, 2000, &[F, M]);
        assert_eq!(sweep_once(&state, 2001).deleted, vec![name.to_string()]);
        assert!(!has_room(&state, name));
        state
            .with_db(|db| {
                assert!(!db.channel_row_exists(name)?);
                assert_eq!(db.room_member_count(name)?, 0);
                assert!(!db.consume_room_invite(name, &format!("h-{name}"), 1500)?);
                assert_eq!(db.latest_group_epoch(name)?, None);
                assert!(db.get_messages(name, 10, None)?.is_empty());
                assert!(db.get_pins(name)?.is_empty());
                assert!(db.get_user_channels(F)?.is_empty());
                Ok(())
            })
            .unwrap();
        // Idempotent: nothing left to sweep.
        assert_eq!(sweep_once(&state, 2002), SweepReport::default());
    }

    #[test]
    fn activity_keeps_a_room_alive_and_is_flushed_by_the_sweep() {
        let state = state();
        let name = "#r-busy-a-a";
        room(&state, name, 1000, 2000, &[F, M]);
        // A message at t=1900 (bumped in memory) pushes expiry to 2900.
        state.room_activity.lock().insert(name.to_string(), 1900);
        assert!(sweep_once(&state, 2500).deleted.is_empty());
        let row = state.with_db(|db| db.get_room(name)).flatten().unwrap();
        assert_eq!((row.last_activity, row.expires_at), (1900, 2900));
        assert!(state.room_activity.lock().is_empty(), "flushed");
        assert_eq!(sweep_once(&state, 2901).deleted, vec![name.to_string()]);
    }

    #[test]
    fn a_room_near_expiry_is_warned_exactly_once() {
        let state = state();
        let name = "#r-soon-a-a";
        room(&state, name, 1000, 100_000, &[F, M]);
        // A live member to receive the notice.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(16);
        state.connections.lock().insert("s-f".into(), tx);
        state.nick_to_session.lock().insert("founder", "s-f");
        state
            .channels
            .lock()
            .get_mut(name)
            .unwrap()
            .members
            .insert("s-f".into());

        assert!(
            sweep_once(&state, 1000).warned.is_empty(),
            "far from expiry"
        );
        let near = 100_000 - WARN_BEFORE_SECS + 10;
        assert_eq!(sweep_once(&state, near).warned, vec![name.to_string()]);
        let line = rx.try_recv().unwrap();
        assert!(
            line.starts_with(&format!(
                ":{} NOTICE founder :{name} expires ",
                state.server_name
            )),
            "{line}"
        );
        assert!(sweep_once(&state, near + 1).warned.is_empty(), "once");
        assert!(rx.try_recv().is_err());
        assert!(has_room(&state, name), "warned, not deleted");
    }

    #[test]
    fn deleting_a_room_kicks_its_live_members_first() {
        let state = state();
        let name = "#r-live-a-a";
        room(&state, name, 1000, 2000, &[F, M]);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(16);
        state.connections.lock().insert("s-m".into(), tx);
        state.nick_to_session.lock().insert("mem", "s-m");
        state.session_dids.lock().insert("s-m".into(), M.into());
        state
            .channels
            .lock()
            .get_mut(name)
            .unwrap()
            .members
            .insert("s-m".into());
        delete_room(&state, name, EXPIRED_KICK_REASON);
        let line = rx.try_recv().unwrap();
        assert_eq!(
            line,
            format!(":{} KICK {name} mem :Room expired\r\n", state.server_name)
        );
        assert!(!state.channels.lock().contains_key(name));
    }
}
