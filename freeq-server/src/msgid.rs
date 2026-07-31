//! ULID-based message ID generation.
//!
//! Each message gets a globally unique, time-sortable identifier.
//! Format: 26-character Crockford base32 string (compatible with IRCv3 `msgid` tag).
//!
//! Structure: 48 bits timestamp (ms since epoch) + 80 bits random.
//!
//! Monotonic: within the same millisecond, the random component is
//! incremented to guarantee sort order matches generation order.

use rand::Rng;
use std::sync::Mutex;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// How far a client-minted id's embedded timestamp may sit from this server's
/// clock. Federated machines do not have synchronized clocks (we have the
/// drifted-NTP scars to prove it), so the bound is generous — it exists to
/// keep a wildly future-dated id out of the log, not to measure anything.
/// Same ±120s grace the act RFC uses for the one other wall-clock comparison
/// in the system.
pub const MAX_CLIENT_SKEW_MS: u64 = 120_000;

/// Why a client-minted message id was refused. Each variant is a reason a
/// client can act on, which is why they're distinct: the fix for a malformed
/// id is different from the fix for a reused one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdRejection {
    /// Not a 26-character Crockford base32 ULID.
    NotUlid,
    /// The embedded timestamp is further than [`MAX_CLIENT_SKEW_MS`] from now.
    Skewed,
}

impl IdRejection {
    /// The machine-readable code carried in the `FAIL` reply.
    pub fn code(self) -> &'static str {
        match self {
            IdRejection::NotUlid => "INVALID_EVENTID",
            IdRejection::Skewed => "EVENTID_CLOCK_SKEW",
        }
    }

    /// The human-readable half of the `FAIL` reply.
    pub fn description(self) -> &'static str {
        match self {
            IdRejection::NotUlid => "Event id must be a 26-character Crockford base32 ULID",
            IdRejection::Skewed => "Event id timestamp is too far from server time",
        }
    }
}

/// Whether `id` is a well-formed ULID as this server mints them: 26 characters
/// of uppercase Crockford base32.
pub fn is_wellformed(id: &str) -> bool {
    id.len() == 26
        && id
            .bytes()
            .all(|b| CROCKFORD.contains(&b.to_ascii_uppercase()) && !b.is_ascii_lowercase())
}

/// The millisecond timestamp a ULID embeds in its first 10 characters.
///
/// `None` for anything not well-formed, so callers get one answer for "this is
/// not one of our ids" instead of a plausible-looking number decoded from
/// nonsense.
pub fn timestamp_ms(id: &str) -> Option<u64> {
    if !is_wellformed(id) {
        return None;
    }
    let mut ts: u64 = 0;
    for b in id.bytes().take(10) {
        let value = CROCKFORD.iter().position(|c| *c == b)? as u64;
        ts = (ts << 5) | value;
    }
    Some(ts)
}

/// Check an id a *client* minted, before this server files anything under it.
///
/// Shape and clock only — uniqueness needs storage and is checked by the
/// caller, which is the only place that knows whether an id is already taken.
pub fn check_client_minted(id: &str, now_ms: u64) -> Result<(), IdRejection> {
    let ts = timestamp_ms(id).ok_or(IdRejection::NotUlid)?;
    if ts.abs_diff(now_ms) > MAX_CLIENT_SKEW_MS {
        return Err(IdRejection::Skewed);
    }
    Ok(())
}

/// Monotonic state: last timestamp and random component.
static LAST: Mutex<(u64, u128)> = Mutex::new((0, 0));

/// Generate a new monotonic ULID string.
pub fn generate() -> String {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let (ts, rand_bits) = {
        let mut last = LAST.lock().unwrap();
        if now_ms == last.0 {
            // Same millisecond — increment random to maintain ordering.
            // The 80-bit random space is large enough that overflow is
            // effectively impossible in practice.
            last.1 = last.1.wrapping_add(1);
            (now_ms, last.1)
        } else {
            // New millisecond — fresh random
            let mut rng = rand::thread_rng();
            let r: u128 = ((rng.r#gen::<u16>() as u128) << 64) | rng.r#gen::<u64>() as u128;
            // Mask to 80 bits
            let r = r & ((1u128 << 80) - 1);
            *last = (now_ms, r);
            (now_ms, r)
        }
    };

    let mut buf = [0u8; 26];

    // Encode timestamp (10 chars, most significant first)
    let mut t = ts;
    for i in (0..10).rev() {
        buf[i] = CROCKFORD[(t & 0x1F) as usize];
        t >>= 5;
    }

    // Encode 80-bit random (16 chars, most significant first)
    let mut r = rand_bits;
    for i in (10..26).rev() {
        buf[i] = CROCKFORD[(r & 0x1F) as usize];
        r >>= 5;
    }

    // SAFETY: all bytes are ASCII from CROCKFORD alphabet
    unsafe { String::from_utf8_unchecked(buf.to_vec()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ulid_length_and_uniqueness() {
        let a = generate();
        let b = generate();
        assert_eq!(a.len(), 26);
        assert_eq!(b.len(), 26);
        assert_ne!(a, b);
    }

    #[test]
    fn ulid_is_ascii_crockford() {
        let id = generate();
        for c in id.chars() {
            assert!(
                c.is_ascii_digit()
                    || (c.is_ascii_uppercase() && c != 'I' && c != 'L' && c != 'O' && c != 'U'),
                "Invalid Crockford char: {c}"
            );
        }
    }

    #[test]
    fn a_generated_id_passes_the_client_minted_check() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let id = generate();
        assert!(is_wellformed(&id));
        assert!(timestamp_ms(&id).unwrap().abs_diff(now) < 1_000);
        assert_eq!(check_client_minted(&id, now), Ok(()));
    }

    #[test]
    fn malformed_ids_are_not_ulids() {
        for bad in [
            "",
            "tooshort",
            "01KYVT5Z8Q000000000000000",   // 25 chars
            "01KYVT5Z8Q00000000000000000", // 27 chars
            "01kyvt5z8q0000000000000000",  // lowercase
            "01KYVT5Z8Q000000000000000I",  // I, L, O, U are not Crockford
            "01KYVT5Z8Q000000000000000!",
        ] {
            assert!(!is_wellformed(bad), "{bad} should not be well-formed");
            assert_eq!(timestamp_ms(bad), None);
            assert_eq!(check_client_minted(bad, 0), Err(IdRejection::NotUlid));
        }
    }

    #[test]
    fn a_clock_far_from_ours_is_skew_not_malformed() {
        let id = generate();
        let ts = timestamp_ms(&id).unwrap();
        // Inside the grace window, in both directions — a client whose clock
        // is a minute out still gets its own id.
        assert_eq!(check_client_minted(&id, ts + MAX_CLIENT_SKEW_MS), Ok(()));
        assert_eq!(check_client_minted(&id, ts - MAX_CLIENT_SKEW_MS), Ok(()));
        // Outside it, in both directions.
        assert_eq!(
            check_client_minted(&id, ts + MAX_CLIENT_SKEW_MS + 1),
            Err(IdRejection::Skewed)
        );
        assert_eq!(
            check_client_minted(&id, ts - MAX_CLIENT_SKEW_MS - 1),
            Err(IdRejection::Skewed)
        );
    }

    #[test]
    fn ulid_monotonic_ordering() {
        let a = generate();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = generate();
        assert!(a < b, "ULIDs should sort chronologically: {a} vs {b}");
    }
}
