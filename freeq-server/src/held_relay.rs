//! Relayed edits and mutations held until the key that would check them
//! arrives.
//!
//! A peer relays an edit, a delete, a reaction or an unreaction signed by its
//! own user. The first one from a signer whose key this server has not fetched
//! yet cannot be checked, and an edit or mutation this server cannot check is
//! not applied. Dropping it on the spot lost it for good whenever the key
//! arrived a second later — which is the common case: the lookup starts on
//! that same miss. So it waits here, for a bounded time, and goes back
//! through the relay path when the key lands.
//!
//! The same structure as the task-event queue ([`crate::act_relay::DeferQueue`])
//! — per-origin and total ceilings, the oldest evicted with a log line, release
//! by `(signer, kid)`, the same retry backoff — as a separate queue, so a busy
//! editor cannot push task events out and the task-event queue's rules
//! (receipts, waiting on a subject) stay its own.
//!
//! **In memory only, and for a minute at most.** What waits here was never
//! applied, stored or shown; a restart or an expiry loses the same thing the
//! drop it replaces lost.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::act_relay::{FIRST_RETRY, retry_backoff};
use crate::s2s::S2sMessage;

/// How long a held item waits for its key before it is dropped.
pub(crate) const HOLD_LIMIT: Duration = Duration::from_secs(60);

/// What a released item carries back into the relay path from the moment it
/// arrived: the name the origin had then (asking again would need an await the
/// release hook cannot make) and the time it is filed under.
#[derive(Debug, Clone)]
pub(crate) struct Arrival {
    pub origin_name: String,
    /// Unix seconds.
    pub at: u64,
}

/// One relayed edit or mutation, exactly as it arrived.
///
/// The message itself is kept whole and untouched — the signature covers the
/// values as transmitted, before the relay path sanitizes and re-roots them,
/// so releasing it means running that path again from the top.
pub(crate) struct HeldRelay {
    pub message: S2sMessage,
    /// The authenticated peer the link came from.
    pub peer: String,
    /// The origin endpoint id, as the relay path settled it.
    pub origin: String,
    pub arrival: Arrival,
    /// The identity and key that would settle it.
    pub signer: String,
    pub kid: String,
    /// When it was held, for the age limit.
    pub held_at: Instant,
    /// Hold order across every origin. Overwritten by [`HeldQueue::hold`].
    pub seq: u64,
}

impl HeldRelay {
    /// What this is, for the log: which kind of change, where, and to what.
    pub(crate) fn describe(&self) -> (&'static str, &str, Option<&str>) {
        match &self.message {
            S2sMessage::Privmsg {
                target,
                replaces_msgid,
                ..
            } => ("edit", target, replaces_msgid.as_deref()),
            S2sMessage::Tagmsg { target, tags, .. } => {
                let get = |a: &str, b: &str| tags.get(a).or_else(|| tags.get(b));
                let kind = if get("+draft/delete", "+delete").is_some() {
                    "delete"
                } else if tags.contains_key("+freeq.at/unreact") {
                    "unreaction"
                } else {
                    "reaction"
                };
                let subject = get("+draft/delete", "+delete")
                    .or_else(|| get("+reply", "+draft/reply"))
                    .map(String::as_str);
                (kind, target, subject)
            }
            _ => ("event", "", None),
        }
    }
}

/// What is still owed to one signer's key: how many held items it would
/// settle, and when to ask for it next.
struct KeyRetry {
    waiting: usize,
    attempts: u32,
    next_attempt: Instant,
}

/// Relayed edits and mutations waiting for a key, bounded twice.
///
/// Two ceilings for the reason the task-event queue has two: the per-origin
/// bound stops one noisy peer filling the queue for everybody, the total bound
/// is what the process runs under. Nothing here outranks anything else, so
/// making room always costs the oldest item.
pub(crate) struct HeldQueue {
    by_origin: HashMap<String, VecDeque<HeldRelay>>,
    /// Per `(origin, signer, kid)`: what is waiting, and when to ask again.
    retries: HashMap<(String, String, String), KeyRetry>,
    total: usize,
    next_seq: u64,
    max_per_origin: usize,
    max_total: usize,
}

impl HeldQueue {
    pub(crate) fn new(max_per_origin: usize, max_total: usize) -> Self {
        HeldQueue {
            by_origin: HashMap::new(),
            retries: HashMap::new(),
            total: 0,
            next_seq: 0,
            // A ceiling of zero would hold an item and evict it in the same
            // breath. One is the smallest honest queue.
            max_per_origin: max_per_origin.max(1),
            max_total: max_total.max(1),
        }
    }

    /// How many items are waiting. Only the tests ask.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.total
    }

    /// Hold one item, making room for it if either ceiling is reached.
    ///
    /// Returns what was evicted to stay inside the ceilings, each already
    /// logged here.
    pub(crate) fn hold(&mut self, mut item: HeldRelay) -> Vec<HeldRelay> {
        item.seq = self.next_seq;
        self.next_seq += 1;
        let origin = item.origin.clone();
        let key = (origin.clone(), item.signer.clone(), item.kid.clone());
        let now = item.held_at;
        self.by_origin
            .entry(origin.clone())
            .or_default()
            .push_back(item);
        self.total += 1;
        self.retries
            .entry(key)
            .and_modify(|r| r.waiting += 1)
            .or_insert(KeyRetry {
                waiting: 1,
                attempts: 0,
                // The relay path asks once as it holds; this is the first ask
                // after that one goes unanswered.
                next_attempt: now + FIRST_RETRY,
            });

        let mut dropped = Vec::new();
        while self
            .by_origin
            .get(&origin)
            .is_some_and(|q| q.len() > self.max_per_origin)
        {
            let Some(item) = self
                .by_origin
                .get_mut(&origin)
                .and_then(VecDeque::pop_front)
            else {
                break;
            };
            dropped.push(self.note_evicted(item, "this peer's share of the queue"));
        }
        while self.total > self.max_total {
            let Some(oldest) = self.oldest_origin() else {
                break;
            };
            let Some(item) = self
                .by_origin
                .get_mut(&oldest)
                .and_then(VecDeque::pop_front)
            else {
                break;
            };
            dropped.push(self.note_evicted(item, "the queue across every peer"));
        }
        self.by_origin.retain(|_, q| !q.is_empty());
        dropped
    }

    /// Which origin holds the oldest item. Each queue is in hold order, so its
    /// own oldest is its first.
    fn oldest_origin(&self) -> Option<String> {
        self.by_origin
            .iter()
            .filter_map(|(name, q)| q.front().map(|i| (i.seq, name.clone())))
            .min()
            .map(|(_, name)| name)
    }

    /// Account for one item that left without being released.
    fn forget(&mut self, item: &HeldRelay) {
        self.total -= 1;
        let key = (item.origin.clone(), item.signer.clone(), item.kid.clone());
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.retries.entry(key) {
            e.get_mut().waiting -= 1;
            if e.get().waiting == 0 {
                e.remove();
            }
        }
    }

    /// Account for one item thrown away to make room, loudly, and hand it
    /// back. It was never applied, stored or shown.
    fn note_evicted(&mut self, item: HeldRelay, full: &str) -> HeldRelay {
        self.forget(&item);
        let (kind, target, subject) = item.describe();
        tracing::warn!(
            kind,
            reason = %format!("{full} is full"),
            origin = %item.origin,
            peer = %item.peer,
            target = %target,
            subject = ?subject,
            account = %item.signer,
            max_per_origin = self.max_per_origin,
            max_total = self.max_total,
            "Dropped a relayed edit or mutation that was waiting for its signer's key — \
             never applied, never stored"
        );
        item
    }

    /// Take every held item this key could settle, oldest first.
    pub(crate) fn take_for_signer(&mut self, did: &str, kid: &str) -> Vec<HeldRelay> {
        let mut taken = Vec::new();
        for queue in self.by_origin.values_mut() {
            let mut kept = VecDeque::with_capacity(queue.len());
            while let Some(item) = queue.pop_front() {
                match item.signer == did && item.kid == kid {
                    true => taken.push(item),
                    false => kept.push_back(item),
                }
            }
            *queue = kept;
        }
        self.by_origin.retain(|_, q| !q.is_empty());
        self.total -= taken.len();
        self.retries
            .retain(|(_, signer, key_id), _| signer != did || key_id != kid);
        taken.sort_by_key(|i| i.seq);
        taken
    }

    /// Take every item that has waited [`HOLD_LIMIT`] or longer by `now`,
    /// oldest first. The caller logs each: it is the end of that item.
    pub(crate) fn expire(&mut self, now: Instant) -> Vec<HeldRelay> {
        let mut expired = Vec::new();
        for queue in self.by_origin.values_mut() {
            // Each queue is in hold order, so the expired ones are a prefix.
            while queue
                .front()
                .is_some_and(|i| now.saturating_duration_since(i.held_at) >= HOLD_LIMIT)
            {
                expired.extend(queue.pop_front());
            }
        }
        self.by_origin.retain(|_, q| !q.is_empty());
        for item in &expired {
            self.forget(item);
        }
        expired.sort_by_key(|i| i.seq);
        expired
    }

    /// The keys it is time to ask for again, and the peer to ask for each, on
    /// the task-event queue's backoff.
    pub(crate) fn retries_due(&mut self, now: Instant) -> Vec<(String, String, String)> {
        let mut due = Vec::new();
        for ((origin, signer, kid), retry) in self.retries.iter_mut() {
            if signer.is_empty() || kid.is_empty() || retry.next_attempt > now {
                continue;
            }
            due.push((origin.clone(), signer.clone(), kid.clone()));
            retry.attempts += 1;
            retry.next_attempt = now + retry_backoff(retry.attempts);
        }
        due
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edit(origin: &str, signer: &str, kid: &str, at: Instant) -> HeldRelay {
        HeldRelay {
            message: S2sMessage::Privmsg {
                event_id: String::new(),
                from: "a!a@h".to_string(),
                target: "#c".to_string(),
                text: "t".to_string(),
                origin: origin.to_string(),
                msgid: Some(crate::msgid::generate()),
                sig: None,
                account: Some(signer.to_string()),
                recipient_did: None,
                replaces_msgid: Some("root".to_string()),
                tags: HashMap::new(),
                multiline_lines: None,
            },
            peer: origin.to_string(),
            origin: origin.to_string(),
            arrival: Arrival {
                origin_name: origin.to_string(),
                at: 0,
            },
            signer: signer.to_string(),
            kid: kid.to_string(),
            held_at: at,
            seq: 0,
        }
    }

    #[test]
    fn released_by_its_key_in_hold_order() {
        let now = Instant::now();
        let mut q = HeldQueue::new(10, 10);
        assert!(q.hold(edit("p", "did:a", "k1", now)).is_empty());
        assert!(q.hold(edit("p", "did:b", "k2", now)).is_empty());
        assert!(q.hold(edit("p", "did:a", "k1", now)).is_empty());
        let taken = q.take_for_signer("did:a", "k1");
        assert_eq!(taken.len(), 2);
        assert!(taken[0].seq < taken[1].seq, "oldest first");
        assert_eq!(q.len(), 1, "the other signer's item still waits");
    }

    #[test]
    fn expires_at_the_limit_against_the_clock_it_is_given() {
        let t0 = Instant::now();
        let mut q = HeldQueue::new(10, 10);
        let _ = q.hold(edit("p", "did:a", "k1", t0));
        let _ = q.hold(edit("p", "did:a", "k1", t0 + Duration::from_secs(30)));
        assert!(q.expire(t0 + Duration::from_secs(59)).is_empty());
        let gone = q.expire(t0 + HOLD_LIMIT);
        assert_eq!(gone.len(), 1, "only the one that has waited a minute");
        assert_eq!(q.len(), 1);
        assert_eq!(q.expire(t0 + Duration::from_secs(90)).len(), 1);
        assert_eq!(q.len(), 0);
        assert!(
            q.retries_due(t0 + Duration::from_secs(600)).is_empty(),
            "nothing left to ask for"
        );
    }

    #[test]
    fn ceilings_evict_the_oldest() {
        let now = Instant::now();
        let mut q = HeldQueue::new(2, 3);
        let _ = q.hold(edit("p", "did:a", "k", now));
        let first_seq = 0;
        let _ = q.hold(edit("p", "did:a", "k", now));
        let dropped = q.hold(edit("p", "did:a", "k", now));
        assert_eq!(dropped.len(), 1, "per-origin share");
        assert_eq!(dropped[0].seq, first_seq, "the oldest goes");
        let _ = q.hold(edit("r", "did:a", "k", now));
        let dropped = q.hold(edit("s", "did:a", "k", now));
        assert_eq!(dropped.len(), 1, "total");
        assert_eq!(dropped[0].seq, 1, "the oldest anywhere goes");
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn asks_again_on_the_backoff() {
        let t0 = Instant::now();
        let mut q = HeldQueue::new(10, 10);
        let _ = q.hold(edit("p", "did:a", "k", t0));
        assert!(q.retries_due(t0).is_empty(), "the hold asked already");
        assert_eq!(q.retries_due(t0 + FIRST_RETRY).len(), 1);
        assert!(q.retries_due(t0 + FIRST_RETRY).is_empty());
    }
}
