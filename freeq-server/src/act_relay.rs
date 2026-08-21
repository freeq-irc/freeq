//! Verdicts for task events relayed from peer servers, and what follows from
//! each one.
//!
//! Two families of task event cross S2S as a `Tagmsg`: the act family
//! (`act-*` tags, signed under the act canonical — see [`freeq_sdk::act`])
//! and the older stopgap coordination family (`+freeq.at/event`, signed as a
//! chat-profile coordination document — see [`freeq_sdk::chatsig`]). This
//! module is where the receive side reaches its own verdict about each one.
//!
//! The verdict is three-way, the distinction is the RFC's central rule, and
//! each answer leads somewhere different:
//!
//! - **Valid** — the rebuilt document verifies against the signer's key.
//!   Stored, applied as far as the task's origin allows, and delivered.
//! - **Invalid** — the named key was found and the bytes do not verify.
//!   Evidence of tampering or forgery, never a fallback classification, and
//!   the one verdict that stops an event: not delivered, not stored.
//! - **Unverifiable** — everything else: no key on file, no key server
//!   configured for the origin, an algorithm this build does not know, a
//!   mandatory field missing. An outage or an old peer is not evidence about
//!   the sender, so none of these may ever read as invalid and none is ever
//!   refused. Neither stored nor shown while it waits: what this server
//!   cannot check it does not present as a task. It waits in [`DeferQueue`]
//!   for the key that would settle it, and is judged again when one arrives.
//!
//! The verdict itself consults no server state: the caller resolves the DM
//! recipient and supplies the key lookup, which is what makes the checker
//! provable against the committed vectors (`spec/act-signing-vectors.json`,
//! `spec/chat-signing-vectors.json`) without a server around it.

use std::collections::HashMap;

use crate::connection::messaging::NO_KEY_ON_FILE;

/// What this server concluded about one relayed task event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayVerdict {
    /// The rebuilt document verifies against the signer's key.
    Valid,
    /// The named key was found and the bytes do not verify.
    Invalid(&'static str),
    /// No verdict is reachable; the reason says why.
    Unverifiable(&'static str),
}

impl RelayVerdict {
    /// The word for the log's `verdict` field.
    pub(crate) fn label(self) -> &'static str {
        match self {
            RelayVerdict::Valid => "valid",
            RelayVerdict::Invalid(_) => "invalid",
            RelayVerdict::Unverifiable(_) => "unverifiable",
        }
    }

    /// The reason for the log's `reason` field.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            RelayVerdict::Valid => "signature verifies over the rebuilt document",
            RelayVerdict::Invalid(why) | RelayVerdict::Unverifiable(why) => why,
        }
    }
}

/// One structured line per relayed task event: this server's own verdict, and
/// therefore the record of why the event was stored, dropped or carried no
/// further.
///
/// `peer_declared_act` is what separates two failures that otherwise look
/// identical: a signature that fails because an old peer in the path predates
/// task events (and may have stripped tags it did not know) versus one that
/// fails on traffic a task-aware peer carried — the second is worth an
/// operator's attention, the first is a version skew.
///
/// Invalid logs at warn — a found key over bytes that do not verify is
/// evidence — and everything else at info.
pub(crate) fn log_relayed_verdict(
    verdict: RelayVerdict,
    event_id: &str,
    origin: &str,
    peer: &str,
    target: &str,
    peer_declared_act: bool,
) {
    match verdict {
        RelayVerdict::Invalid(_) => tracing::warn!(
            verdict = %verdict.label(),
            reason = %verdict.reason(),
            event_id = %event_id,
            origin = %origin,
            peer = %peer,
            target = %target,
            peer_declared_act,
            "Relayed task event checked"
        ),
        _ => tracing::info!(
            verdict = %verdict.label(),
            reason = %verdict.reason(),
            event_id = %event_id,
            origin = %origin,
            peer = %peer,
            target = %target,
            peer_declared_act,
            "Relayed task event checked"
        ),
    }
}

// ── the defer queue ─────────────────────────────────────────────────────────

/// One relayed task event, held until the key that would settle it arrives.
///
/// Everything the receive side needs to reach the same conclusion later,
/// captured as it arrived: the tags are what the signature covers and cannot
/// be tidied first, and `peer_declared_act` is a fact about the link the event
/// came in on that is not recoverable afterwards. The DM recipient is
/// deliberately absent — it is re-resolved at retry, because who is here can
/// change while an event waits.
///
/// Build one with `..Default::default()` for `seq`: park order is the queue's
/// to assign, and [`DeferQueue::park`] stamps it on the way in.
#[derive(Default)]
pub(crate) struct ParkedEvent {
    pub tags: HashMap<String, String>,
    pub target: String,
    /// The `nick!user@host` prefix delivery quotes back.
    pub from: String,
    pub peer_account: Option<String>,
    pub origin: String,
    pub peer: String,
    pub peer_declared_act: bool,
    pub event_id: String,
    /// The identity whose key would settle this, and the key its signature
    /// names. Empty when the event named neither — nothing will ever match
    /// those, and they wait to be evicted, which is the visible ageing-out an
    /// event that can never verify gets.
    pub signer: String,
    pub kid: String,
    /// Park order across every origin. Overwritten by [`DeferQueue::park`].
    pub seq: u64,
}

/// Whether a parked event is a receipt — the home server's own word about an
/// event it filed, which is never the one thrown out to make room.
fn is_receipt(tags: &HashMap<String, String>) -> bool {
    tags.get("+freeq.at/act-verb")
        .or_else(|| tags.get("act-verb"))
        .is_some_and(|verb| freeq_sdk::act_transitions::is_confirmation(verb))
}

/// The first wait before asking again, and the ceiling that doubling stops at.
pub(crate) const FIRST_RETRY: std::time::Duration = std::time::Duration::from_secs(30);
pub(crate) const MAX_RETRY: std::time::Duration = std::time::Duration::from_secs(600);

/// How long to wait after `attempts` asks have gone unanswered: thirty
/// seconds, doubling, ten minutes at the most. A server that is down for an
/// hour is asked a handful of times rather than a hundred.
///
/// One curve, two askers: the key a parked event waits for, and the ruling a
/// routed transition waits for. They ask different servers different
/// questions, but the reason for the shape is the same one, and two copies of
/// it would drift.
pub(crate) fn retry_backoff(attempts: u32) -> std::time::Duration {
    FIRST_RETRY
        .saturating_mul(1u32 << attempts.min(5))
        .min(MAX_RETRY)
}

/// What is still owed to one signer's key: how many parked events it would
/// settle, and when to ask for it next.
struct KeyRetry {
    waiting: usize,
    attempts: u32,
    next_attempt: std::time::Instant,
}

/// Relayed task events waiting for a key, bounded twice.
///
/// **In memory only, on purpose.** A restart drops whatever is parked; those
/// events were never delivered and never stored, so what is lost is the same
/// thing an eviction loses. Persisting a queue of unverified events would mean
/// carrying a peer's unchecked claims across restarts, which is a larger
/// promise than deferring was meant to make. Catch-up is what heals a real
/// gap.
///
/// Two ceilings rather than one. The per-origin bound stops a single noisy
/// peer filling the queue for everybody; the total bound is what the process
/// actually runs under, because enough peers each inside their own share add
/// up to more than one server should hold. An origin here is the peer the
/// link authenticated as, so nobody can invent one — the total bounds what
/// real peers park between them, not a made-up name.
///
/// One kind of event is never the one evicted to make room: a receipt, the
/// home server's ruling on somebody's move, whose loss leaves the people
/// waiting on it with nothing. A bucket holding nothing but receipts turns
/// away what arrives instead — with one exception, when what arrives is
/// itself a receipt: then the oldest receipt goes, because the newest ruling
/// is the one more likely to still matter and catch-up brings the older one
/// back.
pub(crate) struct DeferQueue {
    by_origin: HashMap<String, std::collections::VecDeque<ParkedEvent>>,
    /// Per `(origin, signer, kid)`: what is waiting, and when to ask again.
    retries: HashMap<(String, String, String), KeyRetry>,
    total: usize,
    next_seq: u64,
    max_per_origin: usize,
    max_total: usize,
}

impl DeferQueue {
    pub(crate) fn new(max_per_origin: usize, max_total: usize) -> Self {
        DeferQueue {
            by_origin: HashMap::new(),
            retries: HashMap::new(),
            total: 0,
            next_seq: 0,
            // A ceiling of zero would park an event and evict it in the same
            // breath, which reads as silent loss rather than a disabled
            // feature. One is the smallest honest queue.
            max_per_origin: max_per_origin.max(1),
            max_total: max_total.max(1),
        }
    }

    /// How many events are waiting. Only the tests ask; the queue's own
    /// records of what it did are its log lines and the count each dropped
    /// event leaves on its task.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.total
    }

    /// Park one event, making room for it if either ceiling is reached.
    ///
    /// Returns whatever the queue threw away to stay inside its ceilings — the
    /// events evicted, or the arriving one when nothing there could be evicted
    /// — so the caller can leave a visible trace on each one's task beside the
    /// log lines written here.
    #[must_use = "dropped events deserve a visible trace, not just the log"]
    pub(crate) fn park(&mut self, mut event: ParkedEvent) -> Vec<ParkedEvent> {
        let arrival = self.next_seq;
        // What arrives decides whether a parked receipt may be given up: only
        // an arriving receipt outranks one.
        let arrival_is_receipt = is_receipt(&event.tags);
        event.seq = arrival;
        self.next_seq += 1;
        let origin = event.origin.clone();
        let key = (origin.clone(), event.signer.clone(), event.kid.clone());
        self.by_origin
            .entry(origin.clone())
            .or_default()
            .push_back(event);
        self.total += 1;
        self.retries
            .entry(key)
            .and_modify(|r| r.waiting += 1)
            .or_insert(KeyRetry {
                waiting: 1,
                attempts: 0,
                // The caller asks once as it parks; this is the first ask
                // after that one goes unanswered.
                next_attempt: std::time::Instant::now() + FIRST_RETRY,
            });

        let mut dropped = Vec::new();
        while self
            .by_origin
            .get(&origin)
            .is_some_and(|q| q.len() > self.max_per_origin)
        {
            let victim = self
                .evict_oldest_from(&origin, arrival_is_receipt)
                .or_else(|| self.take_arrival(&origin, arrival));
            match victim {
                Some(event) => dropped.push(self.note_dropped(
                    event,
                    arrival,
                    "this peer's share of the queue",
                )),
                None => break,
            }
        }
        while self.total > self.max_total {
            let victim = self
                .evict_oldest_anywhere(arrival_is_receipt)
                .or_else(|| self.take_arrival(&origin, arrival));
            match victim {
                Some(event) => {
                    dropped.push(self.note_dropped(event, arrival, "the queue across every peer"))
                }
                None => break,
            }
        }
        self.by_origin.retain(|_, q| !q.is_empty());
        dropped
    }

    /// The event that just arrived, taken back out — the last resort when
    /// nothing already parked may be given up.
    fn take_arrival(&mut self, origin: &str, arrival: u64) -> Option<ParkedEvent> {
        let queue = self.by_origin.get_mut(origin)?;
        let at = queue.iter().position(|e| e.seq == arrival)?;
        queue.remove(at)
    }

    /// The oldest event one origin could give up: the first that is not a
    /// receipt, or — only if `receipts_too` — the oldest event of any kind.
    /// `None` when the origin holds only receipts and none of them may go.
    fn evict_oldest_from(&mut self, origin: &str, receipts_too: bool) -> Option<ParkedEvent> {
        let queue = self.by_origin.get_mut(origin)?;
        let at = queue
            .iter()
            .position(|e| !is_receipt(&e.tags))
            .or_else(|| receipts_too.then_some(0))?;
        queue.remove(at)
    }

    /// The same across every origin. A non-receipt anywhere is preferred to a
    /// receipt anywhere, so the two passes run in that order rather than one
    /// pass picking whichever origin happens to hold the oldest event.
    fn evict_oldest_anywhere(&mut self, receipts_too: bool) -> Option<ParkedEvent> {
        let origin = self
            .oldest_origin(false)
            .or_else(|| receipts_too.then(|| self.oldest_origin(true)).flatten())?;
        self.evict_oldest_from(&origin, receipts_too)
    }

    /// Which origin holds the oldest event that may be given up. Each queue is
    /// in park order, so its own oldest is the first element that qualifies.
    fn oldest_origin(&self, receipts_too: bool) -> Option<String> {
        self.by_origin
            .iter()
            .filter_map(|(name, q)| {
                q.iter()
                    .find(|e| receipts_too || !is_receipt(&e.tags))
                    .map(|e| (e.seq, name.clone()))
            })
            .min()
            .map(|(_, name)| name)
    }

    /// Account for one event the queue threw away, loudly, and hand it back.
    /// An event that goes this way was never delivered and never stored;
    /// besides this log line, the only trace it can leave is the caller's
    /// count on the task's row.
    ///
    /// Three fates, and an operator needs to tell them apart. An ordinary
    /// parked event was *evicted* to make room. An arriving non-receipt was
    /// *refused*, because `full` held nothing but receipts and none of those
    /// may be given up for it. A parked receipt goes only as a *last resort*:
    /// `full` held nothing but receipts and what arrived was a receipt too, so
    /// the choice lay between the oldest ruling and the newest, and the newest
    /// is the one more likely to still matter. The ceiling holds either way,
    /// which is what every other bound here rests on.
    ///
    /// The fields are the verdict line's, so an operator can follow one event
    /// from the verdict that parked it to the moment it was thrown away.
    fn note_dropped(&mut self, event: ParkedEvent, arrival: u64, full: &str) -> ParkedEvent {
        let (fate, why) = if event.seq == arrival {
            (
                "refused",
                format!("{full} is full and holds nothing that may be evicted for this event"),
            )
        } else if is_receipt(&event.tags) {
            (
                "evicted-receipt",
                format!(
                    "{full} is full and holds nothing but receipts, and the receipt that \
                     arrived would otherwise have been the one lost"
                ),
            )
        } else {
            ("evicted", format!("{full} is full"))
        };
        self.total -= 1;
        let key = (
            event.origin.clone(),
            event.signer.clone(),
            event.kid.clone(),
        );
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.retries.entry(key) {
            e.get_mut().waiting -= 1;
            if e.get().waiting == 0 {
                e.remove();
            }
        }
        tracing::warn!(
            fate = %fate,
            reason = %why,
            event_id = %event.event_id,
            origin = %event.origin,
            peer = %event.peer,
            target = %event.target,
            max_per_origin = self.max_per_origin,
            max_total = self.max_total,
            "Dropped a relayed task event that was waiting for its signer's key — \
             never delivered, never stored"
        );
        event
    }

    /// Take every parked event this key could settle, oldest first.
    pub(crate) fn take_for_signer(&mut self, did: &str, kid: &str) -> Vec<ParkedEvent> {
        let mut taken = Vec::new();
        for queue in self.by_origin.values_mut() {
            let mut kept = std::collections::VecDeque::with_capacity(queue.len());
            while let Some(event) = queue.pop_front() {
                match event.signer == did && event.kid == kid {
                    true => taken.push(event),
                    false => kept.push_back(event),
                }
            }
            *queue = kept;
        }
        self.by_origin.retain(|_, q| !q.is_empty());
        self.total -= taken.len();
        self.retries
            .retain(|(_, signer, key_id), _| signer != did || key_id != kid);
        taken.sort_by_key(|e| e.seq);
        taken
    }

    /// The keys it is time to ask for again, and the peer to ask for each.
    ///
    /// Asking is the caller's job; the schedule is this queue's, because it is
    /// the only thing that knows what is still waiting. Each answer moves that
    /// key on to its next backoff step, so a sweep that runs often does not
    /// ask often.
    pub(crate) fn retries_due(&mut self) -> Vec<(String, String, String)> {
        let now = std::time::Instant::now();
        let mut due = Vec::new();
        for ((origin, signer, kid), retry) in self.retries.iter_mut() {
            // A signature that named no signer or no key can never be settled
            // by any lookup; those wait to be evicted instead.
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

// ── routing a transition to the server that owns the task ───────────────────

/// One transition on its way to the server that owns its task.
///
/// The message travels whole because the signature covers its tags and nothing
/// here may tidy them. `home` is the endpoint the task was opened under, which
/// is the only server whose ruling on it counts.
pub(crate) struct PendingRoute {
    pub act_id: String,
    /// The signed event's own id — what the log knows it by here, and what a
    /// ruling on it names when one is built.
    pub event_id: String,
    /// Endpoint id of the server that owns the task.
    pub home: String,
    /// The message to send. Its envelope id is stamped fresh at every attempt:
    /// a receiver's dedup rejects a counter at or below the high-water mark it
    /// already holds from us, so a retry carrying the original id would be
    /// discarded as a replay of something that never arrived.
    pub message: crate::s2s::S2sMessage,
    /// How many attempts have already been made.
    pub attempts: u32,
    /// The earliest moment worth trying again.
    pub next_attempt: std::time::Instant,
    /// Park order, assigned by [`RouteQueue::park`].
    pub seq: u64,
}

/// Transitions waiting for the server that owns their task.
///
/// **In memory, like the defer queue beside it, and for the same reason.**
/// Everything held here has already been filed and shown; what a restart costs
/// is a prompt ruling, not a record, and catch-up carries the event round
/// again anyway. Bounded for the same reason too — a home that stays away must
/// not grow this without limit.
pub(crate) struct RouteQueue {
    by_event: HashMap<String, PendingRoute>,
    next_seq: u64,
    max: usize,
}

impl RouteQueue {
    pub(crate) fn new(max: usize) -> Self {
        RouteQueue {
            by_event: HashMap::new(),
            next_seq: 0,
            max: max.max(1),
        }
    }

    /// How many transitions are waiting. Only the tests ask; the queue's own
    /// records of what it did are its log lines.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_event.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.by_event.is_empty()
    }

    /// Hold one route until it can be delivered. A route for an event already
    /// waiting replaces it — same event, same destination, and the newer one
    /// carries the fresher attempt count.
    pub(crate) fn park(&mut self, mut route: PendingRoute) {
        route.seq = self.next_seq;
        self.next_seq += 1;
        self.by_event.insert(route.event_id.clone(), route);
        while self.by_event.len() > self.max {
            let oldest = self
                .by_event
                .values()
                .min_by_key(|r| r.seq)
                .map(|r| r.event_id.clone());
            let Some(oldest) = oldest else { break };
            if let Some(dropped) = self.by_event.remove(&oldest) {
                tracing::warn!(
                    act_id = %dropped.act_id,
                    event_id = %dropped.event_id,
                    home = %dropped.home,
                    max = self.max,
                    "Gave up carrying a task transition to the server that owns it — \
                     the queue is full. The event is on file and unconfirmed; \
                     catch-up is what will settle it now"
                );
            }
        }
    }

    /// Every route due at `now`, taken out. A caller that still cannot deliver
    /// one parks it again with its attempt count raised.
    pub(crate) fn take_due(&mut self, now: std::time::Instant) -> Vec<PendingRoute> {
        let due: Vec<String> = self
            .by_event
            .values()
            .filter(|r| r.next_attempt <= now)
            .map(|r| r.event_id.clone())
            .collect();
        let mut taken: Vec<PendingRoute> = due
            .into_iter()
            .filter_map(|id| self.by_event.remove(&id))
            .collect();
        taken.sort_by_key(|r| r.seq);
        taken
    }
}

/// The identity a relayed task event's signature claims, and whose key the
/// lookup must use.
///
/// For the act family that is the signed document's own `from` tag — not the
/// S2S message's account stamp, which is the *relaying* server's assertion.
/// For the coordination family the document's `from` is not on the wire as a
/// tag at all; it is the account the origin stamped, which the caller passes
/// as `sender_did`.
pub(crate) fn claimed_signer<'a>(
    tags: &'a HashMap<String, String>,
    sender_did: Option<&'a str>,
) -> Option<&'a str> {
    if crate::connection::act::carries_act_tags(tags) {
        tags.get("+freeq.at/from")
            .or_else(|| tags.get("from"))
            .map(String::as_str)
    } else {
        sender_did
    }
}

/// Rebuild the venue the signer signed, from the delivery target.
///
/// Never the wire target itself: a channel is folded, and a DM binds the
/// sorted DID pair (`dm_recipient_did` is the caller's resolution of the wire
/// target — `None` when it does not resolve, which makes the event
/// unverifiable rather than wrong).
fn venue_for(target: &str, from_did: &str, dm_recipient_did: Option<&str>) -> Option<String> {
    if target.starts_with('#') || target.starts_with('&') {
        return Some(freeq_sdk::chatsig::channel_venue(target));
    }
    dm_recipient_did.map(|other| freeq_sdk::chatsig::dm_venue(from_did, other))
}

/// The coordination document a relayed `+freeq.at/event` TAGMSG's signature
/// covers, rebuilt from the wire tags exactly as local ingress builds it
/// (prefixed spellings only, `ref` falling back to `task-id`).
pub(crate) fn coordination_doc_from_tags<'a>(
    tags: &'a HashMap<String, String>,
    from: &'a str,
    event_id: &'a str,
    venue: &'a str,
    event_type: &'a str,
) -> freeq_sdk::chatsig::ChatDoc<'a> {
    let mut doc = freeq_sdk::chatsig::ChatDoc::coordination(from, event_id, venue, event_type);
    if let Some(payload) = tags.get("+freeq.at/payload") {
        doc = doc.with_payload(payload);
    }
    if let Some(reference) = tags
        .get("+freeq.at/ref")
        .or_else(|| tags.get("+freeq.at/task-id"))
    {
        doc = doc.with_ref(reference);
    }
    if let Some(evidence) = tags.get("+freeq.at/evidence-type") {
        doc = doc.with_evidence(evidence);
    }
    doc
}

/// The verdict for one relayed task event, of either family.
///
/// `tags` is the tag map as it arrived, `target` the message's delivery
/// target, `sender_did` the account the origin stamped on the S2S message,
/// and `dm_recipient_did` the caller's resolution of a non-channel target to
/// a local DID. `lookup` answers `(did, kid)` with a verifying key when one
/// is on file.
pub(crate) fn relayed_task_verdict<K>(
    tags: &HashMap<String, String>,
    target: &str,
    sender_did: Option<&str>,
    dm_recipient_did: Option<&str>,
    lookup: K,
) -> RelayVerdict
where
    K: Fn(&str, &str) -> Option<ed25519_dalek::VerifyingKey>,
{
    let is_act = crate::connection::act::carries_act_tags(tags);
    if !is_act && !tags.contains_key("+freeq.at/event") {
        return RelayVerdict::Unverifiable("not a task event");
    }

    // ── the mandatory fields, each named when missing ──
    let Some(from) = claimed_signer(tags, sender_did) else {
        return RelayVerdict::Unverifiable("missing from: the event names no actor DID");
    };
    let Some(event_id) = tags
        .get(freeq_sdk::chatsig::EVENT_ID_TAG)
        .or_else(|| tags.get(freeq_sdk::chatsig::EVENT_ID_TAG_BARE))
        .map(String::as_str)
    else {
        return RelayVerdict::Unverifiable("missing id: the event carries no signer-minted id");
    };
    let Some(venue) = venue_for(target, from, dm_recipient_did) else {
        return RelayVerdict::Unverifiable(
            "missing target: no venue resolves for the delivery target",
        );
    };

    // ── the signature, and the key it names ──
    let Some(sig_tag) = tags
        .get("+freeq.at/sig")
        .or_else(|| tags.get("freeq.at/sig"))
        .map(String::as_str)
    else {
        return RelayVerdict::Unverifiable("the event carries no signature");
    };
    let kid = match freeq_sdk::sigtag::parse(sig_tag) {
        Ok((kid, _)) => kid,
        Err(freeq_sdk::sigtag::SigError::UnsupportedAlgorithm(_)) => {
            return RelayVerdict::Unverifiable("unsupported signature algorithm");
        }
        Err(_) => return RelayVerdict::Unverifiable("sig tag is not alg:kid:sig"),
    };
    let Some(key) = lookup(from, kid) else {
        return RelayVerdict::Unverifiable(NO_KEY_ON_FILE);
    };

    // ── the rebuilt document against the key ──
    if is_act {
        let pairs = tags.iter().map(|(k, v)| (k.as_str(), v.as_str()));
        match freeq_sdk::act::verify_act(pairs, &venue, event_id, sig_tag, &key) {
            Ok(()) => RelayVerdict::Valid,
            Err(freeq_sdk::act::ActSigError::SigInvalid) => {
                RelayVerdict::Invalid("signature does not verify over the act document")
            }
            // A kid the key does not hash to, a format problem, no act tags:
            // none of these is evidence about the signed bytes.
            Err(_) => RelayVerdict::Unverifiable("unusable signature tag"),
        }
    } else {
        let event_type = tags
            .get("+freeq.at/event")
            .expect("family checked above")
            .as_str();
        let doc = coordination_doc_from_tags(tags, from, event_id, &venue, event_type);
        match doc.verify(sig_tag, &key) {
            Ok(()) => RelayVerdict::Valid,
            Err(e) if e.is_unverifiable() => RelayVerdict::Unverifiable("unusable signature tag"),
            Err(_) => {
                RelayVerdict::Invalid("signature does not verify over the coordination document")
            }
        }
    }
}

#[cfg(test)]
mod defer_tests {
    //! What the queue does with what it is handed. Every drop is read back
    //! from the list [`DeferQueue::park`] returns rather than from the log
    //! line beside it: that list is what the receive side turns into the
    //! count on the task's row, which is the trace the requirement is about,
    //! and a scoped log-capturing subscriber races with every other test that
    //! installs one.

    use super::*;

    const SIGNER: &str = "did:plc:parked";
    const KID: &str = "somekid";

    fn parked(origin: &str, id: &str) -> ParkedEvent {
        parked_by(origin, id, SIGNER, KID)
    }

    fn parked_by(origin: &str, id: &str, signer: &str, kid: &str) -> ParkedEvent {
        ParkedEvent {
            tags: HashMap::from([("+freeq.at/act-verb".to_string(), "progress".to_string())]),
            target: "#room".to_string(),
            from: "someone!s@remote".to_string(),
            peer_account: Some(signer.to_string()),
            origin: origin.to_string(),
            peer: origin.to_string(),
            peer_declared_act: true,
            event_id: id.to_string(),
            signer: signer.to_string(),
            kid: kid.to_string(),
            seq: 0,
        }
    }

    /// A home server's ruling on somebody's move, on its way to a peer.
    fn parked_receipt(origin: &str, id: &str) -> ParkedEvent {
        let mut event = parked(origin, id);
        event.tags.insert(
            "+freeq.at/act-verb".to_string(),
            freeq_sdk::act_transitions::confirmation_verb().to_string(),
        );
        event
    }

    fn ids(events: &[ParkedEvent]) -> Vec<&str> {
        events.iter().map(|e| e.event_id.as_str()).collect()
    }

    /// The order events verify in is the order they arrived in — a claim that
    /// landed before a completion has to be applied before it.
    #[test]
    fn parked_events_come_back_in_the_order_they_were_parked() {
        let mut q = DeferQueue::new(16, 64);
        for id in ["one", "two", "three"] {
            assert!(q.park(parked("peer-a", id)).is_empty());
        }
        // Interleaved with another origin, to prove the order is the queue's
        // and not each origin's.
        assert!(q.park(parked("peer-b", "four")).is_empty());
        assert_eq!(q.len(), 4);

        let flushed = q.take_for_signer(SIGNER, KID);
        assert_eq!(ids(&flushed), ["one", "two", "three", "four"]);
        assert_eq!(q.len(), 0, "a flush empties what it took");
    }

    /// Only the events the arriving key could settle are taken. Everything
    /// else keeps waiting for its own.
    #[test]
    fn a_key_takes_only_the_events_it_could_settle() {
        let mut q = DeferQueue::new(16, 64);
        assert!(q.park(parked_by("peer-a", "mine", SIGNER, KID)).is_empty());
        assert!(
            q.park(parked_by("peer-a", "other-signer", "did:plc:someone", KID))
                .is_empty()
        );
        assert!(
            q.park(parked_by("peer-a", "other-key", SIGNER, "otherkid"))
                .is_empty()
        );

        assert_eq!(ids(&q.take_for_signer(SIGNER, KID)), ["mine"]);
        assert_eq!(q.len(), 2, "the rest are still waiting");
    }

    /// One peer fills its share and no more. The oldest goes first, and the
    /// eviction is loud: an event that fell off the back was never delivered.
    #[test]
    fn the_two_hundred_and_fifty_seventh_event_from_one_origin_evicts_the_oldest() {
        let mut q = DeferQueue::new(256, 4096);
        for i in 0..256 {
            assert!(q.park(parked("peer-a", &format!("e{i}"))).is_empty());
        }
        assert_eq!(q.len(), 256);

        let dropped = q.park(parked("peer-a", "e256"));

        assert_eq!(
            ids(&dropped),
            ["e0"],
            "the evicted event is handed back, for the trace on the task's row"
        );
        assert_eq!(q.len(), 256, "the ceiling holds");
        let held = q.take_for_signer(SIGNER, KID);
        assert_eq!(
            ids(&held).first(),
            Some(&"e1"),
            "the oldest is what fell off"
        );
        assert_eq!(ids(&held).last(), Some(&"e256"));
    }

    /// And the process has a ceiling of its own: enough peers each within
    /// their own share still cannot fill memory between them.
    #[test]
    fn the_four_thousand_and_ninety_seventh_event_evicts_across_origins() {
        let mut q = DeferQueue::new(256, 4096);
        for peer in 0..16 {
            for i in 0..256 {
                assert!(
                    q.park(parked(&format!("peer-{peer}"), &format!("p{peer}-e{i}")))
                        .is_empty()
                );
            }
        }
        assert_eq!(q.len(), 4096);

        // A seventeenth peer, well inside its own share, still pushes the
        // total over — and what goes is the oldest event anywhere.
        let dropped = q.park(parked("peer-16", "newcomer"));

        assert_eq!(
            ids(&dropped),
            ["p0-e0"],
            "the globally oldest event is the one that fell off"
        );
        assert_eq!(q.len(), 4096);
        let held = q.take_for_signer(SIGNER, KID);
        assert_eq!(ids(&held).first(), Some(&"p0-e1"));
        assert_eq!(ids(&held).last(), Some(&"newcomer"));
    }

    /// A receipt is the home's ruling on somebody's move, and losing one
    /// leaves the people waiting on it with nothing. So it is never what the
    /// queue gives up: the oldest *other* event goes instead, however much
    /// older the receipt is.
    #[test]
    fn a_receipt_is_never_the_event_evicted() {
        let mut q = DeferQueue::new(3, 4096);
        assert!(q.park(parked_receipt("peer-a", "ruling")).is_empty());
        assert!(q.park(parked("peer-a", "older")).is_empty());
        assert!(q.park(parked("peer-a", "newer")).is_empty());

        let dropped = q.park(parked("peer-a", "arrival"));
        assert_eq!(
            ids(&dropped),
            ["older"],
            "the oldest event that is not a receipt is what goes"
        );

        let held = q.take_for_signer(SIGNER, KID);
        assert_eq!(ids(&held), ["ruling", "newer", "arrival"]);
    }

    /// When there is nothing else left to give up, the ceiling still holds —
    /// so the arriving event is turned away rather than a parked ruling thrown
    /// out. This is the ordinary case: what arrives is not a receipt, so no
    /// ruling is weighed against it.
    #[test]
    fn a_bucket_of_receipts_refuses_an_arriving_non_receipt() {
        let mut q = DeferQueue::new(2, 4096);
        assert!(q.park(parked_receipt("peer-a", "ruling-one")).is_empty());
        assert!(q.park(parked_receipt("peer-a", "ruling-two")).is_empty());

        let dropped = q.park(parked("peer-a", "arrival"));

        assert_eq!(ids(&dropped), ["arrival"], "the arrival is what went");
        assert_eq!(q.len(), 2, "and the ceiling held");
        assert_eq!(
            ids(&q.take_for_signer(SIGNER, KID)),
            ["ruling-one", "ruling-two"],
            "both rulings are still waiting"
        );
    }

    /// The one exception. Two rulings are parked, a third arrives, and the
    /// ceiling leaves no way to keep all three. Turning the arrival away would
    /// lose the newest ruling, which is the one most likely to still matter,
    /// so the oldest goes instead — and catch-up is what brings it back.
    #[test]
    fn an_arriving_receipt_evicts_the_oldest_receipt_rather_than_being_turned_away() {
        let mut q = DeferQueue::new(2, 4096);
        assert!(q.park(parked_receipt("peer-a", "ruling-one")).is_empty());
        assert!(q.park(parked_receipt("peer-a", "ruling-two")).is_empty());

        let dropped = q.park(parked_receipt("peer-a", "ruling-three"));

        assert_eq!(
            ids(&dropped),
            ["ruling-one"],
            "the oldest ruling is what went"
        );
        assert_eq!(q.len(), 2, "and the ceiling held");
        assert_eq!(
            ids(&q.take_for_signer(SIGNER, KID)),
            ["ruling-two", "ruling-three"],
            "the two newest rulings are the ones kept"
        );
    }

    /// And the same across the whole queue: the total ceiling is held the same
    /// way, by the oldest ruling anywhere rather than by the arrival.
    #[test]
    fn an_arriving_receipt_evicts_the_oldest_receipt_anywhere_when_the_total_is_full() {
        let mut q = DeferQueue::new(64, 3);
        assert!(q.park(parked_receipt("peer-a", "oldest")).is_empty());
        assert!(q.park(parked_receipt("peer-b", "middle")).is_empty());
        assert!(q.park(parked_receipt("peer-b", "newer")).is_empty());

        let dropped = q.park(parked_receipt("peer-c", "arrival"));

        assert_eq!(ids(&dropped), ["oldest"]);
        assert_eq!(q.len(), 3);
        assert_eq!(
            ids(&q.take_for_signer(SIGNER, KID)),
            ["middle", "newer", "arrival"]
        );
    }

    /// A non-receipt is still preferred to any ruling, wherever it is parked:
    /// the total ceiling looks for one across every peer before it weighs a
    /// receipt, rather than taking whichever peer holds the oldest event.
    #[test]
    fn the_total_ceiling_gives_up_a_non_receipt_anywhere_before_any_receipt() {
        let mut q = DeferQueue::new(64, 3);
        // The oldest event anywhere is a ruling; the only ordinary event is
        // younger, and parked under a different peer.
        assert!(q.park(parked_receipt("peer-a", "oldest-ruling")).is_empty());
        assert!(q.park(parked_receipt("peer-a", "newer-ruling")).is_empty());
        assert!(q.park(parked("peer-b", "ordinary")).is_empty());

        let dropped = q.park(parked_receipt("peer-c", "arrival"));

        assert_eq!(
            ids(&dropped),
            ["ordinary"],
            "the ordinary event goes, though a ruling is older"
        );
        assert_eq!(
            ids(&q.take_for_signer(SIGNER, KID)),
            ["oldest-ruling", "newer-ruling", "arrival"]
        );
    }

    /// The retry schedule: every distinct signer with events waiting is asked
    /// for again, once per backoff step rather than once per sweep, and a key
    /// that arrives stops being asked for.
    #[test]
    fn each_waiting_signer_is_asked_for_again_on_its_own_backoff() {
        let mut q = DeferQueue::new(16, 64);
        assert!(q.park(parked_by("peer-a", "one", SIGNER, KID)).is_empty());
        assert!(q.park(parked_by("peer-a", "two", SIGNER, KID)).is_empty());
        assert!(
            q.park(parked_by("peer-b", "three", "did:plc:other", "otherkid"))
                .is_empty()
        );
        // A signature naming nobody can never be settled by a lookup.
        assert!(q.park(parked_by("peer-a", "nameless", "", "")).is_empty());

        assert!(
            q.retries_due().is_empty(),
            "the caller asked once as each event parked; the first retry waits"
        );

        // Wind every schedule back to now, the way thirty seconds passing
        // would.
        let due = force_due(&mut q);
        assert_eq!(due, 2, "one ask per waiting signer, not one per event");
        assert!(
            q.retries_due().is_empty(),
            "and asking moves each key on to its next step"
        );

        q.take_for_signer(SIGNER, KID);
        assert_eq!(
            force_due(&mut q),
            1,
            "a key that arrived is no longer asked for"
        );
    }

    /// Make every waiting key due now, and return how many were.
    fn force_due(q: &mut DeferQueue) -> usize {
        let now = std::time::Instant::now();
        for retry in q.retries.values_mut() {
            retry.next_attempt = now;
        }
        q.retries_due().len()
    }

    /// Thirty seconds, doubling, ten minutes at the most.
    #[test]
    fn the_backoff_doubles_up_to_its_ceiling() {
        assert_eq!(retry_backoff(0), FIRST_RETRY);
        assert_eq!(retry_backoff(1), FIRST_RETRY * 2);
        assert_eq!(retry_backoff(2), FIRST_RETRY * 4);
        for attempts in 5..64 {
            assert_eq!(
                retry_backoff(attempts),
                MAX_RETRY,
                "the wait stops growing rather than overflowing"
            );
        }
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;

    fn route(event_id: &str, home: &str) -> PendingRoute {
        PendingRoute {
            act_id: "01TASK".to_string(),
            event_id: event_id.to_string(),
            home: home.to_string(),
            message: crate::s2s::S2sMessage::SyncRequest,
            attempts: 0,
            next_attempt: std::time::Instant::now(),
            seq: 0,
        }
    }

    /// Only what is due comes back, oldest first: a claim carried before a
    /// completion has to be asked about before it.
    #[test]
    fn only_due_routes_come_back_and_in_park_order() {
        let mut q = RouteQueue::new(16);
        q.park(route("one", "home"));
        q.park(route("two", "home"));
        let mut later = route("later", "home");
        later.next_attempt = std::time::Instant::now() + MAX_RETRY;
        q.park(later);
        assert_eq!(q.len(), 3);

        let due = q.take_due(std::time::Instant::now());
        assert_eq!(
            due.iter().map(|r| r.event_id.as_str()).collect::<Vec<_>>(),
            ["one", "two"]
        );
        assert_eq!(q.len(), 1, "the one still backing off keeps waiting");
    }

    /// A route for an event already waiting replaces it rather than doubling
    /// it: same event, same destination.
    #[test]
    fn a_second_route_for_one_event_replaces_the_first() {
        let mut q = RouteQueue::new(16);
        q.park(route("one", "home"));
        q.park(route("one", "home"));
        assert_eq!(q.len(), 1);
    }

    /// The ceiling holds, and what falls off is loud: the event stays on file
    /// and unconfirmed, and catch-up is what settles it after that.
    #[test]
    fn the_queue_has_a_ceiling_and_says_when_it_drops_something() {
        let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        struct Writer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Writer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let make = {
            let sink = std::sync::Arc::clone(&sink);
            move || Writer(std::sync::Arc::clone(&sink))
        };
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_writer(make)
                .with_ansi(false)
                .with_max_level(tracing::Level::WARN)
                .finish(),
        );

        let mut q = RouteQueue::new(2);
        q.park(route("one", "home"));
        q.park(route("two", "home"));
        q.park(route("three", "home"));

        assert_eq!(q.len(), 2, "the ceiling holds");
        let held: Vec<String> = q
            .take_due(std::time::Instant::now())
            .into_iter()
            .map(|r| r.event_id)
            .collect();
        assert_eq!(held, ["two", "three"], "the oldest is what fell off");
        let logs = String::from_utf8_lossy(&sink.lock().unwrap()).to_string();
        assert!(logs.contains("one"), "the drop names the event: {logs}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn spec(file: &str) -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../spec")
            .join(file);
        serde_json::from_str(&std::fs::read_to_string(path).expect("spec file on disk"))
            .expect("spec file parses")
    }

    fn key_of(vector: &serde_json::Value) -> ed25519_dalek::VerifyingKey {
        let bytes: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(vector["publicKey"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&bytes).unwrap()
    }

    /// A lookup holding exactly one key, under one (did, kid).
    fn one_key(
        did: &str,
        kid: &str,
        key: ed25519_dalek::VerifyingKey,
    ) -> impl Fn(&str, &str) -> Option<ed25519_dalek::VerifyingKey> {
        let did = did.to_string();
        let kid = kid.to_string();
        move |d, k| (d == did && k == kid).then_some(key)
    }

    /// The wire tag map an act vector's message would carry: the vector's own
    /// tags, plus the event id and the real signature — exactly what the
    /// sender puts on a TAGMSG.
    fn act_wire_tags(vector: &serde_json::Value) -> HashMap<String, String> {
        let mut tags: HashMap<String, String> = vector["tags"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect();
        tags.insert(
            freeq_sdk::chatsig::EVENT_ID_TAG.to_string(),
            vector["id"].as_str().unwrap().to_string(),
        );
        tags.insert(
            "+freeq.at/sig".to_string(),
            vector["sigTag"].as_str().unwrap().to_string(),
        );
        tags
    }

    /// The delivery target and resolved DM recipient for a vector's venue: a
    /// channel venue is its own target; a `dm:` venue is delivered to a
    /// `did:` target that the receive side resolved.
    fn delivery_for(vector: &serde_json::Value, from: &str) -> (String, Option<String>) {
        let venue = vector["target"].as_str().unwrap();
        match venue.strip_prefix("dm:") {
            None => (venue.to_string(), None),
            Some(pair) => {
                let other = pair
                    .split(',')
                    .find(|did| *did != from)
                    .expect("a DM venue names two DIDs");
                (other.to_string(), Some(other.to_string()))
            }
        }
    }

    #[test]
    fn every_act_vector_rebuilds_byte_for_byte_and_verifies_valid() {
        let fixtures = spec("act-signing-vectors.json");
        for vector in fixtures["vectors"].as_array().unwrap() {
            let name = vector["name"].as_str().unwrap();
            let tags = act_wire_tags(vector);
            let venue = vector["target"].as_str().unwrap();
            let msgid = vector["id"].as_str().unwrap();

            // The committed canonical, rebuilt from the wire tags exactly.
            let rebuilt = freeq_sdk::act::act_canonical(
                tags.iter().map(|(k, v)| (k.as_str(), v.as_str())),
                venue,
                msgid,
            )
            .unwrap();
            assert_eq!(rebuilt, vector["canonical"].as_str().unwrap(), "{name}");

            let from = vector["tags"]["+freeq.at/from"].as_str().unwrap();
            let (target, dm_recipient) = delivery_for(vector, from);
            let verdict = relayed_task_verdict(
                &tags,
                &target,
                // The relay origin's account stamp: irrelevant to an act
                // event's key lookup, which uses the document's own from.
                Some("did:plc:relaystamp"),
                dm_recipient.as_deref(),
                one_key(from, vector["kid"].as_str().unwrap(), key_of(vector)),
            );
            assert_eq!(verdict, RelayVerdict::Valid, "{name}");
        }
    }

    #[test]
    fn a_tampered_act_tag_is_invalid() {
        let fixtures = spec("act-signing-vectors.json");
        let vector = &fixtures["vectors"][0];
        let mut tags = act_wire_tags(vector);
        tags.insert(
            "+freeq.at/act-title".to_string(),
            "Cite 4 sources on X".to_string(),
        );
        let from = vector["tags"]["+freeq.at/from"].as_str().unwrap();
        let verdict = relayed_task_verdict(
            &tags,
            vector["target"].as_str().unwrap(),
            None,
            None,
            one_key(from, vector["kid"].as_str().unwrap(), key_of(vector)),
        );
        assert!(
            matches!(verdict, RelayVerdict::Invalid(_)),
            "tampering is evidence, and only tampering reads as invalid: {verdict:?}"
        );
    }

    #[test]
    fn an_unknown_kid_is_unverifiable_never_invalid() {
        let fixtures = spec("act-signing-vectors.json");
        let vector = &fixtures["vectors"][0];
        let tags = act_wire_tags(vector);
        let verdict = relayed_task_verdict(
            &tags,
            vector["target"].as_str().unwrap(),
            None,
            None,
            |_, _| None,
        );
        assert_eq!(verdict, RelayVerdict::Unverifiable(NO_KEY_ON_FILE));
    }

    #[test]
    fn a_missing_from_is_unverifiable_and_names_the_field() {
        let fixtures = spec("act-signing-vectors.json");
        let vector = &fixtures["vectors"][0];
        let mut tags = act_wire_tags(vector);
        tags.remove("+freeq.at/from");
        let verdict = relayed_task_verdict(
            &tags,
            vector["target"].as_str().unwrap(),
            // The account stamp does not stand in for an act event's from:
            // the document names its own actor or it names nobody.
            Some("did:plc:relaystamp"),
            None,
            |_, _| None,
        );
        match verdict {
            RelayVerdict::Unverifiable(why) => assert!(why.contains("from"), "{why}"),
            other => panic!("a missing mandatory field is unverifiable: {other:?}"),
        }
    }

    #[test]
    fn a_missing_id_is_unverifiable_and_names_the_field() {
        let fixtures = spec("act-signing-vectors.json");
        let vector = &fixtures["vectors"][0];
        let mut tags = act_wire_tags(vector);
        tags.remove(freeq_sdk::chatsig::EVENT_ID_TAG);
        let verdict = relayed_task_verdict(
            &tags,
            vector["target"].as_str().unwrap(),
            None,
            None,
            |_, _| None,
        );
        match verdict {
            RelayVerdict::Unverifiable(why) => assert!(why.contains("id"), "{why}"),
            other => panic!("a missing mandatory field is unverifiable: {other:?}"),
        }
    }

    #[test]
    fn an_unresolvable_dm_target_is_unverifiable_and_names_the_field() {
        let fixtures = spec("act-signing-vectors.json");
        let vector = &fixtures["vectors"][0];
        let tags = act_wire_tags(vector);
        // A DM delivery whose recipient this server cannot resolve to a DID:
        // no venue, no document, no verdict about the sender.
        let verdict = relayed_task_verdict(&tags, "somenick", None, None, |_, _| None);
        match verdict {
            RelayVerdict::Unverifiable(why) => assert!(why.contains("target"), "{why}"),
            other => panic!("a missing mandatory field is unverifiable: {other:?}"),
        }
    }

    #[test]
    fn an_unknown_algorithm_is_unverifiable() {
        let fixtures = spec("act-signing-vectors.json");
        let vector = &fixtures["vectors"][0];
        let mut tags = act_wire_tags(vector);
        tags.insert("+freeq.at/sig".to_string(), "rsa:somekid:AAAA".to_string());
        let from = vector["tags"]["+freeq.at/from"].as_str().unwrap();
        let verdict = relayed_task_verdict(
            &tags,
            vector["target"].as_str().unwrap(),
            None,
            None,
            one_key(from, vector["kid"].as_str().unwrap(), key_of(vector)),
        );
        assert_eq!(
            verdict,
            RelayVerdict::Unverifiable("unsupported signature algorithm"),
            "a newer signer is not a forger"
        );
    }

    // ── the stopgap coordination family ──

    /// The wire tag map a coordination vector's TAGMSG would carry.
    fn coordination_wire_tags(vector: &serde_json::Value) -> HashMap<String, String> {
        let input = vector["input"].as_object().unwrap();
        let mut tags = HashMap::new();
        tags.insert(
            "+freeq.at/event".to_string(),
            input["eventType"].as_str().unwrap().to_string(),
        );
        if let Some(payload) = input.get("payload").and_then(|v| v.as_str()) {
            tags.insert("+freeq.at/payload".to_string(), payload.to_string());
        }
        if let Some(reference) = input.get("ref").and_then(|v| v.as_str()) {
            tags.insert("+freeq.at/ref".to_string(), reference.to_string());
        }
        if let Some(evidence) = input.get("evidence").and_then(|v| v.as_str()) {
            tags.insert("+freeq.at/evidence-type".to_string(), evidence.to_string());
        }
        tags.insert(
            freeq_sdk::chatsig::EVENT_ID_TAG.to_string(),
            input["msgid"].as_str().unwrap().to_string(),
        );
        tags.insert(
            "+freeq.at/sig".to_string(),
            vector["sigTag"].as_str().unwrap().to_string(),
        );
        tags
    }

    fn coordination_vectors(fixtures: &serde_json::Value) -> Vec<&serde_json::Value> {
        let vectors = fixtures["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["name"].as_str().unwrap().starts_with("coordination"))
            .collect::<Vec<_>>();
        assert!(
            !vectors.is_empty(),
            "the spec file carries coordination vectors"
        );
        vectors
    }

    #[test]
    fn every_coordination_vector_rebuilds_byte_for_byte_and_verifies_valid() {
        let fixtures = spec("chat-signing-vectors.json");
        for vector in coordination_vectors(&fixtures) {
            let name = vector["name"].as_str().unwrap();
            let input = &vector["input"];
            let tags = coordination_wire_tags(vector);
            let from = input["from"].as_str().unwrap();
            let target = input["target"].as_str().unwrap();

            let venue = freeq_sdk::chatsig::channel_venue(target);
            let doc = coordination_doc_from_tags(
                &tags,
                from,
                input["msgid"].as_str().unwrap(),
                &venue,
                input["eventType"].as_str().unwrap(),
            );
            assert_eq!(
                doc.canonical(),
                vector["canonical"].as_str().unwrap(),
                "{name}"
            );

            let verdict = relayed_task_verdict(
                &tags,
                target,
                Some(from),
                None,
                one_key(from, vector["kid"].as_str().unwrap(), key_of(vector)),
            );
            assert_eq!(verdict, RelayVerdict::Valid, "{name}");
        }
    }

    #[test]
    fn a_tampered_coordination_payload_is_invalid() {
        let fixtures = spec("chat-signing-vectors.json");
        let vector = coordination_vectors(&fixtures)[0];
        let input = &vector["input"];
        let mut tags = coordination_wire_tags(vector);
        tags.insert("+freeq.at/payload".to_string(), "%7B%7D".to_string());
        let from = input["from"].as_str().unwrap();
        let verdict = relayed_task_verdict(
            &tags,
            input["target"].as_str().unwrap(),
            Some(from),
            None,
            one_key(from, vector["kid"].as_str().unwrap(), key_of(vector)),
        );
        assert!(
            matches!(verdict, RelayVerdict::Invalid(_)),
            "an altered covered field is evidence: {verdict:?}"
        );
    }

    #[test]
    fn a_coordination_event_with_no_key_on_file_is_unverifiable() {
        let fixtures = spec("chat-signing-vectors.json");
        let vector = coordination_vectors(&fixtures)[0];
        let input = &vector["input"];
        let verdict = relayed_task_verdict(
            &coordination_wire_tags(vector),
            input["target"].as_str().unwrap(),
            Some(input["from"].as_str().unwrap()),
            None,
            |_, _| None,
        );
        assert_eq!(verdict, RelayVerdict::Unverifiable(NO_KEY_ON_FILE));
    }

    #[test]
    fn a_coordination_event_naming_no_sender_is_unverifiable_and_names_from() {
        let fixtures = spec("chat-signing-vectors.json");
        let vector = coordination_vectors(&fixtures)[0];
        let input = &vector["input"];
        // A guest's relay, or an old peer omitting the account field: the
        // document's from is unknowable, so there is nothing to rebuild.
        let verdict = relayed_task_verdict(
            &coordination_wire_tags(vector),
            input["target"].as_str().unwrap(),
            None,
            None,
            |_, _| None,
        );
        match verdict {
            RelayVerdict::Unverifiable(why) => assert!(why.contains("from"), "{why}"),
            other => panic!("a missing mandatory field is unverifiable: {other:?}"),
        }
    }

    #[test]
    fn a_coordination_event_with_no_id_is_unverifiable_and_names_id() {
        let fixtures = spec("chat-signing-vectors.json");
        let vector = coordination_vectors(&fixtures)[0];
        let input = &vector["input"];
        let mut tags = coordination_wire_tags(vector);
        tags.remove(freeq_sdk::chatsig::EVENT_ID_TAG);
        let verdict = relayed_task_verdict(
            &tags,
            input["target"].as_str().unwrap(),
            Some(input["from"].as_str().unwrap()),
            None,
            |_, _| None,
        );
        match verdict {
            RelayVerdict::Unverifiable(why) => assert!(why.contains("id"), "{why}"),
            other => panic!("a missing mandatory field is unverifiable: {other:?}"),
        }
    }

    #[test]
    fn a_coordination_event_with_an_unknown_algorithm_is_unverifiable() {
        let fixtures = spec("chat-signing-vectors.json");
        let vector = coordination_vectors(&fixtures)[0];
        let input = &vector["input"];
        let mut tags = coordination_wire_tags(vector);
        tags.insert("+freeq.at/sig".to_string(), "rsa:somekid:AAAA".to_string());
        let from = input["from"].as_str().unwrap();
        let verdict = relayed_task_verdict(
            &tags,
            input["target"].as_str().unwrap(),
            Some(from),
            None,
            one_key(from, vector["kid"].as_str().unwrap(), key_of(vector)),
        );
        assert_eq!(
            verdict,
            RelayVerdict::Unverifiable("unsupported signature algorithm")
        );
    }

    /// The act family looks its key up under the document's own `from` tag,
    /// never under the account the relaying server stamped — the signature
    /// claims the document's identity, and a key filed under anyone else's
    /// name must stay a miss.
    #[test]
    fn act_key_lookup_uses_the_documents_own_from_not_the_account_stamp() {
        let fixtures = spec("act-signing-vectors.json");
        let vector = &fixtures["vectors"][0];
        let tags = act_wire_tags(vector);
        let from = vector["tags"]["+freeq.at/from"].as_str().unwrap();
        // The right key, but filed under the account stamp's DID: a miss.
        let verdict = relayed_task_verdict(
            &tags,
            vector["target"].as_str().unwrap(),
            Some("did:plc:relaystamp"),
            None,
            one_key(
                "did:plc:relaystamp",
                vector["kid"].as_str().unwrap(),
                key_of(vector),
            ),
        );
        assert_eq!(verdict, RelayVerdict::Unverifiable(NO_KEY_ON_FILE));
        // Filed under the document's from: found, and valid.
        let verdict = relayed_task_verdict(
            &tags,
            vector["target"].as_str().unwrap(),
            Some("did:plc:relaystamp"),
            None,
            one_key(from, vector["kid"].as_str().unwrap(), key_of(vector)),
        );
        assert_eq!(verdict, RelayVerdict::Valid);
    }
}
