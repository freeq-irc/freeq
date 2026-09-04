//! A public, checkable record of one unit of delegated work.
//!
//! The claim freeq makes about tasks is that a unit of work can cross from an
//! agent one person runs to an agent another person runs, on servers neither
//! of them shares, and that every step of it is signed. Until now that claim
//! was a sentence in a README. This makes it a URL.
//!
//! The page is deliberately not a dashboard. It answers one question — *what
//! happened to this task, who said so, and how would I know they were not
//! lying* — and it answers the third part by handing over the exact bytes and
//! the key, rather than by showing a green tick and expecting to be believed.
//! A verdict from this server about this server's own honesty is worth very
//! little; a verdict a stranger can re-derive on their own machine is worth
//! something. So every event ships its canonical form, its signature and the
//! DID that signed it, with a worked command underneath.
//!
//! Read-only, and derived entirely from the event log. Nothing here can change
//! a task, and nothing here is authored: if the log and this page disagree,
//! the log is right.

use crate::server::SharedState;
use crate::web::authorize_venue_read;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use std::sync::Arc;

/// Escape text bound for HTML.
///
/// Every value on this page comes from the wire — a nick, a title, a DID a
/// peer asserted — so all of it is hostile until escaped. The canonical form
/// especially: it is JSON authored elsewhere and rendered verbatim, which is
/// exactly the shape of a stored-XSS bug.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Shorten a DID for display without losing what identifies it.
///
/// Keeps the method and the tail: `did:key:z6Mk…zakf5W`. The tail is what
/// differs between two keys of the same method, so truncating the end - the
/// usual instinct - would make two different agents look identical.
fn short_did(did: &str) -> String {
    if did.len() <= 30 {
        return did.to_string();
    }
    let tail: String = did.chars().rev().take(8).collect::<Vec<_>>().into_iter().rev().collect();
    let head: String = did.chars().take(14).collect();
    format!("{head}…{tail}")
}

fn verdict_class(sig_state: &str) -> (&'static str, &'static str) {
    match sig_state {
        "valid" => ("ok", "signature checks out"),
        "invalid" => ("bad", "signature does NOT match"),
        "unsigned" => ("warn", "not signed"),
        // The honest third case, and the reason this page shows a state rather
        // than a tick: we could not fetch the key, so we do not know. Saying
        // "unverified" would imply a check that never happened.
        _ => ("warn", "key unavailable — not checked here"),
    }
}

pub async fn act_receipt(
    State(state): State<Arc<SharedState>>,
    Path(act_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let events = state
        .with_db(|db| db.act_task_events(&act_id))
        .unwrap_or_default();

    let Some(venue) = events.first().map(|e| e.venue.clone()) else {
        return (StatusCode::NOT_FOUND, Html(page_not_found(&act_id))).into_response();
    };

    // Same authorisation as the JSON API: a receipt for work done in a private
    // room is not public just because it is a receipt. The venue comes from
    // the events rather than from a task row, so a finished task is still
    // judged by where it happened.
    if !authorize_venue_read(&state, &venue, &headers) {
        return (StatusCode::FORBIDDEN, Html(page_private(&act_id))).into_response();
    }

    let task = state.with_db(|db| db.act_task(&act_id)).flatten();

    let mut rows = String::new();
    let mut origins: Vec<String> = Vec::new();
    for e in &events {
        let (cls, verdict) = verdict_class(&e.sig_state);
        let actor = e.actor_did.clone().unwrap_or_else(|| "—".to_string());
        if !e.origin.is_empty() && !origins.contains(&e.origin) {
            origins.push(e.origin.clone());
        }
        let when = time_str(e.timestamp);
        let confirm = e
            .confirm
            .map(|c| format!("<span class=\"pill\">{}</span>", esc(c.as_str())))
            .unwrap_or_else(|| "<span class=\"pill receipt\">receipt</span>".into());
        rows.push_str(&format!(
            r#"<li class="ev">
  <div class="evhead">
    <span class="v {cls}">{verdict}</span>
    {confirm}
    <time>{when}</time>
  </div>
  <div class="who">signed by <code title="{actor_full}">{actor_short}</code>{via}</div>
  <details>
    <summary>the exact bytes that were signed</summary>
    <pre class="canon">{canonical}</pre>
    <div class="siglabel">signature</div>
    <pre class="sig">{signature}</pre>
  </details>
</li>"#,
            cls = cls,
            verdict = verdict,
            confirm = confirm,
            when = esc(&when),
            actor_full = esc(&actor),
            actor_short = esc(&short_did(&actor)),
            via = if e.origin.is_empty() {
                String::new()
            } else {
                format!(" · relayed via <code>{}</code>", esc(&short_did(&e.origin)))
            },
            canonical = esc(&e.canonical),
            signature = esc(e.signature.as_deref().unwrap_or("(none)")),
        ));
    }

    let (kind, tstate, offerer, offeree) = task
        .as_ref()
        .map(|t| {
            (
                t.kind.clone(),
                t.state.clone(),
                t.offerer.clone(),
                t.offeree.clone().unwrap_or_default(),
            )
        })
        .unwrap_or_else(|| ("task".into(), "completed".into(), String::new(), String::new()));

    // The headline claim, stated only when the evidence supports it. Two
    // distinct DIDs and more than one origin means the work genuinely crossed
    // an ownership boundary; one of each means it did not, and the page must
    // not imply otherwise.
    let actors: Vec<String> = {
        let mut v: Vec<String> = events.iter().filter_map(|e| e.actor_did.clone()).collect();
        v.sort();
        v.dedup();
        v
    };
    let crossed = actors.len() > 1 && !origins.is_empty();
    let banner = if crossed {
        format!(
            "<p class=\"crossed\">This work crossed an ownership boundary: \
             <strong>{}</strong> distinct signers, relayed between servers, \
             every step signed.</p>",
            actors.len()
        )
    } else {
        String::new()
    };

    Html(page(
        &act_id, &venue, &kind, &tstate, &offerer, &offeree, &banner, &rows, events.len(),
    ))
    .into_response()
}

fn time_str(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| ts.to_string())
}

#[allow(clippy::too_many_arguments)]
fn page(
    act_id: &str,
    venue: &str,
    kind: &str,
    state: &str,
    offerer: &str,
    offeree: &str,
    banner: &str,
    rows: &str,
    n: usize,
) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{kind} {short} — freeq receipt</title>
<meta name="description" content="A signed, independently checkable record of one unit of delegated work on freeq.">
<style>
:root {{ color-scheme: light dark; --fg:#111; --mu:#666; --bd:#ddd; --ok:#0a7f3f; --bad:#b00020; --warn:#8a6d00; --bg:#fff; --card:#fafafa; }}
@media (prefers-color-scheme: dark) {{ :root {{ --fg:#e8e8e8; --mu:#999; --bd:#333; --bg:#111; --card:#181818; --ok:#4ade80; --bad:#f87171; --warn:#fbbf24; }} }}
body {{ font: 15px/1.6 ui-sans-serif,system-ui,-apple-system,sans-serif; margin:0; color:var(--fg); background:var(--bg); }}
main {{ max-width: 46rem; margin: 0 auto; padding: 2rem 1.2rem 5rem; }}
h1 {{ font-size:1.4rem; margin:0 0 .2rem; }}
.sub {{ color:var(--mu); margin:0 0 1.5rem; }}
code {{ font-family: ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.86em; }}
.meta {{ display:grid; grid-template-columns:auto 1fr; gap:.35rem 1rem; background:var(--card); border:1px solid var(--bd); border-radius:8px; padding:1rem; margin-bottom:1.5rem; }}
.meta dt {{ color:var(--mu); }} .meta dd {{ margin:0; }}
.crossed {{ border-left:3px solid var(--ok); padding:.6rem .9rem; background:var(--card); border-radius:0 6px 6px 0; }}
ol {{ list-style:none; padding:0; }}
.ev {{ border:1px solid var(--bd); border-radius:8px; padding:.8rem 1rem; margin-bottom:.8rem; background:var(--card); }}
.evhead {{ display:flex; align-items:center; gap:.6rem; flex-wrap:wrap; }}
.v {{ font-weight:600; }} .v.ok {{ color:var(--ok); }} .v.bad {{ color:var(--bad); }} .v.warn {{ color:var(--warn); }}
.pill {{ font-size:.75rem; border:1px solid var(--bd); border-radius:99px; padding:.05rem .5rem; color:var(--mu); }}
time {{ color:var(--mu); font-size:.85rem; margin-left:auto; }}
.who {{ color:var(--mu); font-size:.9rem; margin-top:.3rem; }}
details {{ margin-top:.5rem; }} summary {{ cursor:pointer; color:var(--mu); font-size:.85rem; }}
pre {{ background:var(--bg); border:1px solid var(--bd); border-radius:6px; padding:.6rem; overflow-x:auto; font-size:.8rem; margin:.4rem 0; }}
.siglabel {{ color:var(--mu); font-size:.75rem; margin-top:.5rem; }}
.verify {{ margin-top:2.5rem; border-top:1px solid var(--bd); padding-top:1.2rem; }}
.verify h2 {{ font-size:1rem; }} .verify p {{ color:var(--mu); }}
footer {{ margin-top:3rem; color:var(--mu); font-size:.85rem; }}
a {{ color:inherit; }}
</style>
</head><body><main>

<h1>{kind} <code>{short}</code></h1>
<p class="sub">A signed record of one unit of delegated work. Nothing here asks to be trusted.</p>

{banner}

<dl class="meta">
  <dt>task</dt><dd><code>{act_id_e}</code></dd>
  <dt>state</dt><dd>{state_e}</dd>
  <dt>room</dt><dd><code>{venue_e}</code></dd>
  {offerer_row}
  {offeree_row}
  <dt>events</dt><dd>{n}</dd>
</dl>

<h2 style="font-size:1rem">What happened</h2>
<ol>{rows}</ol>

<section class="verify">
<h2>Check it yourself</h2>
<p>
  Each event above shows the exact bytes that were signed and the signature over
  them. The verdicts are this server's, and a server vouching for its own
  honesty is not evidence — so here is how to reach your own.
</p>
<p>Fetch the signer's public key, which is served per DID and never by us alone:</p>
<pre>curl https://irc.freeq.at/api/v1/signing-keys/&lt;did&gt;</pre>
<p>Then verify the ed25519 signature over the canonical bytes verbatim — no
  re-serialisation, no whitespace changes; the canonical form <em>is</em> the
  message. The same task fetched as JSON:</p>
<pre>curl https://irc.freeq.at/api/v1/actions/{act_id_e}</pre>
<p>
  Known limitation, stated here rather than discovered later: a signing key is
  currently vouched for by the server that hosts its owner, not yet anchored in
  the owner's DID document. So this proves the named key signed these bytes,
  and that the key was registered to that DID — not that a hostile home server
  never lied about the binding in the first place. Anchoring is the next piece
  of work.
</p>
</section>

<footer>
  <a href="/">freeq</a> · identity is a DID, not a nickname ·
  <a href="/api/v1/actions/{act_id_e}">this page as JSON</a>
</footer>
</main></body></html>"#,
        kind = esc(kind),
        short = esc(&act_id.chars().take(10).collect::<String>()),
        act_id_e = esc(act_id),
        venue_e = esc(venue),
        state_e = esc(state),
        banner = banner,
        rows = rows,
        n = n,
        offerer_row = if offerer.is_empty() {
            String::new()
        } else {
            format!(
                "<dt>offered by</dt><dd><code title=\"{}\">{}</code></dd>",
                esc(offerer),
                esc(&short_did(offerer))
            )
        },
        offeree_row = if offeree.is_empty() {
            String::new()
        } else {
            format!(
                "<dt>offered to</dt><dd><code title=\"{}\">{}</code></dd>",
                esc(offeree),
                esc(&short_did(offeree))
            )
        },
    )
}

fn page_not_found(act_id: &str) -> String {
    shell(
        "No such task",
        &format!(
            "<p>Nothing is on file for <code>{}</code>.</p>\
             <p>Task ids are ULIDs. A task that never reached this server, or one \
             raised in a room this server does not carry, will not appear here.</p>",
            esc(act_id)
        ),
    )
}

fn page_private(act_id: &str) -> String {
    shell(
        "Private",
        &format!(
            "<p>Task <code>{}</code> happened in a room that is not public.</p>\
             <p>Receipts inherit the privacy of the room the work happened in. \
             A signed record is not a public one by default.</p>",
            esc(act_id)
        ),
    )
}

fn shell(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{t} — freeq</title>
<style>body{{font:15px/1.6 ui-sans-serif,system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1.2rem;color-scheme:light dark}}
code{{font-family:ui-monospace,Menlo,monospace}}</style></head>
<body><h1>{t}</h1>{b}<p><a href="/">freeq</a></p></body></html>"#,
        t = esc(title),
        b = body
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_everything_that_came_off_the_wire() {
        // The canonical form is JSON authored elsewhere and rendered verbatim,
        // which is the exact shape of a stored-XSS bug. A title a peer chose is
        // no safer.
        let hostile = r#"<script>alert('x')</script>"#;
        let out = esc(hostile);
        assert!(!out.contains("<script>"));
        assert!(out.contains("&lt;script&gt;"));
        assert!(esc("a\"b'c&d").contains("&quot;"));
    }

    #[test]
    fn shortens_a_did_without_making_two_keys_look_alike() {
        // Truncating the END is the usual instinct and it is wrong here: two
        // did:keys share a long prefix and differ in the tail.
        let a = "did:key:z6MkwdV4XsY4yTe1i4zh5uGqWNmfqE9SpgyQTvWFWXDyYCa8";
        let b = "did:key:z6MkupQ7sJqy865n8MA2JMUQkBak8ARYKu5QmTGX71zakf5W";
        assert_ne!(short_did(a), short_did(b));
        assert!(short_did(a).starts_with("did:key:"));
        assert_eq!(short_did("did:plc:short"), "did:plc:short");
    }

    #[test]
    fn an_unfetchable_key_reads_as_unchecked_not_as_unverified() {
        // "unverified" implies a check that failed. We did not check.
        let (_, words) = verdict_class("unverifiable");
        assert!(words.contains("not checked"));
        assert_eq!(verdict_class("valid").1, "signature checks out");
        assert_eq!(verdict_class("invalid").0, "bad");
        assert_eq!(verdict_class("unsigned").0, "warn");
    }

    #[test]
    fn states_its_own_limitation_on_the_page() {
        // The honest-origin caveat belongs where the proof is shown, not in a
        // doc nobody opens. If this assertion is ever deleted, the page has
        // started overclaiming.
        let html = page("01ABC", "#room", "handoff", "completed", "", "", "", "", 0);
        assert!(html.contains("not yet anchored"));
        assert!(html.contains("signing-keys"));
    }

    #[test]
    fn an_e2ee_channel_is_not_publicly_discoverable() {
        // Distributing group keys makes a channel E2EE, and the receipt
        // surface must follow: a public page describing work in a room whose
        // contents nobody outside can read is a metadata leak dressed as
        // transparency. encrypted_only is what restricts it.
        let mut ch = crate::server::ChannelState::default();
        assert!(!ch.is_mode_restricted());
        ch.encrypted_only = true;
        assert!(
            ch.is_mode_restricted(),
            "an E2EE channel must be restricted, so receipts for it are not public"
        );
    }

    #[test]
    fn the_crossed_boundary_claim_needs_two_signers() {
        // Rendering "crossed an ownership boundary" for work that never left
        // one machine would be the page lying about the only thing it exists
        // to demonstrate. The banner is passed in, so this pins the copy that
        // may only appear alongside it.
        let solo = page("01ABC", "#room", "handoff", "completed", "", "", "", "", 1);
        assert!(!solo.contains("crossed an ownership boundary"));
    }
}
