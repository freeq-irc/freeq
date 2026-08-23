//! The research agent the `docs/agents.md` tutorial builds, as one program.
//!
//! Every Rust sample in that tutorial is a slice of this file, so the guide
//! cannot print code that does not compile or does not run. Read the tutorial
//! for what each part is for; read this to check that it is true.
//!
//! Usage:
//!   cargo run --example research_agent -- --server 127.0.0.1:6889 --channel '#newsroom'
//!
//! The identity is a `did:key` kept at `~/.freeq/bots/newsroom/key.ed25519`,
//! minted on first run.

use anyhow::Result;
use clap::Parser;
use freeq_sdk::act::act_tags;
use freeq_sdk::auth::KeySigner;
use freeq_sdk::client::{self, ClientHandle, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::event::Event;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "irc.freeq.at:6697")]
    server: String,
    #[arg(long, default_value = "#newsroom")]
    channel: String,
    #[arg(long)]
    tls: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Args::parse();

    // Load persistent identity
    let key_dir = dirs::home_dir().unwrap().join(".freeq/bots/newsroom");
    let key_path = key_dir.join("key.ed25519");
    let private_key = PrivateKey::ed25519_from_bytes(&std::fs::read(&key_path)?)?;
    let did = format!("did:key:{}", private_key.public_key_multibase());
    let signer = KeySigner::new(did.clone(), private_key);

    // Connect
    let config = ConnectConfig {
        server_addr: args.server.clone(),
        nick: "newsroom".into(),
        user: "newsroom".into(),
        realname: "Newsroom Research Agent".into(),
        tls: args.tls,
        ..Default::default()
    };

    let conn = client::establish_connection(&config).await?;
    let (handle, mut events) = client::connect_with_stream(conn, config, Some(Arc::new(signer)));

    // Wait for registration
    loop {
        match events.recv().await {
            Some(Event::Registered { nick }) => {
                tracing::info!("Connected as {nick}");
                break;
            }
            Some(Event::Disconnected { reason }) => {
                anyhow::bail!("Disconnected: {reason}");
            }
            _ => continue,
        }
    }

    // Declare ourselves
    setup_agent(&handle, &did, &args.channel).await?;

    // Main loop
    run_agent(&handle, &mut events, &did, &args.channel).await
}

async fn setup_agent(handle: &ClientHandle, did: &str, channel: &str) -> Result<()> {
    // 1. Declare actor class
    handle.register_agent("agent").await?;

    // 2. Submit provenance — who made this, what code is it running
    let provenance = serde_json::json!({
        "actor_did": did,
        "origin_type": "external_import",
        "creator_did": "did:plc:your-did-here",
        "implementation_ref": "newsroom-agent@v0.1.0",
        "source_repo": "https://github.com/you/newsroom-agent",
        "authority_basis": "Operated by channel administrator",
        "revocation_authority": "did:plc:your-did-here",
    });
    handle.submit_provenance(&provenance).await?;

    // 3. Set initial presence
    handle
        .set_presence("online", Some("Ready for assignments"), None)
        .await?;

    // 4. Start heartbeat — proves liveness, at twice the interval as its TTL
    handle.start_heartbeat(Duration::from_secs(30));

    // 5. Join the channel
    handle.join(channel).await?;

    Ok(())
}

async fn run_agent(
    handle: &ClientHandle,
    events: &mut tokio::sync::mpsc::Receiver<Event>,
    did: &str,
    channel: &str,
) -> Result<()> {
    loop {
        let event = match events.recv().await {
            Some(e) => e,
            None => break,
        };

        match event {
            Event::Message {
                from,
                target,
                text,
                tags,
                ..
            } => {
                // Skip history replay (messages with batch tags)
                if tags.contains_key("batch") {
                    continue;
                }
                // Only respond in our channel
                if !target.eq_ignore_ascii_case(channel) {
                    continue;
                }

                // Check for commands directed at us. The prefix is matched
                // case-insensitively; what follows is passed on as written,
                // because a topic is somebody's words.
                let text = text.trim();
                let lower = text.to_lowercase();
                if lower.starts_with("newsroom:") || lower.starts_with("newsroom,") {
                    let cmd = text["newsroom:".len()..].trim();
                    handle_command(handle, channel, did, &from, cmd).await?;
                }
            }

            Event::TagMsg { from, tags, .. } => {
                // Governance and approvals both arrive on this tag; the
                // approval answers name themselves.
                match tags.get("+freeq.at/governance").map(String::as_str) {
                    Some(answer @ ("approval_granted" | "approval_denied")) => {
                        handle_approval(handle, channel, did, answer, &tags).await?;
                    }
                    Some(signal) => {
                        handle_governance(handle, channel, signal, &from).await?;
                    }
                    None => {}
                }
            }

            Event::Disconnected { reason } => {
                tracing::warn!("Disconnected: {reason}");
                break;
            }

            _ => {}
        }
    }

    Ok(())
}

use std::sync::atomic::{AtomicBool, Ordering};

static PAUSED: AtomicBool = AtomicBool::new(false);

async fn handle_governance(
    handle: &ClientHandle,
    channel: &str,
    signal: &str,
    from: &str,
) -> Result<()> {
    match signal {
        "pause" => {
            PAUSED.store(true, Ordering::SeqCst);
            handle
                .set_presence("paused", Some(&format!("Paused by {from}")), None)
                .await?;
            handle
                .privmsg(channel, &format!("⏸ Paused by {from}. Standing by."))
                .await?;
        }
        "resume" => {
            PAUSED.store(false, Ordering::SeqCst);
            handle.set_presence("active", Some("Resumed"), None).await?;
            handle
                .privmsg(channel, &format!("▶ Resumed by {from}."))
                .await?;
        }
        "revoke" => {
            handle
                .privmsg(channel, "🚫 Revoked. Disconnecting.")
                .await?;
            handle.quit(Some("Revoked by operator")).await?;
            std::process::exit(0);
        }
        _ => {}
    }
    Ok(())
}

async fn handle_command(
    handle: &ClientHandle,
    channel: &str,
    did: &str,
    from: &str,
    cmd: &str,
) -> Result<()> {
    // Respect governance
    if PAUSED.load(Ordering::SeqCst) {
        handle
            .privmsg(channel, "⏸ I'm currently paused. Ask an op to resume me.")
            .await?;
        return Ok(());
    }

    if let Some(topic) = cmd
        .strip_prefix("write about ")
        .or_else(|| cmd.strip_prefix("research "))
    {
        research_and_write(handle, channel, did, from, topic).await?;
    } else if cmd == "status" {
        handle
            .privmsg(channel, "📊 Online and ready. No active tasks.")
            .await?;
    } else {
        handle
            .privmsg(
                channel,
                "Commands: newsroom: write about <topic> | newsroom: status",
            )
            .await?;
    }

    Ok(())
}

async fn research_and_write(
    handle: &ClientHandle,
    channel: &str,
    did: &str,
    requester: &str,
    topic: &str,
) -> Result<()> {
    handle
        .set_presence("executing", Some(&format!("Researching: {topic}")), None)
        .await?;

    // Open the task, directed at ourselves, and take it. An opener names no
    // action — its own event id becomes the action's — which is why `None`
    // stands where every later move names the task.
    let deadline = (now() + 3600).to_string();
    let title = format!("Research and write article: {topic}");
    let task_id = handle
        .send_act(
            channel,
            act_tags(
                "handoff",
                "offer",
                None,
                did,
                &[
                    ("title", &title),
                    ("to", did),
                    // A hint about what the work needs. Stored and filterable
                    // — never a gate: nothing checks it, and an open offer
                    // anyone may claim is the same call without `to`.
                    ("caps", "freeq.at/research-and-write"),
                    // Unix seconds. How long the offer stands, not how long
                    // the work may take.
                    ("deadline", &deadline),
                ],
            ),
            None,
        )
        .await?;
    let asked_by = format!("asked by {requester}");
    handle
        .send_act(
            channel,
            act_tags(
                "handoff",
                "accept",
                Some(&task_id),
                did,
                &[("note", &asked_by)],
            ),
            None,
        )
        .await?;

    // Gather sources
    let searching = format!("searching for sources on {topic}");
    handle
        .send_act(
            channel,
            act_tags(
                "handoff",
                "progress",
                Some(&task_id),
                did,
                &[("note", &searching)],
            ),
            None,
        )
        .await?;

    let sources = search_for_sources(topic).await?;

    // Check governance between steps
    if PAUSED.load(Ordering::SeqCst) {
        handle
            .send_act(
                channel,
                act_tags(
                    "handoff",
                    "progress",
                    Some(&task_id),
                    did,
                    &[("note", "paused during research")],
                ),
                None,
            )
            .await?;
        return Ok(());
    }

    // Attach what the sources were checked against: where the check lives,
    // and a hash of what was there when this was signed.
    let report = quality_report(&sources);
    let checked = format!(
        "source quality: {}/{} verified",
        report.verified,
        sources.len()
    );
    let report_hash = format!("sha256:{}", report.sha256);
    handle
        .send_act(
            channel,
            act_tags(
                "handoff",
                "progress",
                Some(&task_id),
                did,
                &[
                    ("note", &checked),
                    ("ctx", &report.url),
                    ("ctx-h", &report_hash),
                ],
            ),
            None,
        )
        .await?;

    // Write the draft
    handle
        .send_act(
            channel,
            act_tags(
                "handoff",
                "progress",
                Some(&task_id),
                did,
                &[("note", "writing the article draft")],
            ),
            None,
        )
        .await?;

    let draft = write_draft(topic, &sources).await?;

    // Post the draft to the channel for people to read
    handle
        .privmsg(
            channel,
            &format!(
                "📝 Draft ready for review — **{}**: {}",
                draft.title, draft.summary
            ),
        )
        .await?;

    // Request publish approval, and remember what it is for
    handle
        .set_presence(
            "waiting_for_input",
            Some("Waiting for publish approval"),
            Some(&task_id),
        )
        .await?;
    *IN_FLIGHT.lock().unwrap() = Some(Job {
        task_id,
        draft: draft.clone(),
    });

    handle
        .request_approval(
            channel,
            "publish",
            Some(&format!("Publish article: {}", draft.title)),
        )
        .await?;

    handle
        .privmsg(
            channel,
            "👉 To publish: /quote AGENT APPROVE newsroom publish",
        )
        .await?;

    // The approval answer finishes the task.

    Ok(())
}

async fn handle_approval(
    handle: &ClientHandle,
    channel: &str,
    did: &str,
    answer: &str,
    tags: &std::collections::HashMap<String, String>,
) -> Result<()> {
    let Some(job) = IN_FLIGHT.lock().unwrap().take() else {
        return Ok(());
    };
    match answer {
        "approval_granted" => {
            handle
                .set_presence("executing", Some("Publishing article"), None)
                .await?;

            // Publish the draft (your blog API, AT Protocol post, etc.)
            let published = publish_to_blog(&job.draft).await?;

            // Finish the task, pointing at what was published and a hash of it
            let note = format!("published: {}", job.draft.title);
            let published_hash = format!("sha256:{}", published.sha256);
            handle
                .send_act(
                    channel,
                    act_tags(
                        "handoff",
                        "complete",
                        Some(&job.task_id),
                        did,
                        &[
                            ("note", &note),
                            ("ctx", &published.url),
                            ("ctx-h", &published_hash),
                        ],
                    ),
                    None,
                )
                .await?;

            handle
                .set_presence("idle", Some("Task complete"), None)
                .await?;
        }
        "approval_denied" => {
            let reason = tags
                .get("+freeq.at/reason")
                .map(|s| s.as_str())
                .unwrap_or("no reason given");
            let note = format!("publish denied: {reason}");
            handle
                .send_act(
                    channel,
                    act_tags(
                        "handoff",
                        "fail",
                        Some(&job.task_id),
                        did,
                        &[("note", &note)],
                    ),
                    None,
                )
                .await?;
            handle
                .set_presence("idle", Some("Publish denied"), None)
                .await?;
        }
        _ => {}
    }
    Ok(())
}

#[allow(dead_code)]
async fn deep_research(handle: &ClientHandle, channel: &str, task_id: &str) -> Result<()> {
    // Spawn a source-checker worker
    handle
        .spawn_agent(
            channel,
            "newsroom-checker",
            &["post_message"],
            Some(120), // 2 minute TTL
            Some(task_id),
        )
        .await?;

    // The worker reports back through the parent
    handle
        .send_as_child(
            "newsroom-checker",
            channel,
            "🔍 Verifying source credibility...",
        )
        .await?;

    // ... worker does its thing ...

    handle
        .send_as_child(
            "newsroom-checker",
            channel,
            "✅ All 3 sources verified: Reuters (tier 1), Nature (tier 1), arXiv (preprint)",
        )
        .await?;

    // Clean up
    handle.despawn_agent("newsroom-checker").await?;

    Ok(())
}

// ── The parts the tutorial leaves to you ───────────────────────────
//
// Everything below stands in for the work a real newsroom agent would do.
// The lifecycle above is the part the tutorial is about; these are here so it
// compiles and runs end to end.

use std::sync::Mutex;

/// The task in flight, and what the approval answer will finish.
struct Job {
    task_id: String,
    draft: Draft,
}

static IN_FLIGHT: Mutex<Option<Job>> = Mutex::new(None);

#[derive(Clone)]
struct Draft {
    title: String,
    summary: String,
}

struct Source {
    url: String,
}

struct Report {
    verified: usize,
    url: String,
    sha256: String,
}

struct Published {
    url: String,
    sha256: String,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn digest(bytes: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes.as_bytes()))
}

async fn search_for_sources(topic: &str) -> Result<Vec<Source>> {
    // Stands in for work that takes a moment. It also keeps the agent inside
    // the server's flood allowance — see the tutorial's note on pacing.
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(vec![
        Source {
            url: format!("https://reuters.com/{}", slug(topic)),
        },
        Source {
            url: format!("https://nature.com/{}", slug(topic)),
        },
        Source {
            url: format!("https://arxiv.org/abs/{}", slug(topic)),
        },
    ])
}

fn quality_report(sources: &[Source]) -> Report {
    let body = sources
        .iter()
        .map(|s| s.url.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    Report {
        verified: sources.len(),
        url: "https://example.com/newsroom/source-check".to_string(),
        sha256: digest(&body),
    }
}

async fn write_draft(topic: &str, sources: &[Source]) -> Result<Draft> {
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(Draft {
        title: format!("What we know about {topic}"),
        summary: format!(
            "A short piece on {topic}, drawn from {} sources.",
            sources.len()
        ),
    })
}

async fn publish_to_blog(draft: &Draft) -> Result<Published> {
    tokio::time::sleep(Duration::from_secs(2)).await;
    let body = format!("{}\n\n{}", draft.title, draft.summary);
    Ok(Published {
        url: format!("https://blog.example.com/{}", slug(&draft.title)),
        sha256: digest(&body),
    })
}

fn slug(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .to_lowercase()
}
