//! Phase 2: Governable Agents — Interactive Demo
//!
//! Walks through governance features one step at a time.
//! Owner says "next" to advance, "quit" to stop.
//!
//! Usage:
//!   cargo run --example demo_phase2 -- --server irc.freeq.at:6697 --tls --channel "#chad-dev"

use anyhow::Result;
use clap::Parser;
use freeq_sdk::auth::KeySigner;
use freeq_sdk::client::{self, ClientHandle, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::event::Event;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

const OWNER: &str = "chadfowler.com";

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "irc.freeq.at:6697")]
    server: String,
    #[arg(long, default_value = "factory")]
    nick: String,
    #[arg(long, default_value = "#chad-dev")]
    channel: String,
    #[arg(long)]
    tls: bool,
}

// ─── Helpers ────────────────────────────────────────

enum OwnerCmd {
    Next,
    Quit,
}

/// Wait for the owner to say "next" or "quit" in the channel.
/// Returns None on timeout/disconnect.
async fn wait_owner(
    rx: &mut mpsc::Receiver<Event>,
    ch: &str,
    secs: u64,
    handle: &ClientHandle,
) -> Option<OwnerCmd> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut last_hb = tokio::time::Instant::now();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let hb_remaining = Duration::from_secs(25).saturating_sub(last_hb.elapsed());
        let wait = remaining.min(hb_remaining);
        match timeout(wait, rx.recv()).await {
            Ok(Some(Event::Message {
                from,
                target,
                text,
                tags,
                ..
            })) => {
                if tags.contains_key("batch") {
                    continue;
                }
                if !target.eq_ignore_ascii_case(ch) || !from.eq_ignore_ascii_case(OWNER) {
                    continue;
                }
                let w = text.trim().to_lowercase();
                let w = w
                    .strip_prefix("factory:")
                    .or_else(|| w.strip_prefix("factory,"))
                    .or_else(|| w.strip_prefix("@factory"))
                    .map(|s| s.trim())
                    .unwrap_or(&w);
                match w {
                    "next" | "n" | "go" | "continue" | "ok" | "yes" | "y" | "ready" => {
                        return Some(OwnerCmd::Next);
                    }
                    "quit" | "q" | "stop" | "exit" => return Some(OwnerCmd::Quit),
                    _ => continue,
                }
            }
            Ok(Some(Event::Disconnected { reason })) => {
                eprintln!("Disconnected: {reason}");
                return Some(OwnerCmd::Quit);
            }
            Ok(Some(_)) => continue,
            Ok(None) => return Some(OwnerCmd::Quit),
            Err(_) => {
                if last_hb.elapsed() >= Duration::from_secs(25) {
                    let _ = handle.raw("HEARTBEAT 60").await;
                    last_hb = tokio::time::Instant::now();
                }
            }
        }
    }
}

/// Send multiple lines with spacing.
async fn say(h: &ClientHandle, ch: &str, lines: &[&str]) {
    for line in lines {
        let _ = h.privmsg(ch, line).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

/// Prompt and wait. Returns false if user said "quit".
async fn prompt(h: &ClientHandle, rx: &mut mpsc::Receiver<Event>, ch: &str) -> bool {
    say(
        h,
        ch,
        &["", "👉 Say 'next' to continue (or 'quit' to stop)."],
    )
    .await;
    match wait_owner(rx, ch, 600, h).await {
        Some(OwnerCmd::Next) => true,
        _ => false,
    }
}

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Drain history/batch messages after joining.
async fn drain(rx: &mut mpsc::Receiver<Event>) {
    tokio::time::sleep(Duration::from_secs(4)).await;
    while let Ok(Some(_)) = timeout(Duration::from_millis(100), rx.recv()).await {}
}

// ─── Main ───────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("warn").init();
    let args = Args::parse();
    let ch = &args.channel;

    // Load or generate persistent ed25519 key
    let key_dir = dirs::home_dir().unwrap().join(".freeq/bots/factory");
    std::fs::create_dir_all(&key_dir)?;
    let key_path = key_dir.join("key.ed25519");
    let private_key = if key_path.exists() {
        PrivateKey::ed25519_from_bytes(&std::fs::read(&key_path)?)?
    } else {
        let key = PrivateKey::generate_ed25519();
        std::fs::write(&key_path, key.secret_bytes())?;
        key
    };
    let did = format!("did:key:{}", private_key.public_key_multibase());
    println!("DID: {did}");
    let signer = KeySigner::new(did.clone(), private_key);

    // Connect
    println!("Connecting to {}...", args.server);
    let config = ConnectConfig {
        server_addr: args.server.clone(),
        nick: args.nick.clone(),
        user: args.nick.clone(),
        realname: "Phase 2 Factory Agent".to_string(),
        tls: args.tls,
        tls_insecure: false,
        web_token: None,
        websocket_url: None,
    };
    let conn = client::establish_connection(&config).await?;
    let (handle, mut events) =
        client::connect_with_stream(conn, config, Some(std::sync::Arc::new(signer)));

    // Wait for registration
    loop {
        match events.recv().await {
            Some(Event::Registered { nick }) => {
                println!("Registered as {nick}");
                break;
            }
            Some(Event::Disconnected { reason }) => {
                eprintln!("Disconnected: {reason}");
                return Ok(());
            }
            _ => continue,
        }
    }

    // Agent setup
    handle.register_agent("agent").await?;
    handle.raw("HEARTBEAT 60").await?;
    handle
        .raw("PRESENCE :state=active;status=Phase 2 demo")
        .await?;

    let provenance = serde_json::json!({
        "actor_did": did,
        "origin_type": "external_import",
        "creator_did": "did:plc:4qsyxmnsblo4luuycm3572bq",
        "implementation_ref": "freeq/demo_phase2.rs@HEAD",
        "source_repo": "https://github.com/freeq-irc/freeq",
        "authority_basis": "Operated by server administrator",
        "revocation_authority": "did:plc:4qsyxmnsblo4luuycm3572bq",
    });
    handle
        .raw(&format!(
            "PROVENANCE :{}",
            b64(&serde_json::to_vec(&provenance)?)
        ))
        .await?;

    handle.join(ch).await?;
    drain(&mut events).await;
    println!("Ready.");

    // ─── Intro ──────────────────────────────────────

    say(
        &handle,
        ch,
        &[
            "👋 Hi! I'm factory -- a demo agent for Phase 2: Governable Agents.",
            "",
            "Phase 1 made agents visible (identity, provenance, heartbeat).",
            "Phase 2 makes them controllable.",
            "",
            "I'll walk through 5 governance features, one at a time.",
        ],
    )
    .await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ─── Step 1: Governance Signals ─────────────────

    say(
        &handle,
        ch,
        &[
            "━━━ 1/5: Governance Signals (Pause / Resume / Revoke) ━━━",
            "",
            "Channel ops can control agents in real time:",
            "",
            "  AGENT PAUSE <nick> [reason]   -- stop the agent",
            "  AGENT RESUME <nick>           -- let it continue",
            "  AGENT REVOKE <nick> [reason]  -- permanently disconnect it",
            "",
            "These are IRC commands. Try it:",
            "  /quote AGENT PAUSE factory too noisy",
            "",
            "I'll react immediately -- watch my presence change in the sidebar.",
            "",
            "(Or just say 'next' and I'll simulate it.)",
        ],
    )
    .await;

    // Wait for either a real pause signal or "next"
    match wait_owner(&mut events, ch, 120, &handle).await {
        Some(OwnerCmd::Quit) => return shutdown(handle).await,
        _ => {} // next or timeout -- simulate
    }

    // Simulate pause/resume
    handle
        .raw("PRESENCE :state=paused;status=Paused by governance demo")
        .await?;
    say(
        &handle,
        ch,
        &[
            "⏸ I'm now paused. Presence state = paused.",
            "(In the sidebar, my status dot should change.)",
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    handle.raw("PRESENCE :state=active;status=Resumed").await?;
    say(
        &handle,
        ch,
        &[
            "▶ Resumed. Presence state = active.",
            "",
            "Key points:",
            "  - Governance signals arrive as IRCv3 TAGMSG (structured)",
            "  - Everyone in the channel sees a human-readable NOTICE",
            "  - Legacy clients (irssi, weechat) see plain text",
            "  - REVOKE is permanent -- the agent disconnects gracefully",
        ],
    )
    .await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ─── Step 2: Approval Flows ────────────────────

    say(
        &handle,
        ch,
        &[
            "━━━ 2/5: Approval Flows ━━━",
            "",
            "Some actions are too risky for an agent to do alone.",
            "The approval flow:",
            "",
            "  1. Agent sends:   APPROVAL_REQUEST #channel :deploy",
            "  2. Server notifies channel ops",
            "  3. Op approves:   AGENT APPROVE factory deploy",
            "  4. Agent receives the approval and proceeds",
            "",
            "Let me demonstrate. I'll request approval to deploy...",
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    handle
        .raw("PRESENCE :state=blocked_on_permission;status=Awaiting deploy approval")
        .await?;
    handle
        .raw(&format!(
            "APPROVAL_REQUEST {ch} :deploy;resource=landing-page-v2"
        ))
        .await?;

    say(
        &handle,
        ch,
        &[
            "",
            "I just sent APPROVAL_REQUEST. My presence is now 'blocked_on_permission'.",
            "",
            "To approve:  /quote AGENT APPROVE factory deploy",
            "To deny:     /quote AGENT DENY factory deploy",
            "(Or say 'next' to simulate approval.)",
        ],
    )
    .await;

    match wait_owner(&mut events, ch, 120, &handle).await {
        Some(OwnerCmd::Quit) => return shutdown(handle).await,
        _ => {}
    }

    handle
        .raw("PRESENCE :state=executing;status=Deploying landing-page-v2")
        .await?;
    say(&handle, ch, &["✅ Approved! Deploying..."]).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    say(
        &handle,
        ch,
        &["🚀 Deploy complete: landing-page-v2 is live."],
    )
    .await;
    handle
        .raw("PRESENCE :state=active;status=Deploy complete")
        .await?;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ─── Step 3: Spawning Child Agents ─────────────

    say(
        &handle,
        ch,
        &[
            "━━━ 3/5: Spawning Child Agents ━━━",
            "",
            "A parent agent can spawn short-lived children for subtasks.",
            "Children inherit capabilities and have a TTL (auto-expire).",
            "",
            "I'll spawn 'factory-worker' with a 5-minute TTL:",
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    handle
        .raw(&format!(
            "AGENT SPAWN {ch} :nick=factory-worker;capabilities=post_message;ttl=300;task=build-css"
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    say(
        &handle,
        ch,
        &[
            "✅ factory-worker has joined!",
            "",
            "It has: nick=factory-worker, caps=post_message, TTL=300s, task=build-css",
            "Click its name in the sidebar to see its identity card.",
            "It shows me (factory) as its parent.",
            "",
            "I can send messages as the child:",
        ],
    )
    .await;

    handle
        .raw(&format!(
            "AGENT MSG factory-worker {ch} :🔨 Working on CSS compilation..."
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    handle
        .raw(&format!(
            "AGENT MSG factory-worker {ch} :✅ CSS compiled. 847 selectors, 12kb output."
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    say(&handle, ch, &["", "Now I'll despawn it:"]).await;
    handle.raw("AGENT DESPAWN factory-worker").await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    say(
        &handle,
        ch,
        &[
            "✅ factory-worker despawned (it QUITs from the channel).",
            "",
            "If I hadn't despawned it, the server would auto-remove it after 300s.",
            "If I disconnect, the server also cleans up all my children.",
        ],
    )
    .await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ─── Step 4: Heartbeat Enforcement ─────────────

    say(
        &handle,
        ch,
        &[
            "━━━ 4/5: Heartbeat Enforcement ━━━",
            "",
            "Phase 1 introduced heartbeat. Phase 2 enforces it.",
            "If an agent stops heartbeating, the server escalates:",
            "",
            "  1x TTL (60s)  -> 'degraded'        (yellow dot)",
            "  2x TTL (120s) -> 'offline'          (gray dot)",
            "  5x TTL (300s) -> force disconnected (gone)",
            "",
            "This prevents zombie agents from occupying channels forever.",
            "The server watches the clock -- it doesn't trust self-reporting.",
        ],
    )
    .await;

    handle.raw("HEARTBEAT 60").await?;
    say(
        &handle,
        ch,
        &[
            "",
            "I just sent HEARTBEAT 60. If I crash, the server detects it",
            "and cleans up automatically. No orphaned bots.",
        ],
    )
    .await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ─── Step 5: Full Governance Loop ──────────────

    say(
        &handle,
        ch,
        &[
            "━━━ 5/5: Full Governance Loop ━━━",
            "",
            "Realistic scenario: you ask me to build and deploy a landing page.",
            "Watch the full lifecycle play out.",
            "",
            "Starting...",
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Accept task
    handle
        .raw("PRESENCE :state=active;status=Accepted task: build landing page")
        .await?;
    say(
        &handle,
        ch,
        &[
            "📋 Task accepted. Plan:",
            "  1. Spawn a worker to build HTML/CSS",
            "  2. Request deploy approval",
            "  3. Deploy (if approved)",
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Spawn worker
    handle
        .raw(&format!(
            "AGENT SPAWN {ch} :nick=factory-builder;capabilities=post_message;ttl=120;task=build-landing-page"
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    handle
        .raw("PRESENCE :state=executing;status=Building (delegated to factory-builder)")
        .await?;
    handle
        .raw(&format!(
            "AGENT MSG factory-builder {ch} :🔨 Generating HTML structure..."
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    handle
        .raw(&format!(
            "AGENT MSG factory-builder {ch} :🎨 Compiling CSS..."
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    handle
        .raw(&format!(
            "AGENT MSG factory-builder {ch} :✅ Build complete. 3 pages, 2 stylesheets."
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Despawn worker
    handle.raw("AGENT DESPAWN factory-builder").await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    say(&handle, ch, &["Worker done. Build artifacts ready."]).await;

    // Request approval
    handle
        .raw("PRESENCE :state=blocked_on_permission;status=Awaiting deploy approval")
        .await?;
    handle
        .raw(&format!(
            "APPROVAL_REQUEST {ch} :deploy;resource=landing-page"
        ))
        .await?;

    say(
        &handle,
        ch,
        &[
            "",
            "🔔 Requesting deploy approval. I'm now blocked.",
            "",
            "Approve:  /quote AGENT APPROVE factory deploy",
            "(Or say 'next' to simulate.)",
        ],
    )
    .await;

    match wait_owner(&mut events, ch, 120, &handle).await {
        Some(OwnerCmd::Quit) => return shutdown(handle).await,
        _ => {}
    }

    // Deploy
    handle
        .raw("PRESENCE :state=executing;status=Deploying landing page")
        .await?;
    say(&handle, ch, &["✅ Approved. Deploying..."]).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    say(
        &handle,
        ch,
        &["🚀 Deployed! https://landing-page.example.com is live."],
    )
    .await;
    handle
        .raw("PRESENCE :state=idle;status=Task complete -- landing page deployed")
        .await?;

    // ─── Summary ────────────────────────────────────

    say(
        &handle,
        ch,
        &[
            "",
            "━━━ Phase 2: Governable Agents -- Summary ━━━",
            "",
            "What we demonstrated:",
            "  1. Pause/Resume/Revoke -- real-time agent governance",
            "  2. Approval flows -- agents ask permission for risky actions",
            "  3. Child agents -- parent spawns workers with TTL",
            "  4. Heartbeat enforcement -- server detects dead agents",
            "  5. Full loop -- task -> spawn worker -> build -> approve -> deploy",
            "",
            "Everything visible as plain text for legacy IRC clients.",
            "Rich clients get structured tags for UI integration.",
            "",
            "Phase 1 answered: 'Who is this agent?'",
            "Phase 2 answers: 'What can it do, and who controls it?'",
            "",
            "👋 factory signing off. Say 'quit' or I'll hang out here.",
        ],
    )
    .await;

    handle
        .raw("PRESENCE :state=idle;status=Demo complete")
        .await?;

    // Idle loop: heartbeat + wait for quit
    let mut last_hb = tokio::time::Instant::now();
    loop {
        let hb_remaining = Duration::from_secs(25).saturating_sub(last_hb.elapsed());
        match timeout(hb_remaining, events.recv()).await {
            Ok(Some(Event::Message {
                from,
                target,
                text,
                tags,
                ..
            })) => {
                if tags.contains_key("batch") {
                    continue;
                }
                if target.eq_ignore_ascii_case(ch) && from.eq_ignore_ascii_case(OWNER) {
                    let w = text.trim().to_lowercase();
                    if matches!(w.as_str(), "quit" | "q" | "stop" | "exit") {
                        break;
                    }
                }
            }
            Ok(Some(Event::Disconnected { reason })) => {
                eprintln!("Disconnected: {reason}");
                return Ok(());
            }
            Ok(_) => {}
            Err(_) => {
                handle.raw("HEARTBEAT 60").await?;
                last_hb = tokio::time::Instant::now();
            }
        }
    }

    shutdown(handle).await
}

async fn shutdown(handle: ClientHandle) -> Result<()> {
    handle
        .raw("PRESENCE :state=offline;status=Shutting down")
        .await?;
    handle.quit(Some("Goodbye!")).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    println!("Done.");
    Ok(())
}
