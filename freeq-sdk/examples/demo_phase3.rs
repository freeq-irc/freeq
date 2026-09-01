//! Phase 3: Coordinated Work — Interactive Demo
//!
//! Simulates a factory agent building a todo app with signed act events,
//! evidence attachments, and an audit trail. Owner says "next" to advance, "quit" to stop.
//!
//! Usage:
//!   cargo run --example demo_phase3 -- --server irc.freeq.at:6697 --tls --channel "#chad-dev"

use anyhow::Result;
use clap::Parser;
use freeq_sdk::act::{act_tags, ctx_hash};
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
        // Heartbeat every 25s while waiting
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
                // Timeout — send heartbeat if due
                if last_hb.elapsed() >= Duration::from_secs(25) {
                    let _ = handle.raw("HEARTBEAT 60").await;
                    last_hb = tokio::time::Instant::now();
                }
            }
        }
    }
}

async fn say(h: &ClientHandle, ch: &str, lines: &[&str]) {
    for line in lines {
        let _ = h.privmsg(ch, line).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

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

async fn drain(rx: &mut mpsc::Receiver<Event>) {
    tokio::time::sleep(Duration::from_secs(4)).await;
    while let Ok(Some(_)) = timeout(Duration::from_millis(100), rx.recv()).await {}
}

/// Send one act event: the signed TAGMSG that *is* the event, plus the line
/// people read beside it. Returns the event's id — which, for an opener, is
/// the task's id for the rest of its life.
async fn act(
    h: &ClientHandle,
    ch: &str,
    did: &str,
    verb: &str,
    task: Option<&str>,
    fields: &[(&str, &str)],
    human_msg: &str,
) -> String {
    let id = match h
        .send_act(
            ch,
            act_tags("handoff", verb, task, did, fields),
            Some(human_msg),
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            eprintln!("act {verb} refused: {e}");
            String::new()
        }
    };
    tokio::time::sleep(Duration::from_millis(600)).await;
    id
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

    println!("Connecting to {}...", args.server);
    let config = ConnectConfig {
        server_addr: args.server.clone(),
        nick: args.nick.clone(),
        user: args.nick.clone(),
        realname: "Phase 3 Factory Agent".to_string(),
        tls: args.tls,
        tls_insecure: false,
        web_token: None,
        websocket_url: None,
    };
    let conn = client::establish_connection(&config).await?;
    let (handle, mut events) =
        client::connect_with_stream(conn, config, Some(std::sync::Arc::new(signer)));

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
        .raw("PRESENCE :state=active;status=Phase 3 demo")
        .await?;
    let provenance = serde_json::json!({
        "actor_did": did,
        "origin_type": "external_import",
        "creator_did": "did:plc:4qsyxmnsblo4luuycm3572bq",
        "implementation_ref": "freeq/demo_phase3.rs@HEAD",
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
            "👋 Hi! I'm factory -- demo agent for Phase 3: Coordinated Work.",
            "",
            "Phase 1: agents are visible (identity, provenance)",
            "Phase 2: agents are controllable (pause, approve, spawn)",
            "Phase 3: agent work is structured and auditable.",
            "",
            "I'll walk through 4 features, then do a live end-to-end build.",
        ],
    )
    .await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ─── Step 1: Typed Coordination Events ──────────

    say(
        &handle,
        ch,
        &[
            "━━━ 1/4: Typed Coordination Events ━━━",
            "",
            "Today, agent work is chat noise -- unstructured text in a stream.",
            "Phase 3 adds typed events that ride alongside messages:",
            "",
            "  task_request     -- agent accepts a new task",
            "  task_update      -- progress through phases",
            "  evidence_attach  -- proof of work at each step",
            "  task_complete    -- done, with result URL",
            "  task_failed      -- error, with details",
            "",
            "Each event is an IRCv3 TAGMSG (structured, machine-readable)",
            "paired with a PRIVMSG (human-readable, works in any client).",
            "",
            "Let me show you. I'll create a task:",
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // The opener mints the task's id; taking it is the second event, because
    // a directed offer is not work in progress until its recipient accepts.
    let task_id = act(
        &handle,
        ch,
        &did,
        "offer",
        None,
        &[
            ("title", "Build a todo app with user accounts"),
            ("to", &did),
        ],
        "📋 New task: Build a todo app with user accounts",
    )
    .await;
    act(
        &handle,
        ch,
        &did,
        "accept",
        Some(&task_id),
        &[],
        "👍 Taking it",
    )
    .await;

    say(
        &handle,
        ch,
        &[
            "",
            "That sent two things at once:",
            "  1. TAGMSG carrying the signed act tags (for rich clients)",
            "  2. PRIVMSG with the emoji text you just saw (for everyone)",
            "",
            "A rich client renders a task card. irssi sees the text.",
            "Both are the same event -- just different views.",
        ],
    )
    .await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ─── Step 2: Evidence Attachments ───────────────

    say(
        &handle,
        ch,
        &[
            "━━━ 2/4: Evidence Attachments ━━━",
            "",
            "Agents shouldn't just say 'tests passed' -- they should prove it.",
            "Evidence attachments are typed artifacts linked to a task:",
            "",
            "  spec_document     -- requirements text",
            "  architecture_doc  -- design decisions",
            "  file_manifest     -- files created",
            "  code_review       -- review findings",
            "  test_result       -- test output with pass/fail",
            "  deploy_log        -- deploy output + URL",
            "",
            "Each has a summary, optional URL, optional content hash.",
            "Rich clients can expand them inline. Let me attach one:",
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    act(
        &handle,
        ch,
        &did,
        "progress",
        Some(&task_id),
        &[
            ("note", "test_result: 12/12 tests passed"),
            ("ctx", "https://ci.example.com/run/456"),
            ("ctx-h", &ctx_hash(b"12/12 tests passed")),
        ],
        "✅ [qa] Evidence: 12/12 tests passed -- https://ci.example.com/run/456",
    )
    .await;

    say(
        &handle,
        ch,
        &[
            "",
            "That evidence is now linked to task {task_id}.",
            "In the web client, clicking the task shows all evidence.",
            "The content hash means you can verify the evidence hasn't been tampered with.",
            "",
            "In irssi, you see the summary and URL -- still useful, just less interactive.",
        ],
    )
    .await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ─── Step 3: Audit Timeline ────────────────────

    say(
        &handle,
        ch,
        &[
            "━━━ 3/4: Audit Timeline ━━━",
            "",
            "Every coordination event is stored server-side.",
            "The audit timeline answers: 'What did this agent do, and why?'",
            "",
            "REST API:",
            "  GET /api/v1/channels/{name}/events?actor=did:key:...&ref_id=01JRXYZ",
            "  GET /api/v1/actions/{task_id}  (full task with all its events)",
            "",
            "The web client renders this as a visual timeline:",
            "",
            "  20:00  📋 factory created task: Build a todo app",
            "  20:01  📝 factory -> specifying (requirements doc attached)",
            "  20:02  🏗 factory -> designing (architecture doc attached)",
            "  20:03  🔨 factory -> building (8 files, 342 lines)",
            "  20:04  🔍 factory -> reviewing (no issues found)",
            "  20:05  🧪 factory -> testing (12/12 passed)",
            "  20:06  🚀 factory -> deploying",
            "  20:06  ✅ factory completed task (https://todo.example.com)",
            "",
            "Filter by agent, event type, or time range.",
            "Every signed event has a 🔒 badge you can verify.",
        ],
    )
    .await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ─── Step 4: End-to-End Build (The Full Loop) ──

    say(
        &handle,
        ch,
        &[
            "━━━ 4/4: End-to-End Build ━━━",
            "",
            "Now I'll simulate a full factory build with coordination events.",
            "This is what it looks like when Phase 1 + 2 + 3 work together.",
            "",
            "Imagine you just said: 'factory: build a todo app'",
            "Watch the structured lifecycle play out...",
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // ── Task creation
    handle
        .raw("PRESENCE :state=active;status=Accepted task: Build a todo app")
        .await?;
    let task_id = act(
        &handle,
        ch,
        &did,
        "offer",
        None,
        &[
            ("title", "Build a todo app with user accounts"),
            ("to", &did),
        ],
        "📋 New task: Build a todo app with user accounts",
    )
    .await;
    act(
        &handle,
        ch,
        &did,
        "accept",
        Some(&task_id),
        &[],
        "👍 Taking it",
    )
    .await;

    // ── Phase: Specifying
    handle
        .raw("PRESENCE :state=executing;status=Phase: specifying")
        .await?;

    // Spawn a product worker
    handle.raw(&format!("AGENT SPAWN {ch} :nick=factory-product;capabilities=post_message;ttl=120;task=spec-{task_id}")).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    handle
        .raw(&format!(
            "AGENT MSG factory-product {ch} :📝 Clarifying requirements..."
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    handle.raw(&format!("AGENT MSG factory-product {ch} :📝 Users need: signup, login, create/edit/delete todos, mark complete")).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    act(
        &handle,
        ch,
        &did,
        "progress",
        Some(&task_id),
        &[("note", "specifying: Requirements clarified: CRUD + auth")],
        "📝 [product] Spec complete: CRUD todos with user accounts",
    )
    .await;
    act(
        &handle,
        ch,
        &did,
        "progress",
        Some(&task_id),
        &[
            (
                "note",
                "spec_document: 4 user stories, 2 acceptance criteria each",
            ),
            ("ctx", "https://example.org/factory/spec.md"),
            (
                "ctx-h",
                &ctx_hash(b"Product spec: 4 user stories, 2 acceptance criteria each"),
            ),
        ],
        "📎 Evidence attached: spec_document (4 user stories)",
    )
    .await;

    handle.raw("AGENT DESPAWN factory-product").await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ── Phase: Designing
    handle
        .raw("PRESENCE :state=executing;status=Phase: designing")
        .await?;

    handle.raw(&format!("AGENT SPAWN {ch} :nick=factory-architect;capabilities=post_message;ttl=120;task=design-{task_id}")).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    handle
        .raw(&format!(
            "AGENT MSG factory-architect {ch} :🏗 Evaluating stack options..."
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    handle.raw(&format!("AGENT MSG factory-architect {ch} :🏗 Decision: React + Express + SQLite. 6 components, 3 API routes.")).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    act(
        &handle,
        ch,
        &did,
        "progress",
        Some(&task_id),
        &[(
            "note",
            "designing: Stack: React + Express + SQLite, 6 components",
        )],
        "🏗 [architect] Design complete: React + Express + SQLite",
    )
    .await;
    act(
        &handle,
        ch,
        &did,
        "progress",
        Some(&task_id),
        &[
            (
                "note",
                "architecture_doc: React SPA, Express API, SQLite, JWT auth",
            ),
            ("ctx", "https://example.org/factory/architecture.md"),
            (
                "ctx-h",
                &ctx_hash(b"React SPA, Express API, SQLite, JWT auth"),
            ),
        ],
        "📎 Evidence attached: architecture_doc (6 components, 3 routes)",
    )
    .await;

    handle.raw("AGENT DESPAWN factory-architect").await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ── Phase: Building
    handle
        .raw("PRESENCE :state=executing;status=Phase: building")
        .await?;

    handle.raw(&format!("AGENT SPAWN {ch} :nick=factory-builder;capabilities=post_message;ttl=120;task=build-{task_id}")).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    handle
        .raw(&format!(
            "AGENT MSG factory-builder {ch} :🔨 Creating project scaffold..."
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    handle.raw(&format!("AGENT MSG factory-builder {ch} :🔨 Building components: TodoList, TodoItem, LoginForm, SignupForm...")).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    handle
        .raw(&format!(
            "AGENT MSG factory-builder {ch} :🔨 Building API: /auth, /todos, /users..."
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    handle
        .raw(&format!(
            "AGENT MSG factory-builder {ch} :✅ Build complete. 8 files, 342 lines."
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    act(
        &handle,
        ch,
        &did,
        "progress",
        Some(&task_id),
        &[("note", "building: 8 files created, 342 lines of code")],
        "🔨 [builder] Build complete: 8 files, 342 lines",
    )
    .await;
    act(
        &handle, ch, &did, "progress", Some(&task_id),
        &[
            ("note", "file_manifest: 8 files, 342 lines"),
            ("ctx", "https://example.org/factory/files.txt"),
            ("ctx-h", &ctx_hash(b"App.tsx TodoList.tsx TodoItem.tsx LoginForm.tsx SignupForm.tsx server.ts db.ts auth.ts")),
        ],
        "📎 Evidence attached: file_manifest (8 files, 342 lines)",
    ).await;

    handle.raw("AGENT DESPAWN factory-builder").await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ── Phase: Reviewing
    handle
        .raw("PRESENCE :state=executing;status=Phase: reviewing")
        .await?;

    handle.raw(&format!("AGENT SPAWN {ch} :nick=factory-reviewer;capabilities=post_message;ttl=120;task=review-{task_id}")).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    handle
        .raw(&format!(
            "AGENT MSG factory-reviewer {ch} :🔍 Reviewing code quality..."
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    handle.raw(&format!("AGENT MSG factory-reviewer {ch} :🔍 Checking security: input validation, SQL injection, auth flow...")).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    handle.raw(&format!("AGENT MSG factory-reviewer {ch} :✅ Review passed. No critical issues. 1 suggestion (add rate limiting).")).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    act(
        &handle,
        ch,
        &did,
        "progress",
        Some(&task_id),
        &[(
            "note",
            "reviewing: Code review passed, 0 critical, 1 suggestion",
        )],
        "🔍 [reviewer] Review passed: 0 critical issues, 1 suggestion",
    )
    .await;
    act(
        &handle,
        ch,
        &did,
        "progress",
        Some(&task_id),
        &[
            (
                "note",
                "code_review: 0 critical, 0 major, 1 minor (add rate limiting to /auth)",
            ),
            ("ctx", "https://example.org/factory/review.md"),
            (
                "ctx-h",
                &ctx_hash(b"0 critical, 0 major, 1 minor (add rate limiting to /auth)"),
            ),
        ],
        "📎 Evidence attached: code_review (approved, 1 minor suggestion)",
    )
    .await;

    handle.raw("AGENT DESPAWN factory-reviewer").await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ── Phase: Testing
    handle
        .raw("PRESENCE :state=executing;status=Phase: testing")
        .await?;

    handle.raw(&format!("AGENT SPAWN {ch} :nick=factory-qa;capabilities=post_message;ttl=120;task=test-{task_id}")).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    handle
        .raw(&format!(
            "AGENT MSG factory-qa {ch} :🧪 Running test suite..."
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    handle
        .raw(&format!(
            "AGENT MSG factory-qa {ch} :🧪 Auth tests: 4/4 passed"
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    handle
        .raw(&format!(
            "AGENT MSG factory-qa {ch} :🧪 CRUD tests: 6/6 passed"
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    handle
        .raw(&format!(
            "AGENT MSG factory-qa {ch} :🧪 Edge cases: 2/2 passed"
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    handle
        .raw(&format!(
            "AGENT MSG factory-qa {ch} :✅ All tests passed: 12/12"
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    act(
        &handle,
        ch,
        &did,
        "progress",
        Some(&task_id),
        &[("note", "testing: 12/12 tests passed")],
        "🧪 [qa] Tests complete: 12/12 passed",
    )
    .await;
    act(
        &handle,
        ch,
        &did,
        "progress",
        Some(&task_id),
        &[
            ("note", "test_result: 12/12 passed (4 auth, 6 CRUD, 2 edge)"),
            ("ctx", "https://ci.example.com/run/789"),
            ("ctx-h", &ctx_hash(b"12/12 passed (4 auth, 6 CRUD, 2 edge)")),
        ],
        "📎 Evidence attached: test_result (12/12 passed) -- https://ci.example.com/run/789",
    )
    .await;

    handle.raw("AGENT DESPAWN factory-qa").await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    if !prompt(&handle, &mut events, ch).await {
        return shutdown(handle).await;
    }

    // ── Phase: Deploy (with Phase 2 approval flow!)
    handle
        .raw("PRESENCE :state=blocked_on_permission;status=Awaiting deploy approval")
        .await?;
    handle
        .raw(&format!("APPROVAL_REQUEST {ch} :deploy;resource=todo-app"))
        .await?;

    say(
        &handle,
        ch,
        &[
            "",
            "🔔 Build is done. Requesting deploy approval.",
            "Phase 2 + Phase 3 working together: structured work meets governance.",
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

    handle
        .raw("PRESENCE :state=executing;status=Phase: deploying")
        .await?;

    act(
        &handle,
        ch,
        &did,
        "progress",
        Some(&task_id),
        &[("note", "deploying: Deploying to production")],
        "🚀 [deploy] Deploying to production...",
    )
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    let deploy_url = "https://todo-app.example.com";

    act(
        &handle,
        ch,
        &did,
        "progress",
        Some(&task_id),
        &[
            ("note", "deploy_log: Deployed successfully in 8s"),
            ("ctx", &deploy_url),
            ("ctx-h", &ctx_hash(deploy_url.as_bytes())),
        ],
        &format!("📎 Evidence attached: deploy_log -- {deploy_url}"),
    )
    .await;

    // ── Task complete
    act(
        &handle,
        ch,
        &did,
        "complete",
        Some(&task_id),
        &[("note", "Todo app deployed"), ("ctx", &deploy_url)],
        &format!(
            "🎉 Task complete: Todo app deployed at {deploy_url} (6 phases, 6 evidence items)"
        ),
    )
    .await;

    handle
        .raw(&format!(
            "PRESENCE :state=idle;status=Task complete -- {deploy_url}"
        ))
        .await?;

    // ─── Summary ────────────────────────────────────

    say(
        &handle,
        ch,
        &[
            "",
            "━━━ Phase 3: Coordinated Work -- Summary ━━━",
            "",
            "What happened during that build:",
            "",
            "  Events emitted:",
            "    1x task_request   -- task created",
            "    6x task_update    -- one per phase (spec, design, build, review, test, deploy)",
            "    6x evidence_attach -- proof at each step",
            "    1x task_complete  -- final result with URL",
            "",
            "  Agents spawned and despawned:",
            "    factory-product, factory-architect, factory-builder,",
            "    factory-reviewer, factory-qa (each with TTL)",
            "",
            "  Governance:",
            "    1x approval_request before deploy (Phase 2)",
            "",
            "All of this is:",
            "  - Queryable via REST API (filter by task, agent, time)",
            "  - Renderable as a visual timeline in the web client",
            "  - Readable as plain text in any IRC client",
            "  - Cryptographically signed for non-repudiation",
            "",
            "Phase 1: 'Who is this agent?'",
            "Phase 2: 'What can it do, and who controls it?'",
            "Phase 3: 'What did it do, and can I verify it?'",
            "",
            "👋 factory signing off. Say 'quit' or I'll hang out.",
        ],
    )
    .await;

    handle
        .raw("PRESENCE :state=idle;status=Demo complete")
        .await?;

    // Idle loop
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
