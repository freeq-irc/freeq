//! HTTP routes for the agent assistance interface.
//!
//! Handlers are intentionally thin: extract the [`Caller`], call the
//! deterministic tool, wrap the resulting [`FactBundle`] in an
//! [`AssistResponse`] envelope. This split is what lets the next PR
//! drop in an LLM summarizer between tool and envelope without
//! reshaping any handler.

use super::caller;
use super::llm::{global as llm_global, router as llm_router};
use super::tools;
use super::types::*;
use crate::server::SharedState;
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::Arc;

/// Build the agent-assist router. Merged into the main app router by
/// [`crate::web::router`].
pub fn routes() -> Router<Arc<SharedState>> {
    Router::new()
        .route("/.well-known/agent.json", get(get_discovery))
        // Original validators / diagnosers (batch 1).
        .route(
            "/agent/tools/validate_client_config",
            post(post_validate_client_config),
        )
        .route(
            "/agent/tools/diagnose_message_ordering",
            post(post_diagnose_message_ordering),
        )
        .route("/agent/tools/diagnose_sync", post(post_diagnose_sync))
        // Bot-developer batch (batch 2).
        .route(
            "/agent/tools/inspect_my_session",
            post(post_inspect_my_session),
        )
        .route(
            "/agent/tools/diagnose_join_failure",
            post(post_diagnose_join_failure),
        )
        .route(
            "/agent/tools/diagnose_disconnect",
            post(post_diagnose_disconnect),
        )
        .route(
            "/agent/tools/replay_missed_messages",
            post(post_replay_missed_messages),
        )
        .route(
            "/agent/tools/predict_message_outcome",
            post(post_predict_message_outcome),
        )
        .route(
            "/agent/tools/explain_message_routing",
            post(post_explain_message_routing),
        )
        .route(
            "/agent/tools/diagnose_av_session",
            post(post_diagnose_av_session),
        )
        // Free-form router (LLM-backed). Returns LLM_NOT_CONFIGURED if
        // no provider is installed.
        .route("/agent/session", post(post_session))
}

/// Capabilities advertised by the discovery endpoint. Kept in lock-step
/// with the tool routes above so agents can rely on this as truth.
pub(crate) const CAPABILITIES: &[&str] = &[
    "validate_client_config",
    "diagnose_message_ordering",
    "diagnose_sync",
    "inspect_my_session",
    "diagnose_join_failure",
    "diagnose_disconnect",
    "replay_missed_messages",
    "predict_message_outcome",
    "explain_message_routing",
    "diagnose_av_session",
    "free_form_session",
];

#[derive(Debug, Deserialize)]
struct SessionRequest {
    message: String,
    /// Optional structured context. Currently informational only —
    /// the deterministic tools take their args from the model's
    /// extracted intent. This field is reserved so future tools (and
    /// the LLM router) can use it without a wire-shape change.
    #[serde(default)]
    #[allow(dead_code)]
    context: serde_json::Value,
}

// ─── Discovery ───────────────────────────────────────────────────────────

async fn get_discovery() -> impl IntoResponse {
    let llm_enabled = llm_global::is_configured();
    let mut caps = CAPABILITIES.to_vec();
    if !llm_enabled {
        // The session endpoint exists either way, but free-form
        // routing only works when an LLM is configured. Drop the
        // capability advertisement so agents pick a structured tool
        // directly.
        caps.retain(|c| *c != "free_form_session");
    }
    Json(AgentDiscovery {
        service: "Freeq",
        version: env!("CARGO_PKG_VERSION"),
        description: "Agent-facing assistance interface for Freeq client validation and \
             diagnostic queries. Returns conclusions, never raw state.",
        assistance_endpoint: "/agent/tools",
        capabilities: caps,
        auth: AgentDiscoveryAuth {
            required: false,
            methods: vec!["bearer"],
        },
        surfaces: Default::default(),
    })
}

// ─── Tool handlers ───────────────────────────────────────────────────────

async fn post_validate_client_config(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Json(input): Json<ValidateClientConfigInput>,
) -> impl IntoResponse {
    let caller = caller::extract(&headers, &state);
    let request_id = new_request_id();
    let bundle = tools::validate_client_config(&input);
    log_audit("validate_client_config", &request_id, &caller, &bundle);
    Json(envelope(request_id, bundle, &caller)).into_response()
}

async fn post_diagnose_message_ordering(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Json(input): Json<DiagnoseMessageOrderingInput>,
) -> impl IntoResponse {
    let caller = caller::extract(&headers, &state);
    let request_id = new_request_id();
    let bundle = tools::diagnose_message_ordering(&input, &caller, &state);
    log_audit("diagnose_message_ordering", &request_id, &caller, &bundle);
    Json(envelope(request_id, bundle, &caller)).into_response()
}

async fn post_diagnose_sync(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Json(input): Json<DiagnoseSyncInput>,
) -> impl IntoResponse {
    let caller = caller::extract(&headers, &state);
    let request_id = new_request_id();
    let bundle = tools::diagnose_sync(&input, &caller, &state);
    log_audit("diagnose_sync", &request_id, &caller, &bundle);
    Json(envelope(request_id, bundle, &caller)).into_response()
}

// ─── Batch 2 handlers ────────────────────────────────────────────────────

async fn post_inspect_my_session(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Json(input): Json<InspectMySessionInput>,
) -> impl IntoResponse {
    let caller = caller::extract(&headers, &state);
    let request_id = new_request_id();
    let bundle = tools::inspect_my_session(&input, &caller, &state);
    log_audit("inspect_my_session", &request_id, &caller, &bundle);
    Json(envelope(request_id, bundle, &caller)).into_response()
}

async fn post_diagnose_join_failure(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Json(input): Json<DiagnoseJoinFailureInput>,
) -> impl IntoResponse {
    let caller = caller::extract(&headers, &state);
    let request_id = new_request_id();
    let bundle = tools::diagnose_join_failure(&input, &caller, &state);
    log_audit("diagnose_join_failure", &request_id, &caller, &bundle);
    Json(envelope(request_id, bundle, &caller)).into_response()
}

async fn post_diagnose_disconnect(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Json(input): Json<DiagnoseDisconnectInput>,
) -> impl IntoResponse {
    let caller = caller::extract(&headers, &state);
    let request_id = new_request_id();
    let bundle = tools::diagnose_disconnect(&input, &caller, &state);
    log_audit("diagnose_disconnect", &request_id, &caller, &bundle);
    Json(envelope(request_id, bundle, &caller)).into_response()
}

async fn post_replay_missed_messages(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Json(input): Json<ReplayMissedMessagesInput>,
) -> impl IntoResponse {
    let caller = caller::extract(&headers, &state);
    let request_id = new_request_id();
    let bundle = tools::replay_missed_messages(&input, &caller, &state);
    log_audit("replay_missed_messages", &request_id, &caller, &bundle);
    Json(envelope(request_id, bundle, &caller)).into_response()
}

async fn post_predict_message_outcome(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Json(input): Json<PredictMessageOutcomeInput>,
) -> impl IntoResponse {
    let caller = caller::extract(&headers, &state);
    let request_id = new_request_id();
    let bundle = tools::predict_message_outcome(&input, &caller, &state);
    log_audit("predict_message_outcome", &request_id, &caller, &bundle);
    Json(envelope(request_id, bundle, &caller)).into_response()
}

async fn post_explain_message_routing(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Json(input): Json<ExplainMessageRoutingInput>,
) -> impl IntoResponse {
    let caller = caller::extract(&headers, &state);
    let request_id = new_request_id();
    let bundle = tools::explain_message_routing(&input);
    log_audit("explain_message_routing", &request_id, &caller, &bundle);
    Json(envelope(request_id, bundle, &caller)).into_response()
}

async fn post_diagnose_av_session(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Json(input): Json<DiagnoseAvSessionInput>,
) -> impl IntoResponse {
    let caller = caller::extract(&headers, &state);
    let request_id = new_request_id();
    let bundle = tools::diagnose_av_session(&input, &caller, &state);
    log_audit("diagnose_av_session", &request_id, &caller, &bundle);
    Json(envelope(request_id, bundle, &caller)).into_response()
}

/// Free-form session endpoint. The LLM classifies the request into a
/// tool call, the deterministic tool runs, and the result is returned
/// alongside classification metadata so the agent knows which tool
/// ran and at what confidence.
async fn post_session(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Json(input): Json<SessionRequest>,
) -> impl IntoResponse {
    let caller = caller::extract(&headers, &state);
    let request_id = new_request_id();

    // Cap message size at the wire layer too, even though the
    // prompt envelope also caps. Defense in depth against giant
    // payloads keeping the connection open while we'd hit the LLM.
    if input.message.len() > 16_384 {
        let bundle = tools::permission_denied(
            "MESSAGE_TOO_LARGE",
            "Message exceeds the 16 KB limit for free-form classification.",
            DisclosureLevel::Public,
        );
        log_audit("session", &request_id, &caller, &bundle);
        return Json(envelope(request_id, bundle, &caller)).into_response();
    }

    let routed = llm_router::handle_session(llm_router::SessionInput {
        message: &input.message,
        caller: &caller,
        state: &state,
    })
    .await;

    log_audit_with_provider(
        "session",
        &request_id,
        &caller,
        &routed.bundle,
        &routed.classification.provider,
    );

    let mut resp = envelope(request_id, routed.bundle, &caller);
    resp.classification = Some(RoutedClassification {
        provider: routed.classification.provider,
        tool: routed.classification.tool,
        confidence: routed.classification.confidence,
        summary: routed.classification.summary,
    });
    Json(resp).into_response()
}

// ─── Envelope assembly + final disclosure check ──────────────────────────

/// Final guard between a tool's [`FactBundle`] and the wire response.
///
/// Tools perform their own per-channel permission checks at the start,
/// so this is a *narrow* defense-in-depth pass: it catches the one
/// failure mode the abstract `caller.level` is sufficient to detect —
/// a bundle marked server-operator-only being returned to a non-admin
/// caller. Per-channel disclosure (ChannelMember / ChannelOperator)
/// can't be re-checked here because we don't carry the channel
/// context into the envelope; that's the tool's responsibility.
fn envelope(request_id: String, bundle: FactBundle, caller: &Caller) -> AssistResponse {
    let admin_only = matches!(bundle.min_disclosure, DisclosureLevel::ServerOperator);
    let caller_is_admin = matches!(caller.level, DisclosureLevel::ServerOperator);
    if admin_only && !caller_is_admin {
        let denied = tools::permission_denied(
            "DISCLOSURE_FILTER_BLOCKED",
            "Tool returned admin-only facts to a non-admin caller; redacted.",
            DisclosureLevel::ServerOperator,
        );
        return AssistResponse::from_bundle(request_id, denied);
    }
    AssistResponse::from_bundle(request_id, bundle)
}

/// Audit log for every assistance request. Per spec §16, all
/// diagnostic requests must be auditable.
fn log_audit(tool: &str, request_id: &str, caller: &Caller, bundle: &FactBundle) {
    tracing::info!(
        target: "agent_assist::audit",
        tool,
        request_id,
        caller_did = caller.did.as_deref().unwrap_or("anonymous"),
        caller_level = ?caller.level,
        ok = bundle.ok,
        code = %bundle.code,
        "agent assistance request",
    );
}

/// Audit log variant that also records which LLM provider classified
/// the request (only the `/agent/session` endpoint uses this).
fn log_audit_with_provider(
    tool: &str,
    request_id: &str,
    caller: &Caller,
    bundle: &FactBundle,
    provider: &str,
) {
    tracing::info!(
        target: "agent_assist::audit",
        tool,
        request_id,
        caller_did = caller.did.as_deref().unwrap_or("anonymous"),
        caller_level = ?caller.level,
        ok = bundle.ok,
        code = %bundle.code,
        llm_provider = provider,
        "agent assistance request (free-form)",
    );
}

fn new_request_id() -> String {
    // Compact, sortable, no extra crate: timestamp_ns + a 4-byte
    // PRNG slice from the system clock's sub-nanosecond jitter.
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("req_{}{:04x}", now.as_secs(), now.subsec_nanos() & 0xFFFF)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_assist::types::Confidence;

    fn bundle_at(level: DisclosureLevel) -> FactBundle {
        FactBundle {
            ok: true,
            code: "TEST".into(),
            summary: "ok".into(),
            confidence: Confidence::High,
            safe_facts: vec!["fact one".into()],
            suggested_fixes: vec![],
            redactions: vec![],
            followups: vec![],
            min_disclosure: level,
        }
    }

    #[test]
    fn envelope_blocks_admin_only_bundle_for_non_admin() {
        let caller = Caller::anonymous();
        let resp = envelope(
            "req".into(),
            bundle_at(DisclosureLevel::ServerOperator),
            &caller,
        );
        assert!(!resp.ok);
        assert_eq!(resp.diagnosis.code, "DISCLOSURE_FILTER_BLOCKED");
        // Defense-in-depth: the original safe_facts must not appear.
        assert!(!resp.safe_facts.iter().any(|f| f.contains("fact one")));
    }

    #[test]
    fn envelope_passes_admin_only_bundle_for_admin() {
        let caller = Caller {
            did: Some("did:plc:admin".into()),
            session_id: Some("s1".into()),
            level: DisclosureLevel::ServerOperator,
        };
        let resp = envelope(
            "req".into(),
            bundle_at(DisclosureLevel::ServerOperator),
            &caller,
        );
        assert!(resp.ok);
        assert_eq!(resp.diagnosis.code, "TEST");
        assert_eq!(resp.safe_facts, vec!["fact one".to_string()]);
    }

    #[test]
    fn envelope_passes_account_level_to_anonymous_trusting_tool_check() {
        // Per-channel checks live in the tool. The envelope intentionally
        // does NOT re-check ChannelMember/ChannelOperator because it
        // doesn't carry the channel context. A tool that forgot its
        // upfront check would slip through here — but that's why every
        // tool is responsible for its own permission gate.
        let caller = Caller::anonymous();
        let resp = envelope(
            "req".into(),
            bundle_at(DisclosureLevel::ChannelMember),
            &caller,
        );
        assert!(resp.ok);
    }
}
