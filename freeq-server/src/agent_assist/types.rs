//! Public + internal types for the agent assistance interface.
//!
//! The split between [`FactBundle`] and [`AssistResponse`] is deliberate:
//! tools produce a [`FactBundle`] (deterministic, pre-redacted, no LLM
//! involvement). The HTTP layer wraps it in an [`AssistResponse`]
//! envelope. A future LLM summarizer slots in *between* the tool and
//! the envelope, taking only the bundle's `safe_facts` and producing
//! a refined `summary` — it never sees raw server state.

use serde::{Deserialize, Serialize};

// ─── Disclosure levels (§6.1 of the spec) ────────────────────────────────

/// Caller authorization tier.
///
/// Each tool declares the minimum level required for its facts to be
/// returned. The disclosure filter compares the caller's actual level
/// to the bundle's `min_disclosure` and either passes the bundle through
/// or substitutes a `PermissionDenied` diagnosis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureLevel {
    /// Anyone, including unauthenticated callers.
    Public,
    /// An authenticated DID, asking about its own state only.
    Account,
    /// Authenticated and currently a member of the channel in question.
    ChannelMember,
    /// Authenticated and an op (`@`) on the channel in question.
    ChannelOperator,
    /// Server operator (DID listed in `--oper-dids`).
    ServerOperator,
}

impl DisclosureLevel {
    /// True if the caller's level satisfies the requirement.
    pub fn satisfies(self, required: DisclosureLevel) -> bool {
        self >= required
    }
}

// ─── Caller context ──────────────────────────────────────────────────────

/// Identifies the caller for permission and scoping decisions.
///
/// Built by [`crate::agent_assist::caller::extract`] from request
/// headers + shared state.
#[derive(Debug, Clone)]
pub struct Caller {
    /// Authenticated DID, if the caller presented a valid bearer.
    pub did: Option<String>,
    /// IRC session id the bearer resolved to (for self-scoping).
    pub session_id: Option<String>,
    /// Caller's tier when no channel is involved.
    pub level: DisclosureLevel,
}

impl Caller {
    /// An anonymous, unauthenticated caller.
    pub fn anonymous() -> Self {
        Self {
            did: None,
            session_id: None,
            level: DisclosureLevel::Public,
        }
    }

    /// True if this caller is the named DID.
    pub fn is_self(&self, did: &str) -> bool {
        self.did.as_deref() == Some(did)
    }
}

// ─── Confidence ──────────────────────────────────────────────────────────

/// Coarse confidence on a diagnosis. Surfaced to callers so they know
/// whether to act or to investigate further.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

// ─── FactBundle (tool output, pre-envelope) ──────────────────────────────

/// A diagnosis with safe facts. Tools produce these; the api layer
/// wraps them in [`AssistResponse`].
///
/// LLM future: a summarizer takes `safe_facts` (only) and overwrites
/// `summary` with a refined version. No other field changes, and the
/// LLM never sees inputs from caller-supplied logs unless they were
/// first sanitised into `safe_facts`.
#[derive(Debug, Clone, Serialize)]
pub struct FactBundle {
    /// Whether the diagnosis indicates a healthy state.
    pub ok: bool,
    /// Stable machine-readable diagnosis code (e.g.
    /// `"CLIENT_ORDERED_BY_RECEIVE_TIME"`).
    pub code: String,
    /// Human-readable one-line summary. May be replaced by the LLM
    /// summarizer in a future PR; deterministic placeholder for now.
    pub summary: String,
    pub confidence: Confidence,
    /// Facts derived from server state, already filtered for the
    /// bundle's `min_disclosure` level.
    pub safe_facts: Vec<String>,
    pub suggested_fixes: Vec<SuggestedFix>,
    /// Categories of data deliberately omitted (so the caller knows
    /// the response is a *redacted* view, not a complete one).
    pub redactions: Vec<String>,
    /// Tools the caller could call next for more detail.
    pub followups: Vec<Followup>,
    /// Minimum caller tier required to return this bundle as-is. The
    /// envelope replaces the bundle with a permission-denied stub if
    /// the caller is below this tier.
    #[serde(skip)]
    pub min_disclosure: DisclosureLevel,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuggestedFix {
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Followup {
    pub tool: String,
    pub reason: String,
}

// ─── HTTP envelope (the wire response) ───────────────────────────────────

/// Outer JSON envelope returned by every `/agent/*` tool endpoint.
///
/// `classification` is populated for `/agent/session` (the LLM-routed
/// endpoint) and omitted for direct tool calls.
#[derive(Debug, Serialize)]
pub struct AssistResponse {
    pub ok: bool,
    pub request_id: String,
    pub diagnosis: Diagnosis,
    pub safe_facts: Vec<String>,
    pub suggested_fixes: Vec<SuggestedFix>,
    pub redactions: Vec<String>,
    pub followups: Vec<Followup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<RoutedClassification>,
}

/// Metadata about how a free-form `/agent/session` request was routed
/// through the LLM. Surfaced so the agent knows which tool ran and
/// why; the deterministic facts/diagnosis still come from the tool
/// itself.
#[derive(Debug, Serialize)]
pub struct RoutedClassification {
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Diagnosis {
    pub code: String,
    pub summary: String,
    pub confidence: Confidence,
}

impl AssistResponse {
    /// Build the wire envelope from a [`FactBundle`] (no LLM
    /// classification metadata).
    pub fn from_bundle(request_id: String, b: FactBundle) -> Self {
        Self {
            ok: b.ok,
            request_id,
            diagnosis: Diagnosis {
                code: b.code,
                summary: b.summary,
                confidence: b.confidence,
            },
            safe_facts: b.safe_facts,
            suggested_fixes: b.suggested_fixes,
            redactions: b.redactions,
            followups: b.followups,
            classification: None,
        }
    }

    /// Build the wire envelope from a [`FactBundle`] *with*
    /// classification metadata (used by `/agent/session`).
    pub fn from_routed(
        request_id: String,
        b: FactBundle,
        classification: RoutedClassification,
    ) -> Self {
        let mut resp = Self::from_bundle(request_id, b);
        resp.classification = Some(classification);
        resp
    }
}

// ─── Tool inputs ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ValidateClientConfigInput {
    pub client_name: String,
    #[serde(default)]
    pub client_version: String,
    #[serde(default)]
    pub server_url: String,
    pub transport: Option<String>,
    pub auth_method: Option<String>,
    #[serde(default)]
    pub supports: ClientSupports,
    #[serde(default)]
    pub desired_features: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ClientSupports {
    #[serde(default)]
    pub message_tags: bool,
    #[serde(default)]
    pub batch: bool,
    #[serde(default)]
    pub server_time: bool,
    #[serde(default)]
    pub sasl: bool,
    #[serde(default)]
    pub resume: bool,
    #[serde(default)]
    pub e2ee: bool,
    #[serde(default)]
    pub crdt_sync: bool,
    #[serde(default)]
    pub echo_message: bool,
    #[serde(default)]
    pub away_notify: bool,
}

#[derive(Debug, Deserialize)]
pub struct DiagnoseMessageOrderingInput {
    pub channel: String,
    /// Caller's observed display order (oldest → newest).
    pub message_ids: Vec<String>,
    #[serde(default)]
    pub symptom: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DiagnoseSyncInput {
    pub channel: Option<String>,
    /// DID the caller wants diagnosed. Self-scoping enforced by the
    /// disclosure filter — a non-admin caller may only diagnose their
    /// own DID.
    pub account: String,
    #[serde(default)]
    pub symptom: Option<String>,
}

// ─── Bot-developer tool inputs (batch 2) ─────────────────────────────────

/// "What does the server actually know about me right now?"
#[derive(Debug, Deserialize)]
pub struct InspectMySessionInput {
    /// DID to inspect. Self-only for non-admins.
    pub account: String,
}

/// "I tried to JOIN and it failed — explain why."
#[derive(Debug, Deserialize)]
pub struct DiagnoseJoinFailureInput {
    /// DID that attempted the join. Self-only for non-admins.
    pub account: String,
    /// Channel name (with or without leading `#`).
    pub channel: String,
    /// Optional: the IRC numeric the client received (e.g. `"473"`,
    /// `"475"`). Lets us be more specific in the diagnosis.
    #[serde(default)]
    pub observed_numeric: Option<String>,
}

/// "I just dropped — what happened?"
#[derive(Debug, Deserialize)]
pub struct DiagnoseDisconnectInput {
    pub account: String,
}

/// "What is the AV session in this channel actually doing, and does it
/// match what my client sees?" Returns counts + a divergence flag, with
/// instance ids and DIDs hashed so the response is safe to share in a
/// bug report. Anyone with `ChannelMember` rights for the channel can
/// call it; the caller's own instance ids are quoted in cleartext so
/// they can self-diagnose; everyone else's are hashed.
#[derive(Debug, Deserialize)]
pub struct DiagnoseAvSessionInput {
    /// Channel name (with or without leading `#`).
    pub channel: String,
}

/// "Between this msgid and now, did I miss anything?"
#[derive(Debug, Deserialize)]
pub struct ReplayMissedMessagesInput {
    pub channel: String,
    /// Last msgid the bot is sure it processed. Server reports the
    /// count + bounding msgids of the gap.
    pub since_msgid: String,
    /// Optional cap on how far to look. Default 1000.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// "Will this send succeed?"
#[derive(Debug, Deserialize)]
pub struct PredictMessageOutcomeInput {
    pub account: String,
    pub target: String,
    /// Reserved for future per-byte size checks. Currently informational
    /// — the server's wire-line limit is enforced at parse time.
    #[serde(default)]
    pub draft_size_bytes: Option<usize>,
}

/// "Explain this raw IRC line in routing terms."
#[derive(Debug, Deserialize)]
pub struct ExplainMessageRoutingInput {
    /// Raw IRC line (no trailing CRLF needed).
    pub wire_line: String,
    /// The recipient's own nick — needed to detect self-echo + mentions.
    pub my_nick: String,
}

// ─── Discovery (.well-known/agent.json) ──────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AgentDiscovery {
    pub service: &'static str,
    pub version: &'static str,
    pub description: &'static str,
    pub assistance_endpoint: &'static str,
    pub capabilities: Vec<&'static str>,
    pub auth: AgentDiscoveryAuth,
    /// The other machine-readable surfaces on this host. An agent that finds
    /// this document should not have to guess at the rest.
    pub surfaces: AgentSurfaces,
}

/// Cross-links to the sibling discovery surfaces (OpenAPI, llms.txt, MCP).
#[derive(Debug, Serialize)]
pub struct AgentSurfaces {
    /// OpenAPI 3.1 contract for every HTTP endpoint on this server.
    pub openapi: &'static str,
    /// YAML source of the same document.
    pub openapi_yaml: &'static str,
    /// Markdown index for LLM agents.
    pub llms_txt: &'static str,
    /// IRC-over-WebSocket transport (relative; scheme follows the request).
    pub irc_websocket: &'static str,
    /// npm package name of the MCP server that wraps this API.
    pub mcp_package: &'static str,
    /// SKILL.md packages describing how to use freeq well.
    pub skills: &'static str,
}

impl Default for AgentSurfaces {
    fn default() -> Self {
        Self {
            openapi: "/api/v1/openapi.json",
            openapi_yaml: "/api/v1/openapi.yaml",
            llms_txt: "/llms.txt",
            irc_websocket: "/irc",
            mcp_package: "@freeq/mcp",
            skills: "https://github.com/freeq-irc/freeq/tree/main/skills",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AgentDiscoveryAuth {
    pub required: bool,
    pub methods: Vec<&'static str>,
}
