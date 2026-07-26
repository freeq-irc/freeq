//! HTTP API endpoints for the Policy & Authority Framework.
//!
//! These endpoints enable:
//! - Policy discovery (clients fetch channel policies)
//! - Join flow (clients submit evidence, receive attestations)
//! - Transparency log queries

use super::eval::{Credential, UserEvidence};
use super::types::*;
use crate::server::SharedState;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

/// Build the policy API router (shares state with main server).
pub fn routes() -> Router<Arc<SharedState>> {
    Router::new()
        .route("/api/v1/policy/{channel}", get(get_policy))
        .route("/api/v1/policy/{channel}/rules", get(get_policy_rules))
        .route("/api/v1/policy/{channel}/history", get(get_policy_chain))
        .route("/api/v1/policy/{channel}/join", post(join_channel))
        .route(
            "/api/v1/policy/{channel}/membership/{did}",
            get(check_membership),
        )
        .route(
            "/api/v1/policy/{channel}/transparency",
            get(get_transparency_log),
        )
        .route("/api/v1/authority/{hash}", get(get_authority_set))
        .route("/api/v1/verify/github", post(verify_github))
        .route("/api/v1/credentials/{did}", get(get_credentials))
        .route("/api/v1/credentials/present", post(present_credential))
        .route("/api/v1/policy/{channel}/check", post(check_requirements))
}

// ─── Request/Response Types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct JoinRequest {
    subject_did: String,
    #[serde(default)]
    accepted_hashes: Vec<String>,
    #[serde(default)]
    credentials: Vec<CredentialInput>,
    #[serde(default)]
    proofs: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CredentialInput {
    credential_type: String,
    issuer: String,
}

#[derive(Debug, Serialize)]
struct JoinResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    join_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestation: Option<MembershipAttestation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    missing: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct PolicyResponse {
    policy: PolicyDocument,
    #[serde(skip_serializing_if = "Option::is_none")]
    authority_set: Option<AuthoritySet>,
}

#[derive(Debug, Serialize)]
struct PolicyRulesResponse {
    channel: String,
    hash: String,
    text: String,
}

#[derive(Debug, Deserialize)]
struct LogQuery {
    since: Option<i64>,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn get_engine(state: &SharedState) -> Result<&super::PolicyEngine, (StatusCode, &'static str)> {
    state.policy_engine.as_ref().map(|e| e.as_ref()).ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Policy framework not enabled",
    ))
}

fn normalize_channel(channel: &str) -> String {
    let ch = if channel.starts_with('#') {
        channel.to_string()
    } else {
        format!("#{channel}")
    };
    ch.to_lowercase()
}

// ─── Handlers ────────────────────────────────────────────────────────────────

async fn get_policy(
    State(state): State<Arc<SharedState>>,
    Path(channel): Path<String>,
) -> impl IntoResponse {
    let engine = match get_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let channel_id = normalize_channel(&channel);

    match engine.get_policy(&channel_id) {
        Ok(Some(policy)) => {
            let auth_set = engine
                .store()
                .get_authority_set(&policy.authority_set_hash)
                .ok()
                .flatten();
            Json(PolicyResponse {
                policy,
                authority_set: auth_set,
            })
            .into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "No policy for this channel").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Return the human-readable rules text for a channel's current policy.
///
/// Additive companion to `get_policy` — mirrors its visibility (public
/// readable, no auth). 404 when the channel has no policy, or when the
/// policy has no stored rules text (legacy policies, or policies received
/// over S2S which carry only the hash).
async fn get_policy_rules(
    State(state): State<Arc<SharedState>>,
    Path(channel): Path<String>,
) -> impl IntoResponse {
    let engine = match get_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let channel_id = normalize_channel(&channel);

    let policy = match engine.get_policy(&channel_id) {
        Ok(Some(p)) => p,
        Ok(None) => return (StatusCode::NOT_FOUND, "No policy for this channel").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // Extract the ACCEPT hash from the requirement tree.
    let mut hashes = HashSet::new();
    collect_hashes_from_req(&policy.requirements, &mut hashes);
    let hash = match hashes.into_iter().next() {
        Some(h) => h,
        None => {
            return (StatusCode::NOT_FOUND, "Policy has no rules text").into_response();
        }
    };

    match engine.get_rules_text(&hash) {
        Ok(Some(text)) => Json(PolicyRulesResponse {
            channel: channel_id,
            hash,
            text,
        })
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            "No stored rules text for this policy",
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_policy_chain(
    State(state): State<Arc<SharedState>>,
    Path(channel): Path<String>,
) -> impl IntoResponse {
    let engine = match get_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let channel_id = normalize_channel(&channel);

    match engine.store().get_policy_chain(&channel_id) {
        Ok(chain) => Json(chain).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn join_channel(
    State(state): State<Arc<SharedState>>,
    Path(channel): Path<String>,
    Json(req): Json<JoinRequest>,
) -> impl IntoResponse {
    let engine = match get_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let channel_id = normalize_channel(&channel);

    let evidence = UserEvidence {
        accepted_hashes: req.accepted_hashes.into_iter().collect::<HashSet<_>>(),
        credentials: req
            .credentials
            .into_iter()
            .map(|c| Credential {
                credential_type: c.credential_type,
                issuer: c.issuer,
            })
            .collect(),
        proofs: req.proofs.into_iter().collect::<HashSet<_>>(),
    };

    match engine.process_join(&channel_id, &req.subject_did, &evidence) {
        Ok(result) => match result {
            super::JoinResult::Confirmed {
                attestation,
                join_id,
            } => Json(JoinResponse {
                status: "confirmed".into(),
                join_id: Some(join_id),
                attestation: Some(attestation),
                error: None,
                missing: None,
            })
            .into_response(),

            super::JoinResult::NoPolicy => Json(JoinResponse {
                status: "open".into(),
                join_id: None,
                attestation: None,
                error: None,
                missing: None,
            })
            .into_response(),

            super::JoinResult::Pending { join_id, missing } => (
                StatusCode::ACCEPTED,
                Json(JoinResponse {
                    status: "pending".into(),
                    join_id: Some(join_id),
                    attestation: None,
                    error: None,
                    missing: Some(missing),
                }),
            )
                .into_response(),

            super::JoinResult::Failed(reason) => (
                StatusCode::FORBIDDEN,
                Json(JoinResponse {
                    status: "failed".into(),
                    join_id: None,
                    attestation: None,
                    error: Some(reason),
                    missing: None,
                }),
            )
                .into_response(),
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn check_membership(
    State(state): State<Arc<SharedState>>,
    Path((channel, did)): Path<(String, String)>,
) -> impl IntoResponse {
    let engine = match get_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let channel_id = normalize_channel(&channel);

    match engine.check_membership(&channel_id, &did) {
        Ok(Some(attestation)) => Json(attestation).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "No valid membership").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_transparency_log(
    State(state): State<Arc<SharedState>>,
    Path(channel): Path<String>,
    Query(query): Query<LogQuery>,
) -> impl IntoResponse {
    let engine = match get_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let channel_id = normalize_channel(&channel);

    match engine.store().get_log_entries(&channel_id, query.since) {
        Ok(entries) => Json(entries).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_authority_set(
    State(state): State<Arc<SharedState>>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let engine = match get_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };

    match engine.store().get_authority_set(&hash) {
        Ok(Some(auth_set)) => Json(auth_set).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Authority set not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ─── GitHub Verification ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct GitHubVerifyRequest {
    /// The DID of the user claiming GitHub membership.
    did: String,
    /// Their GitHub username.
    github_username: String,
    /// The GitHub org to verify membership in.
    org: String,
}

#[derive(Debug, Serialize)]
struct CredentialResponse {
    status: String,
    credential_type: String,
    issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
}

/// Verify GitHub org membership and issue a credential.
///
/// Calls the GitHub API to check if the user is a public member of the org.
/// If verified, stores a `github_membership` credential for their DID.
async fn verify_github(
    State(state): State<Arc<SharedState>>,
    Json(req): Json<GitHubVerifyRequest>,
) -> impl IntoResponse {
    let engine = match get_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };

    // Validate inputs
    if req.did.is_empty() || req.github_username.is_empty() || req.org.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(CredentialResponse {
                status: "error".into(),
                credential_type: "github_membership".into(),
                issuer: "github".into(),
                error: Some("did, github_username, and org are required".into()),
                metadata: None,
            }),
        )
            .into_response();
    }

    // Validate GitHub username and org name to prevent URL injection.
    // GitHub names: 1-39 chars, alphanumeric or hyphens, no path separators.
    fn is_valid_github_name(s: &str) -> bool {
        !s.is_empty() && s.len() <= 39 && s.chars().all(|c| c.is_alphanumeric() || c == '-')
    }

    if !is_valid_github_name(&req.org) || !is_valid_github_name(&req.github_username) {
        return (
            StatusCode::BAD_REQUEST,
            Json(CredentialResponse {
                status: "error".into(),
                credential_type: "github_membership".into(),
                issuer: "github".into(),
                error: Some("invalid github_username or org format".into()),
                metadata: None,
            }),
        )
            .into_response();
    }

    // Check GitHub API for public org membership
    // GET https://api.github.com/orgs/{org}/public_members/{username}
    // Returns 204 if member, 404 if not
    let client = reqwest::Client::new();
    let url = format!(
        "https://api.github.com/orgs/{}/public_members/{}",
        req.org, req.github_username
    );

    let result = client
        .get(&url)
        .header("User-Agent", "freeq-server")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await;

    match result {
        Ok(resp) if resp.status().as_u16() == 204 => {
            // Verified! Store credential
            let metadata = serde_json::json!({
                "github_username": req.github_username,
                "org": req.org,
                "verified_at": chrono::Utc::now().to_rfc3339(),
            });

            match engine.store_credential(&req.did, "github_membership", "github", &metadata) {
                Ok(()) => {
                    tracing::info!(
                        did = %req.did, username = %req.github_username, org = %req.org,
                        "GitHub org membership verified"
                    );
                    Json(CredentialResponse {
                        status: "verified".into(),
                        credential_type: "github_membership".into(),
                        issuer: "github".into(),
                        error: None,
                        metadata: Some(metadata),
                    })
                    .into_response()
                }
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        Ok(resp) if resp.status().as_u16() == 404 => (
            StatusCode::FORBIDDEN,
            Json(CredentialResponse {
                status: "not_verified".into(),
                credential_type: "github_membership".into(),
                issuer: "github".into(),
                error: Some(format!(
                    "{} is not a public member of {}",
                    req.github_username, req.org
                )),
                metadata: None,
            }),
        )
            .into_response(),
        Ok(resp) => {
            let status = resp.status();
            (
                StatusCode::BAD_GATEWAY,
                Json(CredentialResponse {
                    status: "error".into(),
                    credential_type: "github_membership".into(),
                    issuer: "github".into(),
                    error: Some(format!("GitHub API returned {status}")),
                    metadata: None,
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(CredentialResponse {
                status: "error".into(),
                credential_type: "github_membership".into(),
                issuer: "github".into(),
                error: Some(format!("GitHub API error: {e}")),
                metadata: None,
            }),
        )
            .into_response(),
    }
}

/// Present a verifiable credential issued by an external service.
/// The server verifies the signature and stores it if valid.
#[derive(Debug, Deserialize)]
struct PresentCredentialRequest {
    /// The VerifiableCredential JSON.
    credential: super::types::VerifiableCredential,
}

#[derive(Debug, Serialize)]
struct PresentCredentialResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn present_credential(
    State(state): State<Arc<SharedState>>,
    Json(req): Json<PresentCredentialRequest>,
) -> impl IntoResponse {
    let engine = match get_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };

    let vc = &req.credential;

    // Basic checks
    if vc.credential_type_tag != "FreeqCredential/v1" {
        return (
            StatusCode::BAD_REQUEST,
            Json(PresentCredentialResponse {
                status: "error".into(),
                error: Some("Unknown credential type".into()),
            }),
        )
            .into_response();
    }

    if vc.is_expired() {
        return (
            StatusCode::BAD_REQUEST,
            Json(PresentCredentialResponse {
                status: "error".into(),
                error: Some("Credential has expired".into()),
            }),
        )
            .into_response();
    }

    // Resolve issuer DID → get public key
    let resolver = &state.did_resolver;
    let issuer_key = match resolve_issuer_key(resolver, &vc.issuer).await {
        Ok(key) => key,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(PresentCredentialResponse {
                    status: "error".into(),
                    error: Some(format!("Cannot resolve issuer {}: {e}", vc.issuer)),
                }),
            )
                .into_response();
        }
    };

    // Verify signature
    match super::credentials::verify_credential(vc, &vc.subject, &issuer_key) {
        Ok(()) => {}
        Err(e) => {
            return (
                StatusCode::FORBIDDEN,
                Json(PresentCredentialResponse {
                    status: "error".into(),
                    error: Some(e),
                }),
            )
                .into_response();
        }
    }

    // Valid! Store as a local credential
    if let Err(e) =
        engine.store_credential(&vc.subject, &vc.credential_type, &vc.issuer, &vc.claims)
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    tracing::info!(
        subject = %vc.subject, issuer = %vc.issuer, cred_type = %vc.credential_type,
        "External verifiable credential accepted"
    );

    Json(PresentCredentialResponse {
        status: "accepted".into(),
        error: None,
    })
    .into_response()
}

/// Resolve an issuer DID to an Ed25519 public key.
///
/// Looks for a verification method with `publicKeyMultibase` containing
/// an Ed25519 key in the DID document.
async fn resolve_issuer_key(
    resolver: &freeq_sdk::did::DidResolver,
    issuer_did: &str,
) -> Result<[u8; 32], String> {
    let did_doc = resolver
        .resolve(issuer_did)
        .await
        .map_err(|e| format!("DID resolution failed: {e}"))?;

    // Look for Ed25519 key in verification methods
    for method in &did_doc.verification_method {
        if let Some(ref multibase) = method.public_key_multibase
            && let Some(key) = decode_multibase_ed25519(multibase)
        {
            return Ok(key);
        }
    }

    // Also check assertionMethod (inline methods)
    for entry in &did_doc.assertion_method {
        if let freeq_sdk::did::StringOrMap::Inline(method) = entry
            && let Some(ref multibase) = method.public_key_multibase
            && let Some(key) = decode_multibase_ed25519(multibase)
        {
            return Ok(key);
        }
    }

    Err("No Ed25519 public key found in issuer DID document".into())
}

/// Decode a multibase-encoded Ed25519 public key.
/// Expects 'z' prefix (base58btc) followed by multicodec 0xed01 + 32 bytes.
fn decode_multibase_ed25519(multibase: &str) -> Option<[u8; 32]> {
    if !multibase.starts_with('z') {
        return None;
    }
    let bytes = bs58::decode(&multibase[1..]).into_vec().ok()?;
    // Multicodec ed25519-pub: 0xed, 0x01 prefix (2 bytes) + 32-byte key
    if bytes.len() == 34 && bytes[0] == 0xed && bytes[1] == 0x01 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[2..]);
        Some(key)
    } else if bytes.len() == 32 {
        // Raw key without multicodec prefix
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Some(key)
    } else {
        None
    }
}

/// Decode an Ed25519 public key from JWK.
#[allow(dead_code)]
fn decode_jwk_ed25519(jwk: &serde_json::Value) -> Option<[u8; 32]> {
    use base64::Engine;
    let kty = jwk.get("kty")?.as_str()?;
    let crv = jwk.get("crv")?.as_str()?;
    if kty != "OKP" || crv != "Ed25519" {
        return None;
    }
    let x = jwk.get("x")?.as_str()?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x)
        .ok()?;
    if bytes.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Some(key)
    } else {
        None
    }
}

/// Get all credentials for a DID.
async fn get_credentials(
    State(state): State<Arc<SharedState>>,
    Path(did): Path<String>,
) -> impl IntoResponse {
    let engine = match get_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };

    match engine.store().get_credentials(&did) {
        Ok(creds) => Json(creds).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ─── Personalized Requirements Check ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CheckRequest {
    /// DID of the user checking requirements.
    did: String,
}

#[derive(Debug, Serialize)]
struct CheckResponse {
    channel: String,
    /// Whether the user can currently join.
    can_join: bool,
    /// Overall status: "open", "satisfied", "unsatisfied", "no_policy".
    status: String,
    /// Per-requirement status.
    requirements: Vec<RequirementStatus>,
    /// Role the user would get if they joined now.
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
}

#[derive(Debug, Serialize)]
struct RequirementStatus {
    /// "accept", "present", "prove"
    requirement_type: String,
    /// Human-readable description.
    description: String,
    /// Whether this requirement is currently satisfied.
    satisfied: bool,
    /// For PRESENT: credential endpoint info (if in policy).
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<RequirementAction>,
}

#[derive(Debug, Serialize)]
struct RequirementAction {
    /// "accept_rules", "verify_external"
    action_type: String,
    /// URL to start verification (for external credentials).
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    /// Button label.
    label: String,
    /// Hash to accept (for ACCEPT requirements).
    #[serde(skip_serializing_if = "Option::is_none")]
    accept_hash: Option<String>,
}

/// Check what a specific user needs to join a policy-gated channel.
/// Returns per-requirement status and action URLs.
async fn check_requirements(
    State(state): State<Arc<SharedState>>,
    Path(channel): Path<String>,
    Json(req): Json<CheckRequest>,
) -> impl IntoResponse {
    let engine = match get_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let channel_id = normalize_channel(&channel);

    // Get policy
    let policy = match engine.get_policy(&channel_id) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Json(CheckResponse {
                channel: channel_id,
                can_join: true,
                status: "no_policy".into(),
                requirements: vec![],
                role: None,
            })
            .into_response();
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // Check if user already has attestation
    if let Ok(Some(att)) = engine.check_membership(&channel_id, &req.did) {
        return Json(CheckResponse {
            channel: channel_id,
            can_join: true,
            status: "satisfied".into(),
            requirements: vec![],
            role: Some(att.role),
        })
        .into_response();
    }

    // Build evidence from stored credentials
    let evidence = engine
        .build_evidence(&req.did, collect_accept_hashes(&policy))
        .unwrap_or_else(|_| super::eval::UserEvidence {
            accepted_hashes: HashSet::new(),
            credentials: vec![],
            proofs: HashSet::new(),
        });

    // Evaluate each requirement
    let mut requirements = vec![];
    flatten_requirements(
        &policy.requirements,
        &evidence,
        &policy.credential_endpoints,
        &req.did,
        &mut requirements,
    );

    let all_satisfied = requirements.iter().all(|r| r.satisfied);

    // Determine role
    let role = if all_satisfied {
        let mut role = "member".to_string();
        for (role_name, role_req) in policy.role_requirements.iter().rev() {
            if super::eval::evaluate(role_req, &evidence).is_satisfied() {
                role = role_name.clone();
                break;
            }
        }
        Some(role)
    } else {
        None
    };

    Json(CheckResponse {
        channel: channel_id,
        can_join: all_satisfied,
        status: if all_satisfied {
            "satisfied".into()
        } else {
            "unsatisfied".into()
        },
        requirements,
        role,
    })
    .into_response()
}

/// Flatten a requirement tree into individual statuses with actions.
fn flatten_requirements(
    req: &super::types::Requirement,
    evidence: &super::eval::UserEvidence,
    endpoints: &std::collections::BTreeMap<String, super::types::CredentialEndpoint>,
    subject_did: &str,
    out: &mut Vec<RequirementStatus>,
) {
    use super::types::Requirement;
    match req {
        // Open join gate — nothing for the user to satisfy.
        Requirement::Open => {}
        Requirement::Accept { hash } => {
            let satisfied = evidence.accepted_hashes.contains(hash);
            out.push(RequirementStatus {
                requirement_type: "accept".into(),
                description: "Accept the channel rules".into(),
                satisfied,
                action: if satisfied {
                    None
                } else {
                    Some(RequirementAction {
                        action_type: "accept_rules".into(),
                        url: None,
                        label: "Accept Rules".into(),
                        accept_hash: Some(hash.clone()),
                    })
                },
            });
        }
        Requirement::Present {
            credential_type,
            issuer,
        } => {
            let satisfied = evidence.credentials.iter().any(|c| {
                c.credential_type == *credential_type
                    && issuer.as_ref().is_none_or(|iss| c.issuer == *iss)
            });
            let action = if satisfied {
                None
            } else {
                endpoints.get(credential_type).map(|ep| {
                    // Build verification URL with subject_did and callback params
                    let sep = if ep.url.contains('?') { '&' } else { '?' };
                    let url = format!(
                        "{}{}subject_did={}&callback=/api/v1/credentials/present",
                        ep.url,
                        sep,
                        urlencoding::encode(subject_did),
                    );
                    RequirementAction {
                        action_type: "verify_external".into(),
                        url: Some(url),
                        label: ep.label.clone(),
                        accept_hash: None,
                    }
                })
            };
            let desc = match issuer {
                Some(iss) => format!("Credential: {} (from {})", credential_type, iss),
                None => format!("Credential: {}", credential_type),
            };
            out.push(RequirementStatus {
                requirement_type: "present".into(),
                description: desc,
                satisfied,
                action,
            });
        }
        Requirement::Prove { proof_type } => {
            let satisfied = evidence.proofs.contains(proof_type);
            out.push(RequirementStatus {
                requirement_type: "prove".into(),
                description: format!("Prove: {}", proof_type),
                satisfied,
                action: None,
            });
        }
        Requirement::All { requirements } => {
            for r in requirements {
                flatten_requirements(r, evidence, endpoints, subject_did, out);
            }
        }
        Requirement::Any { requirements } => {
            // For ANY, show all options but mark the group
            for r in requirements {
                flatten_requirements(r, evidence, endpoints, subject_did, out);
            }
        }
        Requirement::Not { requirement } => {
            flatten_requirements(requirement, evidence, endpoints, subject_did, out);
        }
    }
}

/// Collect all ACCEPT hashes from a policy (requirements + role requirements).
fn collect_accept_hashes(policy: &super::types::PolicyDocument) -> HashSet<String> {
    let mut hashes = HashSet::new();
    collect_hashes_from_req(&policy.requirements, &mut hashes);
    for req in policy.role_requirements.values() {
        collect_hashes_from_req(req, &mut hashes);
    }
    hashes
}

fn collect_hashes_from_req(req: &super::types::Requirement, out: &mut HashSet<String>) {
    use super::types::Requirement;
    match req {
        Requirement::Accept { hash } => {
            out.insert(hash.clone());
        }
        Requirement::All { requirements } | Requirement::Any { requirements } => {
            for r in requirements {
                collect_hashes_from_req(r, out);
            }
        }
        Requirement::Not { requirement } => {
            collect_hashes_from_req(requirement, out);
        }
        _ => {}
    }
}
