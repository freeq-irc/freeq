//! IRC POLICY command handler.
//!
//! POLICY <channel> SET <rules_text>                   — Set an ACCEPT join gate (rules), preserving roles
//! POLICY <channel> OPEN                               — Open join gate (no rules), preserving roles
//! POLICY <channel> SET-ROLE <role> <requirement_json> — Add role escalation requirement
//! POLICY <channel> VERIFY github <username> <org>     — Verify GitHub org membership
//! POLICY <channel> INFO                               — Show current policy
//! POLICY <channel> RULES                              — Show the human-readable rules text
//! POLICY <channel> ACCEPT                             — Accept policy + present credentials
//! POLICY <channel> CLEAR                              — Remove policy (ops only)

use crate::irc::Message;
use crate::policy::canonical;
use crate::policy::eval::UserEvidence;
use crate::policy::types::*;
use crate::server::SharedState;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use super::helpers::{s2s_broadcast, s2s_next_event_id};

pub(super) fn handle_policy(
    conn: &super::Connection,
    msg: &Message,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send_fn: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let nick = conn.nick_or_star();

    let engine = match &state.policy_engine {
        Some(e) => e,
        None => {
            let reply = Message::from_server(
                server_name,
                "NOTICE",
                vec![nick, "Policy framework is not enabled on this server"],
            );
            send_fn(state, session_id, format!("{reply}\r\n"));
            return;
        }
    };

    if msg.params.len() < 2 {
        let reply = Message::from_server(
            server_name,
            "NOTICE",
            vec![
                nick,
                "Usage: POLICY <channel> SET|OPEN|SET-ROLE|REQUIRE|VERIFY|INFO|RULES|ACCEPT|CLEAR",
            ],
        );
        send_fn(state, session_id, format!("{reply}\r\n"));
        return;
    }

    let channel = &msg.params[0];
    let subcommand = msg.params[1].to_uppercase();

    if !channel.starts_with('#') {
        let reply = Message::from_server(
            server_name,
            "NOTICE",
            vec![nick, "POLICY only applies to channels"],
        );
        send_fn(state, session_id, format!("{reply}\r\n"));
        return;
    }

    match subcommand.as_str() {
        "SET" => {
            // Require ops
            if !is_channel_op(
                state,
                channel,
                session_id,
                conn.authenticated_did.as_deref(),
            ) {
                let reply = Message::from_server(
                    server_name,
                    "482", // ERR_CHANOPRIVSNEEDED
                    vec![nick, channel, "You're not channel operator"],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
                return;
            }

            // Get rules text from remaining params
            let rules_text = if msg.params.len() > 2 {
                msg.params[2..].join(" ")
            } else {
                let reply = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec![nick, "Usage: POLICY <channel> SET <rules text>"],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
                return;
            };

            let rules_hash = canonical::sha256_hex(rules_text.as_bytes());

            // Persist the plaintext rules keyed by their hash so they can be
            // read back later (POLICY <ch> RULES / GET .../rules). The hash
            // remains the verification source of truth; this is additive.
            // NOTE: rules text is stored only on the setting server — it is not
            // propagated over S2S, so peers that receive this policy get only
            // the hash and their RULES command reports "text not available".
            if let Err(e) = engine.store_rules_text(&rules_hash, &rules_text) {
                tracing::warn!(channel = %channel, error = %e, "Failed to store policy rules text");
            }

            // Check if channel already has a policy
            let result = match engine.get_policy(channel) {
                Ok(Some(current)) => {
                    // Update the join gate to the new rules, but PRESERVE any
                    // existing role requirements (e.g. op → github credential)
                    // and credential endpoints. Changing the rules text must not
                    // silently drop op-gating.
                    engine.update_channel_policy_with_endpoints(
                        channel,
                        Requirement::Accept {
                            hash: rules_hash.clone(),
                        },
                        current.role_requirements.clone(),
                        current.credential_endpoints.clone(),
                    )
                }
                Ok(None) => {
                    // Create new
                    engine
                        .create_channel_policy(
                            channel,
                            Requirement::Accept {
                                hash: rules_hash.clone(),
                            },
                            BTreeMap::new(),
                        )
                        .map(|(p, _)| p)
                }
                Err(e) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, &format!("Policy error: {e}")],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                    return;
                }
            };

            match result {
                Ok(policy) => {
                    let pid = policy.policy_id.as_deref().unwrap_or("?");
                    let notice = format!(
                        "Policy set for {channel} (version {}, rules_hash={}, policy_id={})",
                        policy.version,
                        &rules_hash[..12],
                        &pid[..12.min(pid.len())]
                    );
                    let reply = Message::from_server(server_name, "NOTICE", vec![nick, &notice]);
                    send_fn(state, session_id, format!("{reply}\r\n"));

                    // Auto-attest the op who set the policy
                    if let Some(did) = &conn.authenticated_did {
                        let evidence = UserEvidence {
                            accepted_hashes: HashSet::from([rules_hash]),
                            credentials: vec![],
                            proofs: HashSet::new(),
                        };
                        let _ = engine.process_join(channel, did, &evidence);
                    }

                    // Broadcast policy to S2S peers
                    let origin = state.server_iroh_id.lock().clone().unwrap_or_default();
                    let auth_set_json = engine
                        .store()
                        .get_authority_set(&policy.authority_set_hash)
                        .ok()
                        .flatten()
                        .and_then(|a| serde_json::to_string(&a).ok());
                    s2s_broadcast(
                        state,
                        crate::s2s::S2sMessage::PolicySync {
                            event_id: s2s_next_event_id(state),
                            channel: channel.to_string(),
                            policy_json: serde_json::to_string(&policy).ok(),
                            authority_set_json: auth_set_json,
                            origin,
                        },
                    );
                }
                Err(e) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, &format!("Failed to set policy: {e}")],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                }
            }
        }

        "SET-ROLE" => {
            // POLICY #channel SET-ROLE <role> <requirement_json>
            // e.g. POLICY #channel SET-ROLE op {"type":"ALL","requirements":[{"type":"ACCEPT","hash":"abc"},{"type":"PRESENT","credential_type":"github_membership","issuer":"github"}]}
            if !is_channel_op(
                state,
                channel,
                session_id,
                conn.authenticated_did.as_deref(),
            ) {
                let reply = Message::from_server(
                    server_name,
                    "482",
                    vec![nick, channel, "You're not channel operator"],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
                return;
            }

            if msg.params.len() < 4 {
                let reply = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec![
                        nick,
                        "Usage: POLICY <channel> SET-ROLE <role_name> <requirement_json>",
                    ],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
                return;
            }

            let role_name = msg.params[2].to_lowercase();
            let json_str = msg.params[3..].join(" ");

            let requirement: Requirement = match serde_json::from_str(&json_str) {
                Ok(r) => r,
                Err(e) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, &format!("Invalid requirement JSON: {e}")],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                    return;
                }
            };

            // Get current policy, add/update role requirement, create new version
            let current = match engine.get_policy(channel) {
                Ok(Some(p)) => p,
                Ok(None) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![
                            nick,
                            "Set a base policy first with POLICY <channel> SET <rules>",
                        ],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                    return;
                }
                Err(e) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, &format!("Policy error: {e}")],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                    return;
                }
            };

            let mut role_reqs = current.role_requirements.clone();
            role_reqs.insert(role_name.clone(), requirement);

            match engine.update_channel_policy(channel, current.requirements.clone(), role_reqs) {
                Ok(policy) => {
                    let pid = policy.policy_id.as_deref().unwrap_or("?");
                    let notice = format!(
                        "Role '{}' requirement set for {} (version {}, policy_id={})",
                        role_name,
                        channel,
                        policy.version,
                        &pid[..12.min(pid.len())]
                    );
                    let reply = Message::from_server(server_name, "NOTICE", vec![nick, &notice]);
                    send_fn(state, session_id, format!("{reply}\r\n"));

                    // Broadcast to S2S
                    let origin = state.server_iroh_id.lock().clone().unwrap_or_default();
                    let auth_set_json = engine
                        .store()
                        .get_authority_set(&policy.authority_set_hash)
                        .ok()
                        .flatten()
                        .and_then(|a| serde_json::to_string(&a).ok());
                    s2s_broadcast(
                        state,
                        crate::s2s::S2sMessage::PolicySync {
                            event_id: s2s_next_event_id(state),
                            channel: channel.to_string(),
                            policy_json: serde_json::to_string(&policy).ok(),
                            authority_set_json: auth_set_json,
                            origin,
                        },
                    );
                }
                Err(e) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, &format!("Failed to set role: {e}")],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                }
            }
        }

        "VERIFY" => {
            // POLICY #channel VERIFY github <org>
            // Verifies GitHub org membership via OAuth (if configured)
            // or public API fallback.
            let did = match &conn.authenticated_did {
                Some(d) => d.clone(),
                None => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, "You must be authenticated to verify credentials"],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                    return;
                }
            };

            if msg.params.len() < 4 {
                let reply = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec![
                        nick,
                        "Usage: POLICY <channel> VERIFY <github|bluesky> <target>",
                    ],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
                return;
            }

            let provider = msg.params[2].to_lowercase();
            if provider != "github" && provider != "bluesky" {
                let reply = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec![nick, "Supported providers: github, bluesky"],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
                return;
            }

            let target = &msg.params[3];

            // Bluesky follower verification — no OAuth needed, uses public API
            if provider == "bluesky" {
                let origin = format!("https://{}", state.config.server_name);
                let target_handle = target.trim_start_matches('@');
                let verify_url = format!(
                    "{}/verify/bluesky/start?subject_did={}&target={}&callback={}/api/v1/credentials/present",
                    origin,
                    urlencoding::encode(&did),
                    urlencoding::encode(target_handle),
                    urlencoding::encode(&origin),
                );
                let reply = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec![
                        nick,
                        &format!(
                            "Open this URL to verify you follow @{target_handle} on Bluesky: {verify_url}"
                        ),
                    ],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
                return;
            }

            if state.config.github_client_id.is_some() {
                // OAuth mode — redirect user to GitHub
                let origin = format!("https://{}", state.config.server_name);

                // Detect if target is owner/repo or just an org name
                let query_param = if target.contains('/') {
                    format!("repo={}", urlencoding::encode(target))
                } else {
                    format!("org={}", urlencoding::encode(target))
                };

                let verify_url = format!(
                    "{}/verify/github/start?subject_did={}&{}&callback={}/api/v1/credentials/present",
                    origin,
                    urlencoding::encode(&did),
                    query_param,
                    urlencoding::encode(&origin),
                );
                let reply = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec![
                        nick,
                        &format!("Open this URL to verify your GitHub identity: {verify_url}"),
                    ],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
            } else {
                // No OAuth configured. The public-API fallback below can NOT
                // prove the caller owns the GitHub account they name — anyone
                // can claim any public org member's username — yet it stores a
                // `github_membership` credential that satisfies PRESENT
                // requirements and role escalation exactly like the OAuth-
                // verified one. Fail closed unless the operator explicitly
                // opts into the spoofable check (dev/demo only).
                let allow_unverified = std::env::var("FREEQ_ALLOW_UNVERIFIED_GITHUB")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                if !allow_unverified {
                    for line in [
                        "GitHub verification is not available: no GitHub OAuth app is configured.",
                        "Ask the operator to set GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET (the public-API fallback cannot prove account ownership and is disabled; FREEQ_ALLOW_UNVERIFIED_GITHUB=1 enables it for dev/demo).",
                    ] {
                        let reply = Message::from_server(server_name, "NOTICE", vec![nick, line]);
                        send_fn(state, session_id, format!("{reply}\r\n"));
                    }
                    return;
                }
                // Fall back to public membership check (opt-in, unverified).
                // This requires the user to also provide their GitHub username
                if msg.params.len() < 5 {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![
                            nick,
                            "No GitHub OAuth configured. Usage: POLICY <channel> VERIFY github <org> <github-username>",
                        ],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                    let reply2 = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![
                            nick,
                            "⚠ Note: public API check cannot prove you own this GitHub account",
                        ],
                    );
                    send_fn(state, session_id, format!("{reply2}\r\n"));
                    return;
                }

                let username = &msg.params[4];
                let engine_ref = Arc::clone(engine);
                let did_c = did.clone();
                let username_c = username.to_string();
                let org_c = target.to_string();
                let state_c = Arc::clone(state);
                let session_c = session_id.to_string();
                let server_c = server_name.to_string();
                let nick_c = nick.to_string();

                let reply = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec![
                        nick,
                        &format!(
                            "Checking GitHub: is {} a public member of {}? (unverified — no OAuth)",
                            username, target
                        ),
                    ],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));

                tokio::spawn(async move {
                    let client = reqwest::Client::new();
                    let url = format!(
                        "https://api.github.com/orgs/{}/public_members/{}",
                        org_c, username_c
                    );
                    let result = client
                        .get(&url)
                        .header("User-Agent", "freeq-server")
                        .header("Accept", "application/vnd.github+json")
                        .send()
                        .await;

                    let msg_text = match result {
                        Ok(resp) if resp.status().as_u16() == 204 => {
                            let metadata = serde_json::json!({
                                "github_username": username_c,
                                "org": org_c,
                                "verified_at": chrono::Utc::now().to_rfc3339(),
                                "method": "public_api",
                            });
                            match engine_ref.store_credential(
                                &did_c,
                                "github_membership",
                                "github",
                                &metadata,
                            ) {
                                Ok(()) => format!(
                                    "✓ {} is a public member of {}. Credential stored (⚠ not OAuth-verified).",
                                    username_c, org_c
                                ),
                                Err(e) => format!("Verified but failed to store: {e}"),
                            }
                        }
                        Ok(resp) if resp.status().as_u16() == 404 => {
                            format!(
                                "✗ {} is NOT a public member of {}. Make your membership public at https://github.com/orgs/{}/people",
                                username_c, org_c, org_c
                            )
                        }
                        Ok(resp) => {
                            format!("GitHub API returned {}", resp.status())
                        }
                        Err(e) => {
                            format!("GitHub API error: {e}")
                        }
                    };

                    let reply = Message::from_server(&server_c, "NOTICE", vec![&nick_c, &msg_text]);
                    let conns = state_c.connections.lock();
                    if let Some(tx) = conns.get(&session_c) {
                        let _ = tx.try_send(format!("{reply}\r\n"));
                    }
                });
            }
        }

        "INFO" => match engine.get_policy(channel) {
            Ok(Some(policy)) => {
                let pid = policy.policy_id.as_deref().unwrap_or("unknown");
                let lines = [
                    format!("Policy for {channel}:"),
                    format!("  Version: {}", policy.version),
                    format!("  Policy ID: {pid}"),
                    format!("  Effective: {}", policy.effective_at),
                    format!("  Validity: {:?}", policy.validity_model),
                    format!(
                        "  Requirement: {}",
                        describe_requirement(&policy.requirements)
                    ),
                ];
                for line in &lines {
                    let reply = Message::from_server(server_name, "NOTICE", vec![nick, line]);
                    send_fn(state, session_id, format!("{reply}\r\n"));
                }
                if !policy.role_requirements.is_empty() {
                    for (role, req) in &policy.role_requirements {
                        let desc = format!("  Role '{}': {}", role, describe_requirement(req));
                        let reply = Message::from_server(server_name, "NOTICE", vec![nick, &desc]);
                        send_fn(state, session_id, format!("{reply}\r\n"));
                    }
                }
            }
            Ok(None) => {
                let reply = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec![nick, &format!("{channel} has no policy (open join)")],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
            }
            Err(e) => {
                let reply = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec![nick, &format!("Policy error: {e}")],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
            }
        },

        "RULES" => match engine.get_policy(channel) {
            Ok(Some(policy)) => {
                // Pull the ACCEPT hash out of the requirement tree, then look
                // up the plaintext we stored at SET time. The hash is included
                // in the output so the reader can independently verify the text.
                let hash = extract_accept_hash(&policy.requirements).into_iter().next();
                match hash {
                    Some(h) => match engine.get_rules_text(&h) {
                        Ok(Some(text)) => {
                            let header = format!("Rules for {channel} (rules_hash={h}):");
                            let reply =
                                Message::from_server(server_name, "NOTICE", vec![nick, &header]);
                            send_fn(state, session_id, format!("{reply}\r\n"));
                            // One NOTICE per line, like the INFO arm.
                            for line in text.split('\n') {
                                let reply =
                                    Message::from_server(server_name, "NOTICE", vec![nick, line]);
                                send_fn(state, session_id, format!("{reply}\r\n"));
                            }
                        }
                        Ok(None) => {
                            let msg = format!(
                                "Rules text isn't available for this policy (rules_hash={h}; set before rules were stored, or received over S2S). Ask an op to re-run POLICY {channel} SET <rules>."
                            );
                            let reply =
                                Message::from_server(server_name, "NOTICE", vec![nick, &msg]);
                            send_fn(state, session_id, format!("{reply}\r\n"));
                        }
                        Err(e) => {
                            let reply = Message::from_server(
                                server_name,
                                "NOTICE",
                                vec![nick, &format!("Policy error: {e}")],
                            );
                            send_fn(state, session_id, format!("{reply}\r\n"));
                        }
                    },
                    None => {
                        // Policy exists but has no ACCEPT requirement (e.g. a
                        // pure PRESENT/PROVE policy) — there are no rules to read.
                        let reply = Message::from_server(
                            server_name,
                            "NOTICE",
                            vec![
                                nick,
                                "This policy has no rules text (no ACCEPT requirement)",
                            ],
                        );
                        send_fn(state, session_id, format!("{reply}\r\n"));
                    }
                }
            }
            Ok(None) => {
                let reply = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec![nick, &format!("{channel} has no policy (open join)")],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
            }
            Err(e) => {
                let reply = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec![nick, &format!("Policy error: {e}")],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
            }
        },

        "ACCEPT" => {
            let did = match &conn.authenticated_did {
                Some(d) => d.clone(),
                None => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, "You must be authenticated to accept a policy"],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                    return;
                }
            };

            // Get current policy and its rules hash
            let policy = match engine.get_policy(channel) {
                Ok(Some(p)) => p,
                Ok(None) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, &format!("{channel} has no policy — just JOIN it")],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                    return;
                }
                Err(e) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, &format!("Policy error: {e}")],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                    return;
                }
            };

            // Extract ACCEPT hashes from the requirement tree, then
            // auto-collect stored credentials (e.g. verified GitHub membership)
            let accepted_hashes: HashSet<String> = extract_accept_hash(&policy.requirements)
                .into_iter()
                .chain(extract_accept_hash_from_roles(&policy.role_requirements))
                .collect();
            let evidence = match engine.build_evidence(&did, accepted_hashes) {
                Ok(e) => e,
                Err(err) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, &format!("Error building evidence: {err}")],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                    return;
                }
            };

            match engine.process_join(channel, &did, &evidence) {
                Ok(crate::policy::JoinResult::Confirmed { attestation, .. }) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![
                            nick,
                            &format!(
                                "Policy accepted for {channel} — role: {}. You may now JOIN.",
                                attestation.role
                            ),
                        ],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                }
                Ok(crate::policy::JoinResult::Failed(reason)) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, &format!("Policy acceptance failed: {reason}")],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                }
                Ok(_) => {}
                Err(e) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, &format!("Policy error: {e}")],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                }
            }
        }

        "CLEAR" => {
            // Require ops
            if !is_channel_op(
                state,
                channel,
                session_id,
                conn.authenticated_did.as_deref(),
            ) {
                let reply = Message::from_server(
                    server_name,
                    "482",
                    vec![nick, channel, "You're not channel operator"],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
                return;
            }

            match engine.remove_policy(channel) {
                Ok(true) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![
                            nick,
                            &format!("Policy removed from {channel} — channel is now open join"),
                        ],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));

                    // Broadcast clear to S2S peers
                    let origin = state.server_iroh_id.lock().clone().unwrap_or_default();
                    s2s_broadcast(
                        state,
                        crate::s2s::S2sMessage::PolicySync {
                            event_id: s2s_next_event_id(state),
                            channel: channel.to_string(),
                            policy_json: None,
                            authority_set_json: None,
                            origin,
                        },
                    );
                }
                Ok(false) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, &format!("{channel} has no policy to remove")],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                }
                Err(e) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, &format!("Failed to remove policy: {e}")],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                }
            }
        }

        "OPEN" => {
            // POLICY <channel> OPEN — set the join gate to Open (no rules to
            // accept, anyone may join) while PRESERVING any role requirements
            // (e.g. op → github credential) and credential endpoints. Use this
            // when you want an open channel that still gates op/roles.
            if !is_channel_op(
                state,
                channel,
                session_id,
                conn.authenticated_did.as_deref(),
            ) {
                let reply = Message::from_server(
                    server_name,
                    "482",
                    vec![nick, channel, "You're not channel operator"],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
                return;
            }

            let result = match engine.get_policy(channel) {
                Ok(Some(current)) => engine.update_channel_policy_with_endpoints(
                    channel,
                    Requirement::Open,
                    current.role_requirements.clone(),
                    current.credential_endpoints.clone(),
                ),
                Ok(None) => engine
                    .create_channel_policy(channel, Requirement::Open, BTreeMap::new())
                    .map(|(p, _)| p),
                Err(e) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, &format!("Policy error: {e}")],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                    return;
                }
            };

            match result {
                Ok(policy) => {
                    let notice = format!(
                        "Join gate for {channel} set to OPEN (version {}) — anyone may join; role requirements preserved",
                        policy.version
                    );
                    let reply = Message::from_server(server_name, "NOTICE", vec![nick, &notice]);
                    send_fn(state, session_id, format!("{reply}\r\n"));

                    let origin = state.server_iroh_id.lock().clone().unwrap_or_default();
                    let auth_set_json = engine
                        .store()
                        .get_authority_set(&policy.authority_set_hash)
                        .ok()
                        .flatten()
                        .and_then(|a| serde_json::to_string(&a).ok());
                    s2s_broadcast(
                        state,
                        crate::s2s::S2sMessage::PolicySync {
                            event_id: s2s_next_event_id(state),
                            channel: channel.to_string(),
                            policy_json: serde_json::to_string(&policy).ok(),
                            authority_set_json: auth_set_json,
                            origin,
                        },
                    );
                }
                Err(e) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, &format!("Failed to set open join gate: {e}")],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                }
            }
        }

        "REQUIRE" => {
            // POLICY #channel REQUIRE <credential_type> issuer=<did> url=<verify_url> label=<Button Text>
            // Adds a credential endpoint to the policy (UX metadata).
            if !is_channel_op(
                state,
                channel,
                session_id,
                conn.authenticated_did.as_deref(),
            ) {
                let reply = Message::from_server(
                    server_name,
                    "482",
                    vec![nick, channel, "You're not channel operator"],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
                return;
            }

            if msg.params.len() < 3 {
                let reply = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec![
                        nick,
                        "Usage: POLICY <channel> REQUIRE <credential_type> issuer=<did> url=<url> label=<text>",
                    ],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
                return;
            }

            let credential_type = msg.params[2].to_lowercase();
            let rest = msg.params[3..].join(" ");

            // Parse key=value pairs
            let mut issuer = String::new();
            let mut url = String::new();
            let mut label = format!("Verify {}", credential_type);

            for part in rest.split_whitespace() {
                if let Some(val) = part.strip_prefix("issuer=") {
                    issuer = val.to_string();
                } else if let Some(val) = part.strip_prefix("url=") {
                    url = val.to_string();
                } else if let Some(val) = part.strip_prefix("label=") {
                    label = val.replace('_', " ");
                }
            }

            if issuer.is_empty() || url.is_empty() {
                let reply = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec![nick, "issuer= and url= are required"],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
                return;
            }

            // Validate URL: must be a path or https URL, no HTML/script injection
            let decoded_url = urlencoding::decode(&url).unwrap_or(std::borrow::Cow::Borrowed(&url));
            if decoded_url.contains('<')
                || decoded_url.contains('>')
                || decoded_url.contains('"')
                || decoded_url.contains("javascript:")
            {
                let reply = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec![nick, "Invalid URL: contains forbidden characters"],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
                return;
            }
            if !url.starts_with('/') && !url.starts_with("https://") {
                let reply = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec![nick, "URL must be a relative path (/) or https:// URL"],
                );
                send_fn(state, session_id, format!("{reply}\r\n"));
                return;
            }

            // Get current policy and add credential endpoint
            let current = match engine.get_policy(channel) {
                Ok(Some(p)) => p,
                Ok(None) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![
                            nick,
                            "Set a base policy first with POLICY <channel> SET <rules>",
                        ],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                    return;
                }
                Err(e) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, &format!("Policy error: {e}")],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                    return;
                }
            };

            let endpoint = crate::policy::types::CredentialEndpoint {
                issuer: issuer.clone(),
                url: url.clone(),
                label: label.clone(),
                description: None,
            };

            // Update policy with new endpoint AND add PRESENT requirement
            let mut endpoints = current.credential_endpoints.clone();
            endpoints.insert(credential_type.clone(), endpoint);

            // Add a PRESENT requirement for this credential type to the requirement tree.
            // If the current requirements don't already include this credential type,
            // wrap existing + new PRESENT in an ALL.
            let present_req = crate::policy::types::Requirement::Present {
                credential_type: credential_type.clone(),
                issuer: Some(issuer.clone()),
            };

            let new_requirements =
                if already_requires_credential(&current.requirements, &credential_type) {
                    current.requirements.clone()
                } else {
                    match &current.requirements {
                        crate::policy::types::Requirement::All { requirements } => {
                            let mut reqs = requirements.clone();
                            reqs.push(present_req);
                            crate::policy::types::Requirement::All { requirements: reqs }
                        }
                        other => crate::policy::types::Requirement::All {
                            requirements: vec![other.clone(), present_req],
                        },
                    }
                };

            match engine.update_channel_policy_with_endpoints(
                channel,
                new_requirements,
                current.role_requirements.clone(),
                endpoints,
            ) {
                Ok(policy) => {
                    let notice = format!(
                        "Credential endpoint '{}' added to {} (issuer={}, version {})",
                        credential_type, channel, issuer, policy.version
                    );
                    let reply = Message::from_server(server_name, "NOTICE", vec![nick, &notice]);
                    send_fn(state, session_id, format!("{reply}\r\n"));

                    // Broadcast to S2S
                    let origin = state.server_iroh_id.lock().clone().unwrap_or_default();
                    s2s_broadcast(
                        state,
                        crate::s2s::S2sMessage::PolicySync {
                            event_id: s2s_next_event_id(state),
                            channel: channel.to_string(),
                            policy_json: serde_json::to_string(&policy).ok(),
                            authority_set_json: None,
                            origin,
                        },
                    );
                }
                Err(e) => {
                    let reply = Message::from_server(
                        server_name,
                        "NOTICE",
                        vec![nick, &format!("Failed: {e}")],
                    );
                    send_fn(state, session_id, format!("{reply}\r\n"));
                }
            }
        }

        _ => {
            let reply = Message::from_server(
                server_name,
                "NOTICE",
                vec![
                    nick,
                    "Usage: POLICY <channel> SET|OPEN|SET-ROLE|REQUIRE|VERIFY|INFO|RULES|ACCEPT|CLEAR",
                ],
            );
            send_fn(state, session_id, format!("{reply}\r\n"));
        }
    }
}

/// Check if session is a channel op.
fn is_channel_op(state: &SharedState, channel: &str, session_id: &str, did: Option<&str>) -> bool {
    let channels = state.channels.lock();
    if let Some(ch) = channels.get(channel) {
        if ch.ops.contains(session_id) {
            return true;
        }
        if let Some(d) = did
            && (ch.did_ops.contains(d) || ch.founder_did.as_deref() == Some(d))
        {
            return true;
        }
    }
    false
}

/// Extract ACCEPT hashes from role requirements too.
fn extract_accept_hash_from_roles(roles: &BTreeMap<String, Requirement>) -> HashSet<String> {
    let mut hashes = HashSet::new();
    for req in roles.values() {
        hashes.extend(extract_accept_hash(req));
    }
    hashes
}

/// Extract ACCEPT hash from a requirement tree (for simple ACCEPT-only policies).
/// Check if a requirement tree already contains a PRESENT for a given credential type.
fn already_requires_credential(req: &Requirement, credential_type: &str) -> bool {
    match req {
        Requirement::Present {
            credential_type: ct,
            ..
        } => ct == credential_type,
        Requirement::All { requirements } | Requirement::Any { requirements } => requirements
            .iter()
            .any(|r| already_requires_credential(r, credential_type)),
        Requirement::Not { requirement } => {
            already_requires_credential(requirement, credential_type)
        }
        _ => false,
    }
}

fn extract_accept_hash(req: &Requirement) -> HashSet<String> {
    let mut hashes = HashSet::new();
    match req {
        Requirement::Accept { hash } => {
            hashes.insert(hash.clone());
        }
        Requirement::All { requirements } | Requirement::Any { requirements } => {
            for r in requirements {
                hashes.extend(extract_accept_hash(r));
            }
        }
        Requirement::Not { requirement } => {
            hashes.extend(extract_accept_hash(requirement));
        }
        _ => {}
    }
    hashes
}

/// Human-readable description of a requirement.
fn describe_requirement(req: &Requirement) -> String {
    match req {
        Requirement::Open => "OPEN (no join gate — anyone may join)".to_string(),
        Requirement::Accept { hash } => format!("ACCEPT({}...)", &hash[..12.min(hash.len())]),
        Requirement::Present {
            credential_type,
            issuer,
        } => match issuer {
            Some(iss) => format!("PRESENT({credential_type}, issuer={iss})"),
            None => format!("PRESENT({credential_type})"),
        },
        Requirement::Prove { proof_type } => format!("PROVE({proof_type})"),
        Requirement::All { requirements } => {
            let inner: Vec<_> = requirements.iter().map(describe_requirement).collect();
            format!("ALL({})", inner.join(", "))
        }
        Requirement::Any { requirements } => {
            let inner: Vec<_> = requirements.iter().map(describe_requirement).collect();
            format!("ANY({})", inner.join(", "))
        }
        Requirement::Not { requirement } => {
            format!("NOT({})", describe_requirement(requirement))
        }
    }
}
