//! Policy engine — orchestrates the join flow, requirement evaluation,
//! and attestation issuance.
//!
//! This is the "authority server" logic that runs inside freeq-server.

use super::canonical;
use super::eval::{self, Credential, EvalResult, UserEvidence};
use super::store::{PolicyError, PolicyStore};
use super::types::*;
use chrono::Utc;
use std::collections::HashSet;

/// The policy engine — evaluates requirements and issues attestations.
pub struct PolicyEngine {
    store: PolicyStore,
    /// DID of this server (as an authority).
    authority_did: String,
    /// HMAC signing key for attestations (32 bytes, generated at startup).
    signing_key: [u8; 32],
}

/// Result of a join attempt.
#[derive(Debug)]
pub enum JoinResult {
    /// Join succeeded — attestation issued.
    Confirmed {
        attestation: MembershipAttestation,
        join_id: String,
    },
    /// Channel has no policy — open join (backwards compatible).
    NoPolicy,
    /// Join pending — additional requirements needed.
    Pending {
        join_id: String,
        missing: Vec<String>,
    },
    /// Join failed.
    Failed(String),
}

impl PolicyEngine {
    pub fn new(store: PolicyStore, authority_did: String) -> Self {
        let signing_key: [u8; 32] = rand::random();
        PolicyEngine {
            store,
            authority_did,
            signing_key,
        }
    }

    /// Create with a specific signing key (for testing/persistence).
    pub fn with_key(store: PolicyStore, authority_did: String, signing_key: [u8; 32]) -> Self {
        PolicyEngine {
            store,
            authority_did,
            signing_key,
        }
    }

    /// Access the underlying store.
    pub fn store(&self) -> &PolicyStore {
        &self.store
    }

    // ─── Channel Setup ───────────────────────────────────────────────────

    /// Create an initial policy and authority set for a channel.
    /// Returns (policy, authority_set).
    pub fn create_channel_policy(
        &self,
        channel_id: &str,
        requirements: Requirement,
        role_requirements: std::collections::BTreeMap<String, Requirement>,
    ) -> Result<(PolicyDocument, AuthoritySet), PolicyError> {
        // Validate requirements
        eval::validate_structure(&requirements).map_err(PolicyError::Validation)?;
        for (role, req) in &role_requirements {
            eval::validate_structure(req)
                .map_err(|e| PolicyError::Validation(format!("Role {role}: {e}")))?;
        }

        // Create authority set first (policy needs the hash)
        let auth_set = AuthoritySet {
            authority_set_hash: None,
            channel_id: channel_id.to_string(),
            signers: vec![AuthoritySigner {
                did: self.authority_did.clone(),
                public_key: format!("hmac-sha256:{}", canonical::sha256_hex(&self.signing_key)),
                label: Some("Primary authority".into()),
                endpoint: None,
            }],
            policy_threshold: 1,
            authority_refresh_ttl_seconds: 3600,
            transparency: Some(TransparencyConfig {
                visibility: "public".into(),
                mmd_seconds: 86400,
            }),
            previous_authority_set_hash: None,
        };
        let auth_set = self.store.store_authority_set(auth_set)?;
        let auth_hash = auth_set.authority_set_hash.clone().unwrap();

        // Create policy
        let policy = PolicyDocument {
            channel_id: channel_id.to_string(),
            policy_id: None,
            version: 1,
            effective_at: Utc::now().to_rfc3339(),
            previous_policy_hash: None,
            authority_set_hash: auth_hash,
            requirements,
            role_requirements,
            validity_model: ValidityModel::JoinTime,
            receipt_embedding: ReceiptEmbedding::Require,
            policy_locations: vec![],
            limits: None,
            transparency: None,
            credential_endpoints: std::collections::BTreeMap::new(),
            agent_budget: None,
            agent_budgets: std::collections::BTreeMap::new(),
        };
        let policy = self.store.store_policy(policy)?;

        Ok((policy, auth_set))
    }

    /// Update a channel's policy (creates a new version, chained to previous).
    pub fn update_channel_policy(
        &self,
        channel_id: &str,
        requirements: Requirement,
        role_requirements: std::collections::BTreeMap<String, Requirement>,
    ) -> Result<PolicyDocument, PolicyError> {
        // Validate
        eval::validate_structure(&requirements).map_err(PolicyError::Validation)?;

        let current = self
            .store
            .get_current_policy(channel_id)?
            .ok_or_else(|| PolicyError::Validation("No existing policy to update".into()))?;

        let policy = PolicyDocument {
            channel_id: channel_id.to_string(),
            policy_id: None,
            version: current.version + 1,
            effective_at: Utc::now().to_rfc3339(),
            previous_policy_hash: current.policy_id.clone(),
            authority_set_hash: current.authority_set_hash.clone(),
            requirements,
            role_requirements,
            validity_model: current.validity_model.clone(),
            receipt_embedding: current.receipt_embedding.clone(),
            policy_locations: current.policy_locations.clone(),
            limits: current.limits.clone(),
            transparency: current.transparency.clone(),
            credential_endpoints: current.credential_endpoints.clone(),
            agent_budget: current.agent_budget.clone(),
            agent_budgets: current.agent_budgets.clone(),
        };
        self.store.store_policy(policy)
    }

    /// Update a channel's policy with explicit credential endpoints.
    pub fn update_channel_policy_with_endpoints(
        &self,
        channel_id: &str,
        requirements: Requirement,
        role_requirements: std::collections::BTreeMap<String, Requirement>,
        credential_endpoints: std::collections::BTreeMap<
            String,
            crate::policy::types::CredentialEndpoint,
        >,
    ) -> Result<PolicyDocument, PolicyError> {
        eval::validate_structure(&requirements).map_err(PolicyError::Validation)?;

        let current = self
            .store
            .get_current_policy(channel_id)?
            .ok_or_else(|| PolicyError::Validation("No existing policy to update".into()))?;

        let policy = PolicyDocument {
            channel_id: channel_id.to_string(),
            policy_id: None,
            version: current.version + 1,
            effective_at: Utc::now().to_rfc3339(),
            previous_policy_hash: current.policy_id.clone(),
            authority_set_hash: current.authority_set_hash.clone(),
            requirements,
            role_requirements,
            validity_model: current.validity_model.clone(),
            receipt_embedding: current.receipt_embedding.clone(),
            policy_locations: current.policy_locations.clone(),
            limits: current.limits.clone(),
            transparency: current.transparency.clone(),
            credential_endpoints,
            agent_budget: current.agent_budget.clone(),
            agent_budgets: current.agent_budgets.clone(),
        };
        self.store.store_policy(policy)
    }

    // ─── Join Flow ───────────────────────────────────────────────────────

    /// Process a join request.
    ///
    /// For ACCEPT-only policies, the user provides `accepted_hashes` with
    /// the rules hash. For more complex requirements, additional evidence
    /// is needed.
    pub fn process_join(
        &self,
        channel_id: &str,
        subject_did: &str,
        evidence: &UserEvidence,
    ) -> Result<JoinResult, PolicyError> {
        // Get current policy
        let policy = match self.store.get_current_policy(channel_id)? {
            Some(p) => p,
            None => return Ok(JoinResult::NoPolicy),
        };

        let policy_id = policy.policy_id.clone().unwrap_or_default();

        // Check if user already has a valid attestation
        if let Some(existing) = self.store.get_attestation(channel_id, subject_did)? {
            // Check if attestation is for current policy
            if existing.policy_id == policy_id {
                // Check expiry for continuous validity
                if let Some(ref expires_at) = existing.expires_at {
                    if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires_at)
                        && exp > Utc::now()
                    {
                        let jid = existing.join_id.clone().unwrap_or_default();
                        return Ok(JoinResult::Confirmed {
                            attestation: existing,
                            join_id: jid,
                        });
                    }
                    // Expired — fall through to re-evaluate
                } else {
                    // No expiry (join_time model) — still valid
                    let jid = existing.join_id.clone().unwrap_or_default();
                    return Ok(JoinResult::Confirmed {
                        attestation: existing,
                        join_id: jid,
                    });
                }
            }
            // Policy changed — need to re-evaluate
        }

        // Evaluate requirements
        let result = eval::evaluate(&policy.requirements, evidence);
        match result {
            EvalResult::Satisfied => {
                // Generate join receipt
                let join_id = generate_join_id();
                let nonce = generate_nonce();
                let now = Utc::now().to_rfc3339();

                let receipt = JoinReceipt {
                    channel_id: channel_id.to_string(),
                    policy_id: policy_id.clone(),
                    join_id: join_id.clone(),
                    subject_did: subject_did.to_string(),
                    timestamp: now.clone(),
                    nonce,
                    embedded_policy: match policy.receipt_embedding {
                        ReceiptEmbedding::Require => Some(policy.clone()),
                        _ => None,
                    },
                    signature: String::new(), // Server-side receipt doesn't need user sig for MVP
                };
                self.store.store_join_receipt(&receipt)?;

                // Determine role
                let role = self.evaluate_role(subject_did, &policy, evidence);

                // Issue attestation
                let attestation = self.issue_attestation(
                    channel_id,
                    &policy_id,
                    &policy.authority_set_hash,
                    subject_did,
                    &role,
                    Some(&join_id),
                    &policy.validity_model,
                )?;

                // Confirm join
                self.store
                    .update_join_state(&join_id, JoinState::JoinConfirmed)?;

                Ok(JoinResult::Confirmed {
                    attestation,
                    join_id,
                })
            }
            EvalResult::Failed(reason) => Ok(JoinResult::Failed(reason)),
            EvalResult::Error(err) => Ok(JoinResult::Failed(format!("Evaluation error: {err}"))),
        }
    }

    /// Evaluate which role a user qualifies for.
    fn evaluate_role(
        &self,
        _subject_did: &str,
        policy: &PolicyDocument,
        evidence: &UserEvidence,
    ) -> String {
        // Check role requirements from highest to lowest priority
        // (order determined by BTreeMap key ordering)
        for (role_name, requirement) in policy.role_requirements.iter().rev() {
            if eval::evaluate(requirement, evidence).is_satisfied() {
                return role_name.clone();
            }
        }
        "member".to_string()
    }

    /// Issue a membership attestation.
    fn issue_attestation(
        &self,
        channel_id: &str,
        policy_id: &str,
        authority_set_hash: &str,
        subject_did: &str,
        role: &str,
        join_id: Option<&str>,
        validity_model: &ValidityModel,
    ) -> Result<MembershipAttestation, PolicyError> {
        let now = Utc::now();
        let expires_at = match validity_model {
            ValidityModel::Continuous => Some((now + chrono::Duration::hours(1)).to_rfc3339()),
            ValidityModel::JoinTime => None,
        };

        // Build attestation without signature, then sign the canonical form
        let mut attestation = MembershipAttestation {
            attestation_id: generate_attestation_id(),
            channel_id: channel_id.to_string(),
            policy_id: policy_id.to_string(),
            authority_set_hash: authority_set_hash.to_string(),
            subject_did: subject_did.to_string(),
            role: role.to_string(),
            issued_at: now.to_rfc3339(),
            expires_at,
            join_id: join_id.map(String::from),
            signature: String::new(),
            issuer_did: self.authority_did.clone(),
        };
        // Sign the attestation (HMAC-SHA256 over JCS-canonical form with empty signature)
        if let Ok(sig) = canonical::hmac_sign(&attestation, &self.signing_key) {
            attestation.signature = sig;
        }

        self.store.store_attestation(&attestation)?;

        Ok(attestation)
    }

    // ─── Query ───────────────────────────────────────────────────────────

    /// Check if a user has a valid attestation for a channel.
    pub fn check_membership(
        &self,
        channel_id: &str,
        subject_did: &str,
    ) -> Result<Option<MembershipAttestation>, PolicyError> {
        self.store.get_attestation(channel_id, subject_did)
    }

    /// Get the current policy for a channel.
    pub fn get_policy(&self, channel_id: &str) -> Result<Option<PolicyDocument>, PolicyError> {
        self.store.get_current_policy(channel_id)
    }

    /// Persist the human-readable rules text keyed by its hash.
    /// The hash stays the verification source of truth; this is auxiliary so
    /// the plaintext can be read back later (see POLICY <ch> RULES).
    pub fn store_rules_text(&self, hash: &str, text: &str) -> Result<(), PolicyError> {
        self.store.store_rules_text(hash, text)
    }

    /// Retrieve the human-readable rules text for a hash, if stored locally.
    /// Returns None for legacy policies (set before text was persisted) or
    /// policies received over S2S (which carry only the hash).
    pub fn get_rules_text(&self, hash: &str) -> Result<Option<String>, PolicyError> {
        self.store.get_rules_text(hash)
    }

    /// Verify the signature on an attestation.
    pub fn verify_attestation(&self, attestation: &MembershipAttestation) -> bool {
        let sig = attestation.signature.clone();
        let mut unsigned = attestation.clone();
        unsigned.signature = String::new();
        canonical::hmac_verify(&unsigned, &self.signing_key, &sig).unwrap_or(false)
    }

    /// Remove a channel's policy entirely.
    /// Returns true if a policy was removed.
    pub fn remove_policy(&self, channel_id: &str) -> Result<bool, PolicyError> {
        self.store.remove_channel_policy(channel_id)
    }

    /// Get the role for a user's current attestation (if any).
    /// Returns None if no valid attestation exists.
    pub fn get_member_role(
        &self,
        channel_id: &str,
        subject_did: &str,
    ) -> Result<Option<String>, PolicyError> {
        Ok(self
            .store
            .get_attestation(channel_id, subject_did)?
            .map(|a| a.role))
    }

    /// Get all channel members with valid attestations.
    pub fn get_channel_members(
        &self,
        channel_id: &str,
    ) -> Result<Vec<MembershipAttestation>, PolicyError> {
        self.store.get_channel_members(channel_id)
    }

    /// Build UserEvidence from a user's stored credentials + accepted hashes.
    /// This auto-collects all verified credentials for the user.
    pub fn build_evidence(
        &self,
        subject_did: &str,
        accepted_hashes: HashSet<String>,
    ) -> Result<UserEvidence, PolicyError> {
        let stored = self.store.get_credentials(subject_did)?;
        let credentials = stored
            .into_iter()
            .map(|c| Credential {
                credential_type: c.credential_type,
                issuer: c.issuer,
            })
            .collect();
        Ok(UserEvidence {
            accepted_hashes,
            credentials,
            proofs: HashSet::new(),
        })
    }

    /// Store a verified credential for a user.
    pub fn store_credential(
        &self,
        subject_did: &str,
        credential_type: &str,
        issuer: &str,
        metadata: &serde_json::Value,
    ) -> Result<(), PolicyError> {
        self.store
            .store_credential(subject_did, credential_type, issuer, metadata)
    }

    /// Invalidate expired attestations. Returns count of invalidated.
    pub fn revalidate_expired(&self) -> Result<usize, PolicyError> {
        let expired = self.store.get_expired_attestations()?;
        let count = expired.len();
        for att in &expired {
            self.store.invalidate_attestation(&att.attestation_id)?;
            tracing::debug!(
                channel = %att.channel_id, did = %att.subject_did,
                "Invalidated expired attestation"
            );
        }
        Ok(count)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn generate_join_id() -> String {
    let bytes: [u8; 16] = rand::random();
    hex::encode(bytes)
}

fn generate_nonce() -> String {
    let bytes: [u8; 16] = rand::random();
    hex::encode(bytes)
}

fn generate_attestation_id() -> String {
    let bytes: [u8; 16] = rand::random();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> PolicyEngine {
        let store = PolicyStore::open(":memory:").unwrap();
        PolicyEngine::new(store, "did:plc:testauthority".into())
    }

    #[test]
    fn test_create_and_join_accept_only() {
        let engine = test_engine();

        // Create channel with ACCEPT-only policy
        let rules_hash = canonical::sha256_hex(b"Be nice. No spam.");
        let (policy, _auth) = engine
            .create_channel_policy(
                "#test",
                Requirement::Accept {
                    hash: rules_hash.clone(),
                },
                std::collections::BTreeMap::new(),
            )
            .unwrap();

        assert_eq!(policy.version, 1);
        assert!(policy.policy_id.is_some());

        // Try to join without accepting rules
        let mut evidence = UserEvidence {
            accepted_hashes: HashSet::new(),
            credentials: vec![],
            proofs: HashSet::new(),
        };
        let result = engine
            .process_join("#test", "did:plc:user1", &evidence)
            .unwrap();
        assert!(matches!(result, JoinResult::Failed(_)));

        // Accept rules and join
        evidence.accepted_hashes.insert(rules_hash.clone());
        let result = engine
            .process_join("#test", "did:plc:user1", &evidence)
            .unwrap();
        match result {
            JoinResult::Confirmed { attestation, .. } => {
                assert_eq!(attestation.subject_did, "did:plc:user1");
                assert_eq!(attestation.role, "member");
                assert_eq!(attestation.channel_id, "#test");
            }
            other => panic!("Expected Confirmed, got {:?}", other),
        }
    }

    #[test]
    fn test_no_policy_allows_join() {
        let engine = test_engine();
        let evidence = UserEvidence {
            accepted_hashes: HashSet::new(),
            credentials: vec![],
            proofs: HashSet::new(),
        };
        let result = engine
            .process_join("#open", "did:plc:user1", &evidence)
            .unwrap();
        assert!(matches!(result, JoinResult::NoPolicy));
    }

    #[test]
    fn test_role_escalation() {
        let engine = test_engine();
        let rules_hash = canonical::sha256_hex(b"Project rules");

        let mut role_reqs = std::collections::BTreeMap::new();
        role_reqs.insert(
            "op".to_string(),
            Requirement::All {
                requirements: vec![
                    Requirement::Accept {
                        hash: rules_hash.clone(),
                    },
                    Requirement::Present {
                        credential_type: "github_membership".into(),
                        issuer: Some("github".into()),
                    },
                ],
            },
        );

        engine
            .create_channel_policy(
                "#project",
                Requirement::Accept {
                    hash: rules_hash.clone(),
                },
                role_reqs,
            )
            .unwrap();

        // Regular user
        let mut evidence = UserEvidence {
            accepted_hashes: HashSet::from([rules_hash.clone()]),
            credentials: vec![],
            proofs: HashSet::new(),
        };
        let result = engine
            .process_join("#project", "did:plc:regular", &evidence)
            .unwrap();
        match result {
            JoinResult::Confirmed { attestation, .. } => {
                assert_eq!(attestation.role, "member");
            }
            other => panic!("Expected Confirmed, got {:?}", other),
        }

        // GitHub committer
        evidence.credentials.push(Credential {
            credential_type: "github_membership".into(),
            issuer: "github".into(),
        });
        let result = engine
            .process_join("#project", "did:plc:committer", &evidence)
            .unwrap();
        match result {
            JoinResult::Confirmed { attestation, .. } => {
                assert_eq!(attestation.role, "op");
            }
            other => panic!("Expected Confirmed, got {:?}", other),
        }
    }

    #[test]
    fn test_open_join_gate_still_gates_op_role() {
        // Open base join gate: anyone joins with zero evidence, but the op
        // role still requires its credential. This is the "open by default,
        // roles still gated" shape (#freeq-style, minus the rules acceptance).
        let engine = test_engine();

        let mut role_reqs = std::collections::BTreeMap::new();
        role_reqs.insert(
            "op".to_string(),
            Requirement::Present {
                credential_type: "github_repo".into(),
                issuer: Some("did:web:irc.freeq.at:verify".into()),
            },
        );

        engine
            .create_channel_policy("#lobby", Requirement::Open, role_reqs)
            .unwrap();

        // Stranger with no evidence at all joins as a plain member.
        let empty = UserEvidence {
            accepted_hashes: HashSet::new(),
            credentials: vec![],
            proofs: HashSet::new(),
        };
        match engine
            .process_join("#lobby", "did:plc:stranger", &empty)
            .unwrap()
        {
            JoinResult::Confirmed { attestation, .. } => assert_eq!(attestation.role, "member"),
            other => panic!("open join should confirm as member, got {:?}", other),
        }

        // Collaborator presenting the github_repo credential is opped.
        let with_cred = UserEvidence {
            accepted_hashes: HashSet::new(),
            credentials: vec![Credential {
                credential_type: "github_repo".into(),
                issuer: "did:web:irc.freeq.at:verify".into(),
            }],
            proofs: HashSet::new(),
        };
        match engine
            .process_join("#lobby", "did:plc:collab", &with_cred)
            .unwrap()
        {
            JoinResult::Confirmed { attestation, .. } => assert_eq!(attestation.role, "op"),
            other => panic!("collaborator should be opped, got {:?}", other),
        }
    }

    #[test]
    fn test_update_preserves_roles_and_endpoints() {
        // Simulates POLICY SET replacing only the join gate: role requirements
        // and credential endpoints must survive a rules change.
        use crate::policy::types::CredentialEndpoint;
        let engine = test_engine();

        let mut role_reqs = std::collections::BTreeMap::new();
        role_reqs.insert(
            "op".to_string(),
            Requirement::Present {
                credential_type: "github_repo".into(),
                issuer: Some("did:web:irc.freeq.at:verify".into()),
            },
        );
        let mut endpoints = std::collections::BTreeMap::new();
        endpoints.insert(
            "github_repo".to_string(),
            CredentialEndpoint {
                issuer: "did:web:irc.freeq.at:verify".into(),
                url: "/verify/github/start?repo=freeq-irc/freeq".into(),
                label: "GitHub Repo Collaborator".into(),
                description: None,
            },
        );

        engine
            .update_channel_policy_with_endpoints(
                "#c",
                Requirement::Accept { hash: "v1".into() },
                role_reqs.clone(),
                endpoints.clone(),
            )
            .err(); // no existing policy yet — create one first
        engine
            .create_channel_policy(
                "#c",
                Requirement::Accept { hash: "v1".into() },
                role_reqs.clone(),
            )
            .unwrap();
        // Now change the rules gate while preserving roles + endpoints.
        let updated = engine
            .update_channel_policy_with_endpoints(
                "#c",
                Requirement::Accept { hash: "v2".into() },
                role_reqs.clone(),
                endpoints.clone(),
            )
            .unwrap();

        assert_eq!(
            updated.requirements,
            Requirement::Accept { hash: "v2".into() }
        );
        assert!(updated.role_requirements.contains_key("op"));
        assert!(updated.credential_endpoints.contains_key("github_repo"));
    }

    #[test]
    fn test_policy_update_chains() {
        let engine = test_engine();
        let hash1 = canonical::sha256_hex(b"rules v1");

        let (p1, _) = engine
            .create_channel_policy(
                "#versioned",
                Requirement::Accept {
                    hash: hash1.clone(),
                },
                std::collections::BTreeMap::new(),
            )
            .unwrap();

        let hash2 = canonical::sha256_hex(b"rules v2");
        let p2 = engine
            .update_channel_policy(
                "#versioned",
                Requirement::Accept {
                    hash: hash2.clone(),
                },
                std::collections::BTreeMap::new(),
            )
            .unwrap();

        assert_eq!(p2.version, 2);
        assert_eq!(p2.previous_policy_hash, p1.policy_id);

        // Policy chain
        let chain = engine.store().get_policy_chain("#versioned").unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].version, 1);
        assert_eq!(chain[1].version, 2);
    }

    #[test]
    fn test_idempotent_join() {
        let engine = test_engine();
        let hash = canonical::sha256_hex(b"rules");

        engine
            .create_channel_policy(
                "#idem",
                Requirement::Accept { hash: hash.clone() },
                std::collections::BTreeMap::new(),
            )
            .unwrap();

        let evidence = UserEvidence {
            accepted_hashes: HashSet::from([hash]),
            credentials: vec![],
            proofs: HashSet::new(),
        };

        // Join twice — second should return existing attestation
        let r1 = engine
            .process_join("#idem", "did:plc:user", &evidence)
            .unwrap();
        let r2 = engine
            .process_join("#idem", "did:plc:user", &evidence)
            .unwrap();

        match (r1, r2) {
            (
                JoinResult::Confirmed {
                    attestation: a1, ..
                },
                JoinResult::Confirmed {
                    attestation: a2, ..
                },
            ) => {
                assert_eq!(a1.attestation_id, a2.attestation_id);
            }
            _ => panic!("Expected both to be Confirmed"),
        }
    }

    #[test]
    fn test_transparency_log() {
        let engine = test_engine();
        let hash = canonical::sha256_hex(b"rules");

        engine
            .create_channel_policy(
                "#logged",
                Requirement::Accept { hash: hash.clone() },
                std::collections::BTreeMap::new(),
            )
            .unwrap();

        let evidence = UserEvidence {
            accepted_hashes: HashSet::from([hash]),
            credentials: vec![],
            proofs: HashSet::new(),
        };

        engine
            .process_join("#logged", "did:plc:user1", &evidence)
            .unwrap();
        engine
            .process_join("#logged", "did:plc:user2", &evidence)
            .unwrap();

        let entries = engine.store().get_log_entries("#logged", None).unwrap();
        assert_eq!(entries.len(), 2);
        // Entries don't contain user DIDs (privacy)
        assert!(entries.iter().all(|e| !e.attestation_hash.is_empty()));
    }

    #[test]
    fn test_attestation_signing() {
        let engine = test_engine();
        let hash = canonical::sha256_hex(b"rules");

        engine
            .create_channel_policy(
                "#signed",
                Requirement::Accept { hash: hash.clone() },
                std::collections::BTreeMap::new(),
            )
            .unwrap();

        let evidence = UserEvidence {
            accepted_hashes: HashSet::from([hash]),
            credentials: vec![],
            proofs: HashSet::new(),
        };

        let result = engine
            .process_join("#signed", "did:plc:user1", &evidence)
            .unwrap();
        match result {
            JoinResult::Confirmed { attestation, .. } => {
                // Signature should be non-empty
                assert!(!attestation.signature.is_empty());
                // Signature should verify
                assert!(engine.verify_attestation(&attestation));
                // Tampered attestation should fail
                let mut tampered = attestation.clone();
                tampered.role = "admin".to_string();
                assert!(!engine.verify_attestation(&tampered));
            }
            other => panic!("Expected Confirmed, got {:?}", other),
        }
    }

    #[test]
    fn test_remove_policy() {
        let engine = test_engine();
        let hash = canonical::sha256_hex(b"rules");

        engine
            .create_channel_policy(
                "#removable",
                Requirement::Accept { hash: hash.clone() },
                std::collections::BTreeMap::new(),
            )
            .unwrap();

        assert!(engine.get_policy("#removable").unwrap().is_some());
        assert!(engine.remove_policy("#removable").unwrap());
        assert!(engine.get_policy("#removable").unwrap().is_none());
        // Double remove returns false
        assert!(!engine.remove_policy("#removable").unwrap());
    }

    #[test]
    fn test_get_member_role() {
        let engine = test_engine();
        let hash = canonical::sha256_hex(b"rules");

        let mut role_reqs = std::collections::BTreeMap::new();
        role_reqs.insert(
            "op".to_string(),
            Requirement::Present {
                credential_type: "admin".into(),
                issuer: Some("github".into()),
            },
        );

        engine
            .create_channel_policy(
                "#roles",
                Requirement::Accept { hash: hash.clone() },
                role_reqs,
            )
            .unwrap();

        let evidence = UserEvidence {
            accepted_hashes: HashSet::from([hash]),
            credentials: vec![],
            proofs: HashSet::new(),
        };

        engine
            .process_join("#roles", "did:plc:regular", &evidence)
            .unwrap();
        assert_eq!(
            engine.get_member_role("#roles", "did:plc:regular").unwrap(),
            Some("member".into())
        );
        assert_eq!(
            engine.get_member_role("#roles", "did:plc:nobody").unwrap(),
            None
        );
    }

    #[test]
    fn test_continuous_validity_expiry() {
        let engine = test_engine();
        let hash = canonical::sha256_hex(b"rules");

        // Create policy with continuous validity
        let auth_set = AuthoritySet {
            authority_set_hash: None,
            channel_id: "#expire".to_string(),
            signers: vec![],
            policy_threshold: 1,
            authority_refresh_ttl_seconds: 3600,
            transparency: None,
            previous_authority_set_hash: None,
        };
        let auth_set = engine.store.store_authority_set(auth_set).unwrap();
        let auth_hash = auth_set.authority_set_hash.unwrap();

        let policy = PolicyDocument {
            channel_id: "#expire".to_string(),
            policy_id: None,
            version: 1,
            effective_at: chrono::Utc::now().to_rfc3339(),
            previous_policy_hash: None,
            authority_set_hash: auth_hash,
            requirements: Requirement::Accept { hash: hash.clone() },
            role_requirements: std::collections::BTreeMap::new(),
            validity_model: ValidityModel::Continuous,
            receipt_embedding: ReceiptEmbedding::Allow,
            policy_locations: vec![],
            limits: None,
            transparency: None,
            credential_endpoints: std::collections::BTreeMap::new(),
            agent_budget: None,
            agent_budgets: std::collections::BTreeMap::new(),
        };
        engine.store.store_policy(policy).unwrap();

        let evidence = UserEvidence {
            accepted_hashes: HashSet::from([hash]),
            credentials: vec![],
            proofs: HashSet::new(),
        };

        let result = engine
            .process_join("#expire", "did:plc:user1", &evidence)
            .unwrap();
        match &result {
            JoinResult::Confirmed { attestation, .. } => {
                // Continuous validity: should have an expiry
                assert!(attestation.expires_at.is_some());
            }
            other => panic!("Expected Confirmed, got {:?}", other),
        }
    }

    #[test]
    fn test_credential_store_and_build_evidence() {
        let engine = test_engine();

        // Store credentials
        let metadata = serde_json::json!({
            "github_username": "octocat",
            "org": "freeq",
        });
        engine
            .store_credential("did:plc:dev1", "github_membership", "github", &metadata)
            .unwrap();

        // Build evidence auto-collects credentials
        let evidence = engine
            .build_evidence("did:plc:dev1", HashSet::new())
            .unwrap();
        assert_eq!(evidence.credentials.len(), 1);
        assert_eq!(evidence.credentials[0].credential_type, "github_membership");
        assert_eq!(evidence.credentials[0].issuer, "github");

        // User without credentials
        let evidence = engine
            .build_evidence("did:plc:nobody", HashSet::new())
            .unwrap();
        assert!(evidence.credentials.is_empty());
    }

    #[test]
    fn test_rules_text_store_and_read() {
        let engine = test_engine();
        let rules_text = "Be nice.\nNo spam.\nRespect others.";
        let rules_hash = canonical::sha256_hex(rules_text.as_bytes());

        // Create a policy the way POLICY SET does, and store the rules text.
        engine
            .create_channel_policy(
                "#rules",
                Requirement::Accept {
                    hash: rules_hash.clone(),
                },
                std::collections::BTreeMap::new(),
            )
            .unwrap();
        engine.store_rules_text(&rules_hash, rules_text).unwrap();

        // Read it back by hash — should match exactly.
        assert_eq!(
            engine.get_rules_text(&rules_hash).unwrap().as_deref(),
            Some(rules_text)
        );

        // Unknown hash (e.g. legacy policy / S2S-only) returns None.
        let unknown = canonical::sha256_hex(b"never stored");
        assert_eq!(engine.get_rules_text(&unknown).unwrap(), None);
    }

    #[test]
    fn test_rules_text_dedupes_by_hash() {
        let engine = test_engine();
        let text = "Shared rules";
        let hash = canonical::sha256_hex(text.as_bytes());
        // Storing twice is idempotent (content-addressed).
        engine.store_rules_text(&hash, text).unwrap();
        engine.store_rules_text(&hash, text).unwrap();
        assert_eq!(engine.get_rules_text(&hash).unwrap().as_deref(), Some(text));
    }

    #[test]
    fn test_github_role_escalation_with_credentials() {
        let engine = test_engine();
        let rules_hash = canonical::sha256_hex(b"Code of Conduct");

        // Create policy: ACCEPT(coc) to join, ACCEPT(coc)+PRESENT(github) for op
        let mut role_reqs = std::collections::BTreeMap::new();
        role_reqs.insert(
            "op".to_string(),
            Requirement::All {
                requirements: vec![
                    Requirement::Accept {
                        hash: rules_hash.clone(),
                    },
                    Requirement::Present {
                        credential_type: "github_membership".into(),
                        issuer: Some("github".into()),
                    },
                ],
            },
        );
        engine
            .create_channel_policy(
                "#project",
                Requirement::Accept {
                    hash: rules_hash.clone(),
                },
                role_reqs,
            )
            .unwrap();

        // Store GitHub credential for dev1
        let metadata = serde_json::json!({ "org": "freeq", "github_username": "dev1" });
        engine
            .store_credential("did:plc:dev1", "github_membership", "github", &metadata)
            .unwrap();

        // dev1 accepts policy — should get "op" role (has GitHub cred)
        let evidence = engine
            .build_evidence("did:plc:dev1", HashSet::from([rules_hash.clone()]))
            .unwrap();
        let result = engine
            .process_join("#project", "did:plc:dev1", &evidence)
            .unwrap();
        match result {
            JoinResult::Confirmed { attestation, .. } => {
                assert_eq!(attestation.role, "op");
            }
            other => panic!("Expected Confirmed with op, got {:?}", other),
        }

        // regular user accepts policy — should get "member" role (no GitHub cred)
        let evidence = engine
            .build_evidence("did:plc:regular", HashSet::from([rules_hash.clone()]))
            .unwrap();
        let result = engine
            .process_join("#project", "did:plc:regular", &evidence)
            .unwrap();
        match result {
            JoinResult::Confirmed { attestation, .. } => {
                assert_eq!(attestation.role, "member");
            }
            other => panic!("Expected Confirmed with member, got {:?}", other),
        }
    }
}
