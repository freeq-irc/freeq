//! freeq-bot-id: Generate and manage bot identities for freeq.
//!
//! Creates ed25519 keypairs and DID documents for bots, with optional
//! cryptographic binding to a creator's AT Protocol identity.
//!
//! Usage:
//!   freeq-bot-id create --name factory --domain freeq.at
//!   freeq-bot-id create --name worker
//!   freeq-bot-id info --name factory
//!   freeq-bot-id did-key  (quick: just print a new did:key)

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use clap::{Parser, Subcommand};
use freeq_sdk::crypto::PrivateKey;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

mod register;

#[derive(Parser)]
#[command(
    name = "freeq-bot-id",
    about = "Generate and manage bot identities for freeq"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new bot identity with ed25519 keypair
    Create {
        /// Bot name (used for file paths and did:web path component)
        #[arg(long)]
        name: String,

        /// Domain for did:web (omit for did:key)
        #[arg(long)]
        domain: Option<String>,

        /// Creator's DID (writes a delegation certificate naming the creator as this bot's owner)
        #[arg(long)]
        creator_did: Option<String>,

        /// Path to creator's ed25519 private key, to sign the delegation (deprecated; to be removed in a later release)
        #[arg(long)]
        creator_key: Option<PathBuf>,

        /// Output directory for DID document (default: ./<name>/)
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Show info about an existing bot identity
    Info {
        /// Bot name
        #[arg(long)]
        name: String,
    },

    /// Record bots as the owner's own: signs in through the browser, then
    /// writes one agent record per bot DID to the owner's account
    Register {
        /// The owner's handle
        #[arg(long)]
        owner: String,

        /// The bots' DIDs
        #[arg(required = true)]
        bot_dids: Vec<String>,

        /// A name for the bot, shown in your Agents list (one DID only)
        #[arg(long)]
        name: Option<String>,
    },

    /// Generate a did:key identity (quick one-liner, prints DID and key path)
    DidKey {
        /// Bot name (for key file storage)
        #[arg(long, default_value = "default")]
        name: String,
    },
}

/// A signed delegation certificate binding a bot's identity to its creator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotDelegation {
    /// Type tag for the delegation.
    #[serde(rename = "type")]
    pub type_tag: String,
    /// The bot's DID.
    pub bot_did: String,
    /// The bot's public key (multibase).
    pub bot_public_key: String,
    /// The creator's DID (who authorized this bot).
    pub creator_did: String,
    /// When the delegation was created.
    pub created_at: String,
    /// Who can revoke this bot's identity.
    pub revocation_authority: String,
    /// Creator's signature over the above fields (base64url, ed25519).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Stored bot identity metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BotIdentity {
    did: String,
    name: String,
    public_key_multibase: String,
    created_at: String,
    creator_did: Option<String>,
    delegation: Option<BotDelegation>,
}

fn bot_dir(name: &str) -> PathBuf {
    dirs::home_dir()
        .expect("could not determine home directory")
        .join(".freeq")
        .join("bots")
        .join(name)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Create {
            name,
            domain,
            creator_did,
            creator_key,
            output,
        } => create(
            &name,
            domain.as_deref(),
            creator_did.as_deref(),
            creator_key.as_ref(),
            output.as_ref(),
        ),
        Command::Info { name } => info(&name),
        Command::Register {
            owner,
            bot_dids,
            name,
        } => tokio::runtime::Runtime::new()?.block_on(register::register(
            &owner,
            &bot_dids,
            name.as_deref(),
        )),
        Command::DidKey { name } => did_key(&name),
    }
}

fn create(
    name: &str,
    domain: Option<&str>,
    creator_did: Option<&str>,
    creator_key: Option<&PathBuf>,
    output_dir: Option<&PathBuf>,
) -> Result<()> {
    let key_dir = bot_dir(name);
    if key_dir.join("key.ed25519").exists() {
        bail!(
            "Bot identity '{}' already exists at {}. Use a different name or delete the existing key.",
            name,
            key_dir.display()
        );
    }

    // Generate bot keypair
    let private_key = PrivateKey::generate_ed25519();
    let multibase_pub = private_key.public_key_multibase();

    // Derive DID
    let bot_did = if let Some(domain) = domain {
        format!("did:web:{}:bots:{}", domain, name)
    } else {
        format!("did:key:{}", multibase_pub)
    };

    // Save private key
    std::fs::create_dir_all(&key_dir)?;
    let key_bytes = match &private_key {
        PrivateKey::Ed25519(k) => k.to_bytes().to_vec(),
        _ => unreachable!(),
    };
    std::fs::write(key_dir.join("key.ed25519"), &key_bytes)?;
    // Restrict permissions on key file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            key_dir.join("key.ed25519"),
            std::fs::Permissions::from_mode(0o600),
        )?;
    }

    // Build delegation certificate if creator is specified
    let delegation = if let Some(creator) = creator_did {
        let mut deleg = BotDelegation {
            type_tag: "FreeqBotDelegation/v1".to_string(),
            bot_did: bot_did.clone(),
            bot_public_key: multibase_pub.clone(),
            creator_did: creator.to_string(),
            created_at: Utc::now().to_rfc3339(),
            revocation_authority: creator.to_string(),
            signature: None,
        };

        // Sign with creator's key if provided
        if let Some(creator_key_path) = creator_key {
            let creator_key_bytes =
                std::fs::read(creator_key_path).context("Failed to read creator key file")?;
            let creator_private = PrivateKey::ed25519_from_bytes(&creator_key_bytes)
                .context("Failed to parse creator key (expected 32-byte ed25519)")?;

            // Canonical JSON for signing (without the signature field).
            // Use JCS (RFC 8785) so a verifying server can reproduce the exact
            // bytes regardless of struct field declaration order. The signature
            // field is `skip_serializing_if = "Option::is_none"`, and at this
            // point it's still None, so it's omitted from the canonical form.
            let canonical = freeq_sdk::canonical::canonicalize(&deleg)
                .context("Failed to canonicalize delegation")?;
            let sig = creator_private.sign(canonical.as_bytes());
            deleg.signature = Some(URL_SAFE_NO_PAD.encode(&sig));

            eprintln!("✅ Delegation signed by {creator}");
        } else {
            eprintln!("{}", delegation_line(Some(&deleg)));
        }

        Some(deleg)
    } else {
        None
    };

    // Build DID document for did:web. Evaluates to the file that holds the
    // certificate besides identity.json, for the signed-certificate warning.
    let cert_file = if let Some(domain) = domain {
        let mut did_doc = serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1"
            ],
            "id": bot_did,
            "verificationMethod": [{
                "id": format!("{}#key-1", bot_did),
                "type": "Multikey",
                "controller": bot_did,
                "publicKeyMultibase": multibase_pub,
            }],
            "authentication": [format!("{}#key-1", bot_did)],
            "assertionMethod": [format!("{}#key-1", bot_did)],
        });

        // Embed delegation as a service entry
        if let Some(ref deleg) = delegation {
            did_doc["service"] = serde_json::json!([{
                "id": format!("{}#freeq-delegation", bot_did),
                "type": "FreeqBotDelegation",
                "serviceEndpoint": deleg,
            }]);
        }

        let doc_dir = output_dir
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(name));
        std::fs::create_dir_all(&doc_dir)?;
        let doc_path = doc_dir.join("did.json");
        std::fs::write(&doc_path, serde_json::to_string_pretty(&did_doc)?)?;
        eprintln!("✅ DID document: {}", doc_path.display());

        eprintln!("   Serve at: https://{domain}/bots/{name}/did.json");
        format!("{}, which you serve", doc_path.display())
    } else {
        // For did:key, save delegation as separate file
        let deleg_path = key_dir.join("delegation.json");
        if let Some(ref deleg) = delegation {
            std::fs::write(&deleg_path, serde_json::to_string_pretty(deleg)?)?;
            eprintln!("✅ Delegation cert: {}", deleg_path.display());
        }
        deleg_path.display().to_string()
    };

    let signed = delegation.as_ref().is_some_and(|d| d.signature.is_some());

    // Save identity metadata
    let identity = BotIdentity {
        did: bot_did.clone(),
        name: name.to_string(),
        public_key_multibase: multibase_pub,
        created_at: Utc::now().to_rfc3339(),
        creator_did: creator_did.map(|s| s.to_string()),
        delegation,
    };
    std::fs::write(
        key_dir.join("identity.json"),
        serde_json::to_string_pretty(&identity)?,
    )?;

    // Signed certificates will stop counting in a later release. A bot run on these
    // files alone never mints a new certificate, so the signature is nulled
    // in place rather than the files deleted.
    if signed {
        eprintln!(
            "This bot's certificate is signed with a creator key. Signed certificates will stop \
             counting in a later release; every server now reads agent records instead. Add this \
             agent under Settings → Agents in the freeq web app, or with `freeq-bot-id register \
             --owner <handle> {bot_did}`, then set `\"signature\": null` in {} and {cert_file}. \
             The DID stays; the server then verifies the certificate from your agent record.",
            key_dir.join("identity.json").display()
        );
    }

    eprintln!("✅ DID: {bot_did}");
    eprintln!("✅ Private key: {}", key_dir.join("key.ed25519").display());
    eprintln!();
    eprintln!(
        "   Connect with: freeq-bots --did {} --key {}",
        bot_did,
        key_dir.join("key.ed25519").display()
    );

    // Print the DID to stdout (for scripting)
    println!("{bot_did}");

    Ok(())
}

fn info(name: &str) -> Result<()> {
    let key_dir = bot_dir(name);
    let identity_path = key_dir.join("identity.json");

    if !identity_path.exists() {
        bail!(
            "No bot identity found at {}. Run 'freeq-bot-id create --name {name}' first.",
            key_dir.display()
        );
    }

    let identity: BotIdentity = serde_json::from_str(&std::fs::read_to_string(&identity_path)?)?;

    println!("Bot: {}", identity.name);
    println!("DID: {}", identity.did);
    println!("Public key: {}", identity.public_key_multibase);
    println!("Created: {}", identity.created_at);

    if let Some(ref creator) = identity.creator_did {
        println!("Creator: {creator}");
    }

    println!("{}", delegation_line(identity.delegation.as_ref()));

    let key_path = key_dir.join("key.ed25519");
    if key_path.exists() {
        println!("Key file: {}", key_path.display());
    } else {
        println!("Key file: ⚠  missing!");
    }

    Ok(())
}

fn did_key(name: &str) -> Result<()> {
    let key_dir = bot_dir(name);
    if key_dir.join("key.ed25519").exists() {
        // Load existing
        let identity: BotIdentity = serde_json::from_str(
            &std::fs::read_to_string(key_dir.join("identity.json"))
                .context("Key exists but identity.json is missing")?,
        )?;
        println!("{}", identity.did);
        return Ok(());
    }

    // Generate new
    create(name, None, None, None, None)
}

/// What `info` says about the bot's certificate. It reads only local files,
/// so it says what the certificate is and how the owner proves it, and makes
/// no claim about whether any server has verified it.
fn delegation_line(delegation: Option<&BotDelegation>) -> String {
    match delegation {
        Some(d) if d.signature.is_some() => format!(
            "Delegation: signed by {} (checked against keys the owner registered with the server)",
            d.creator_did
        ),
        Some(_) => "Delegation: unsigned; the owner proves it by adding this bot under \
                    Settings → Agents, or with freeq-bot-id register"
            .to_string(),
        None => "Delegation: none".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn info_describes_the_certificate_and_claims_no_verdict() {
        let mut deleg = BotDelegation {
            type_tag: "FreeqBotDelegation/v1".to_string(),
            bot_did: "did:key:z6MkBot".to_string(),
            bot_public_key: "z6MkBot".to_string(),
            creator_did: "did:plc:owner".to_string(),
            created_at: "2026-09-29T00:00:00Z".to_string(),
            revocation_authority: "did:plc:owner".to_string(),
            signature: None,
        };
        let unsigned = delegation_line(Some(&deleg));
        assert!(unsigned.contains("Settings → Agents"), "{unsigned}");
        assert!(!unsigned.contains("unverified"), "{unsigned}");
        deleg.signature = Some("sig".to_string());
        let signed = delegation_line(Some(&deleg));
        assert!(
            signed.starts_with("Delegation: signed by did:plc:owner"),
            "{signed}"
        );
        assert!(!signed.contains('✅'), "{signed}");
        assert_eq!(delegation_line(None), "Delegation: none");
    }

    #[test]
    fn test_create_did_key() {
        let tmp = tempfile::tempdir().unwrap();
        // Override home dir by using the key_dir directly
        let name = "test-bot";
        let key_dir = tmp.path().join(name);
        fs::create_dir_all(&key_dir).unwrap();

        let private_key = PrivateKey::generate_ed25519();
        let multibase = private_key.public_key_multibase();
        let did = format!("did:key:{multibase}");

        // Verify the DID resolves
        let doc = freeq_sdk::did::resolve_did_key(&did).unwrap();
        assert_eq!(doc.id, did);
        assert_eq!(doc.authentication_keys().len(), 1);
    }

    #[test]
    fn test_delegation_serialization() {
        let deleg = BotDelegation {
            type_tag: "FreeqBotDelegation/v1".to_string(),
            bot_did: "did:key:z6MkTest".to_string(),
            bot_public_key: "z6MkTest".to_string(),
            creator_did: "did:plc:creator".to_string(),
            created_at: "2026-03-11T00:00:00Z".to_string(),
            revocation_authority: "did:plc:creator".to_string(),
            signature: None,
        };

        let json = serde_json::to_string_pretty(&deleg).unwrap();
        assert!(json.contains("FreeqBotDelegation/v1"));
        assert!(!json.contains("signature")); // None should be skipped

        let deleg_signed = BotDelegation {
            signature: Some("test-sig".to_string()),
            ..deleg
        };
        let json = serde_json::to_string_pretty(&deleg_signed).unwrap();
        assert!(json.contains("test-sig"));
    }

    #[test]
    fn test_delegation_signing() {
        let creator_key = PrivateKey::generate_ed25519();
        let bot_key = PrivateKey::generate_ed25519();

        let deleg = BotDelegation {
            type_tag: "FreeqBotDelegation/v1".to_string(),
            bot_did: format!("did:key:{}", bot_key.public_key_multibase()),
            bot_public_key: bot_key.public_key_multibase(),
            creator_did: "did:plc:creator123".to_string(),
            created_at: Utc::now().to_rfc3339(),
            revocation_authority: "did:plc:creator123".to_string(),
            signature: None,
        };

        let canonical = serde_json::to_string(&deleg).unwrap();
        let sig = creator_key.sign(canonical.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(&sig);

        // Verify with creator's public key
        let sig_bytes = URL_SAFE_NO_PAD.decode(&sig_b64).unwrap();
        creator_key
            .public_key()
            .verify(canonical.as_bytes(), &sig_bytes)
            .unwrap();
    }
}
