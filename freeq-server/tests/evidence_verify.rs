//! End-to-end test of the offline evidence verifier: build a bundle exactly
//! the way the `/evidence` endpoint does (server-signed, with a client-signed
//! message), run the real `freeq-verify` binary on it, and confirm it PASSES —
//! then tamper with a message and confirm it FAILS. This is the guarantee that
//! a third party can check a freeq transcript with no server contact.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::process::Command;

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

fn message_canonical(did: &str, channel: &str, text: &str, ts: u64) -> String {
    format!("{did}\0{channel}\0{text}\0{ts}")
}

/// Build a signed bundle the same way `api_channel_evidence` does.
fn build_bundle(
    server_key: &SigningKey,
    client_key: &SigningKey,
    client_did: &str,
    channel: &str,
    text: &str,
    ts: u64,
) -> serde_json::Value {
    let client_pub = b64().encode(client_key.verifying_key().as_bytes());
    let server_pub = b64().encode(server_key.verifying_key().as_bytes());

    // Client-signed message.
    let msg_sig = client_key.sign(message_canonical(client_did, channel, text, ts).as_bytes());
    let messages = json!([{
        "msgid": "01ABC",
        "channel": channel,
        "sender": "alice!alice@freeq",
        "sender_did": client_did,
        "text": text,
        "timestamp": ts,
        "signature": b64().encode(msg_sig.to_bytes()),
    }]);

    let mut bundle = json!({
        "bundle_version": "1",
        "server_name": "irc.freeq.at",
        "server_public_key": server_pub,
        "channel": channel,
        "exported_at": "2026-07-05T00:00:00Z",
        "message_count": 1,
        "did_keys": { client_did: client_pub },
        "messages": messages,
    });

    let canon = freeq_sdk::canonical::canonicalize(&bundle).unwrap();
    let sig = server_key.sign(canon.as_bytes());
    bundle["bundle_signature"] = json!(b64().encode(sig.to_bytes()));
    bundle
}

fn run_verify(bundle: &serde_json::Value) -> std::process::Output {
    use std::io::Write;
    // Unique per call — tests run in parallel and must not share a path.
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(serde_json::to_string(bundle).unwrap().as_bytes())
        .unwrap();
    f.flush().unwrap();
    Command::new(env!("CARGO_BIN_EXE_freeq-verify"))
        .arg("--verbose")
        .arg(f.path())
        .output()
        .expect("run freeq-verify")
}

#[test]
fn valid_bundle_verifies() {
    let server = SigningKey::generate(&mut rand::rngs::OsRng);
    let client = SigningKey::generate(&mut rand::rngs::OsRng);
    let bundle = build_bundle(
        &server,
        &client,
        "did:plc:alice",
        "#freeq",
        "hello world",
        1_700_000_000,
    );

    let out = run_verify(&bundle);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "expected exit 0, got: {stdout}");
    assert!(stdout.contains("VERIFIED (client key)"));
    assert!(stdout.contains("✓ VERIFIED"));
}

#[test]
fn tampered_message_fails() {
    let server = SigningKey::generate(&mut rand::rngs::OsRng);
    let client = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut bundle = build_bundle(
        &server,
        &client,
        "did:plc:alice",
        "#freeq",
        "hello world",
        1_700_000_000,
    );

    // Alter the message text AFTER signing — the message signature no longer
    // matches, and (because message_count/messages changed) so does the bundle
    // signature. Both defenses should trip.
    bundle["messages"][0]["text"] = json!("hello EVIL world");

    let out = run_verify(&bundle);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!out.status.success(), "expected failure, got: {stdout}");
    assert!(
        stdout.contains("TAMPERED") || stdout.contains("INVALID"),
        "got: {stdout}"
    );
}

#[test]
fn tampered_bundle_signature_fails() {
    let server = SigningKey::generate(&mut rand::rngs::OsRng);
    let client = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut bundle = build_bundle(
        &server,
        &client,
        "did:plc:alice",
        "#freeq",
        "hi",
        1_700_000_000,
    );

    // Corrupt the bundle signature only — messages still individually verify,
    // but the bundle-integrity check must fail.
    bundle["bundle_signature"] = json!(b64().encode([0u8; 64]));

    let out = run_verify(&bundle);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!out.status.success(), "expected failure, got: {stdout}");
    assert!(stdout.contains("INVALID"), "got: {stdout}");
}
