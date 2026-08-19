#![allow(deprecated)] // generic_array::from_slice in transitive crypto deps
//! IRC AT Protocol SDK
//!
//! A reusable client library for connecting to IRC servers that support
//! the ATPROTO-CHALLENGE SASL mechanism.
//!
//! # Modules
//!
//! - [`client`] — Async IRC client with SASL support
//! - [`auth`] — Challenge signing traits and implementations
//! - [`canonical`] — JCS (RFC 8785) canonicalization for hashing/signing
//! - [`sigtag`] — the `+freeq.at/sig` tag format shared by every signing profile
//! - [`chatsig`] — signing profile for chat events (messages, deletes, reactions)
//! - [`act`] — signing profile for `freeq.at/act` action messages
//! - [`crypto`] — secp256k1 and ed25519 key operations
//! - [`did`] — DID document resolution (did:plc, did:web)
//! - [`pds`] — AT Protocol PDS client (session creation/verification)
//! - [`event`] — Events emitted by the client
//! - [`irc`] — IRC message parsing/formatting

pub mod act;
pub mod act_transitions;
pub mod address;
pub mod auth;
pub mod av;
pub mod bot;
pub mod canonical;
pub mod chatsig;
pub mod client;
pub mod crypto;
pub mod did;
pub mod e2ee;
pub mod e2ee_did;
pub mod e2ee_group;
pub mod event;
pub mod identity_claim;
pub mod irc;
pub mod media;
pub mod oauth;
#[cfg(feature = "iroh-transport")]
pub mod p2p;
pub mod pds;
pub mod ratchet;
pub mod sigtag;
// SSRF-safe outbound HTTP now lives in its own single-purpose crate; re-export
// so the `freeq_sdk::ssrf::` path stays stable for existing consumers.
pub use freeq_ssrf as ssrf;
pub mod streaming;
pub mod x3dh;
