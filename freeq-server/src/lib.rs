#![allow(deprecated)] // generic_array::from_slice in transitive crypto deps
//! IRC server with AT Protocol SASL authentication.

pub mod agent_assist;
pub mod av;
pub mod av_artifacts;
pub mod av_bridge;
pub mod av_media;
pub mod av_sfu;
pub mod config;
pub mod connection;
pub mod crdt;
pub mod db;
pub mod irc;
pub mod iroh;
pub mod manifest;
pub mod media_store;
pub mod model_proxy;
pub mod msgid;
pub mod plugin;
pub mod policy;
pub mod s2s;
pub mod sasl;
pub mod secrets;
pub mod server;
pub mod verifiers;
pub mod web;
