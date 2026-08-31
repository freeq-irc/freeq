#![allow(deprecated)] // generic_array::from_slice in transitive crypto deps
//! IRC server with AT Protocol SASL authentication.

pub mod act_relay;
pub mod agent_assist;
pub mod agent_surfaces;
pub mod av;
pub mod av_artifacts;
pub mod av_bridge;
pub mod av_media;
pub mod av_sfu;
pub mod config;
pub mod connection;
pub mod crdt;
pub mod db;
pub mod events;
pub mod irc;
pub mod iroh;
pub mod manifest;
pub mod media_store;
pub mod migrations;
pub mod model_proxy;
pub mod msgid;
pub mod openapi;
pub mod peer_keys;
pub mod plugin;
pub mod policy;
pub mod s2s;
pub mod sasl;
pub mod secrets;
pub mod server;
pub mod verifiers;
pub mod web;
