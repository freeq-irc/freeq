//! FFI bridge for freeq-sdk targeting Windows native clients (WinUI 3 / C# P/Invoke).
//!
//! Exposes a C ABI (`extern "C"`) surface that a C# app can call via P/Invoke.
//! Internally manages a static tokio runtime and a global handle table of `AppCore` instances.

pub mod agent_status;
pub mod bridge;
pub mod core;
pub mod error;
pub mod event;

use once_cell::sync::Lazy;

/// Shared tokio runtime for all FFI operations.
/// Two worker threads — enough for IRC I/O without over-subscribing the system.
pub(crate) static RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .expect("Failed to create tokio runtime")
});
