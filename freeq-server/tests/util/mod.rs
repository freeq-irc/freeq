//! Shared test utilities.
//!
//! Included with `mod util;` from a test file. Each test binary compiles its
//! own copy, so anything a given binary doesn't use is dead code there —
//! hence the blanket allow.

#![allow(dead_code)]

pub mod lying_peer;
