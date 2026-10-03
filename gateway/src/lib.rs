//! AI Control Layer — gateway library.
//!
//! The binary in `main.rs` is a thin wrapper around this crate so the policy
//! engine and the enforcement hooks can be driven directly from tests and from
//! the scenario runner.

pub mod approvals;
pub mod audit;
pub mod engine;
pub mod mcp;
pub mod metrics;
pub mod mock;
pub mod policy;
pub mod proxy;
pub mod semantic;
