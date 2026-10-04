//! AI Control Layer — gateway library.
//!
//! The binary in `main.rs` is a thin wrapper around this crate so the policy
//! engine and the enforcement hooks can be driven directly from tests and from
//! the scenario runner.

// The OpenAPI document is one `json!` literal, deeper than the default limit.
#![recursion_limit = "256"]

pub mod admin;
pub mod approvals;
pub mod audit;
pub mod background;
pub mod budget;
pub mod engine;
pub mod helper;
pub mod mcp;
pub mod metrics;
pub mod mock;
pub mod openapi;
pub mod policy;
pub mod proxy;
pub mod risk;
pub mod semantic;
pub mod state;
pub mod telemetry;
pub mod upstream;
