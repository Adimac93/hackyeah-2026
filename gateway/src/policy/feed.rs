//! The attack signature feed (task.md §4.4): parsed and compiled into the
//! same shape as a catalog control, so one engine runs both.

use regex::Regex;
use serde::Deserialize;

use super::{Action, DeterministicControl, Hook, PolicyError, Severity};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFeed {
    source: String,
    version: u32,
    #[serde(default, rename = "signature")]
    signatures: Vec<RawSignature>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignature {
    external_id: String,
    title: String,
    #[serde(default = "default_deterministic")]
    kind: String,
    severity: Severity,
    pattern: Option<String>,
    /// Signatures describe payloads that arrive through tools or come back from
    /// a model, so those are the hooks they default to.
    #[serde(default = "default_signature_hooks")]
    hooks: Vec<Hook>,
    action: Option<Action>,
}

fn default_deterministic() -> String {
    "deterministic".to_owned()
}

fn default_signature_hooks() -> Vec<Hook> {
    vec![Hook::ToolCall, Hook::ToolResult, Hook::ResponseOut]
}

/// Compile the external feed into the same shape as a catalog control, so one
/// engine covers both. Semantic signatures need an embedding model and are
/// skipped with a warning rather than silently dropped.
pub fn compile_feed(source: &str, origin: &str) -> Result<Vec<DeterministicControl>, PolicyError> {
    let feed: RawFeed = toml::from_str(source).map_err(|source| PolicyError::Parse {
        path: origin.to_owned(),
        source,
    })?;

    let provenance = format!("{}@{}", feed.source, feed.version);
    let mut compiled = Vec::with_capacity(feed.signatures.len());
    for signature in feed.signatures {
        let id = format!("signature.{}", signature.external_id);

        if signature.kind != "deterministic" {
            tracing::warn!(%id, kind = %signature.kind, "skipping: no semantic detector yet");
            continue;
        }
        let Some(pattern) = signature.pattern else {
            tracing::warn!(%id, title = %signature.title, "skipping: no pattern");
            continue;
        };

        let regex = Regex::new(&pattern).map_err(|source| PolicyError::Pattern {
            id: id.clone(),
            source,
        })?;

        compiled.push(DeterministicControl {
            id,
            hooks: signature.hooks.into_iter().collect(),
            severity: signature.severity,
            action: signature.action.unwrap_or(Action::Block),
            regex,
            feed: Some(provenance.clone()),
        });
    }
    Ok(compiled)
}
