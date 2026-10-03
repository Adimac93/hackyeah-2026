//! The attack signature feed (task.md §4.4): parsed and compiled into the
//! same shape as a catalog control, so one engine runs both.

use regex::Regex;
use serde::{Deserialize, Serialize};

use super::{Action, DeterministicControl, Hook, PolicyError, Severity};

/// What a compiled feed is, beyond its controls: the provenance recorded with
/// every match and the entries mirrored into `attack_signatures`.
#[derive(Debug, Clone, Serialize)]
pub struct Feed {
    pub source: String,
    pub version: u32,
    pub entries: Vec<FeedEntry>,
    /// The uploaded text, so a catalog-only upload can keep the current feed.
    #[serde(skip)]
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FeedEntry {
    pub external_id: String,
    pub title: String,
    pub kind: String,
    pub severity: Severity,
    pub pattern: Option<String>,
}

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
pub fn compile_feed(
    source: &str,
    origin: &str,
) -> Result<(Feed, Vec<DeterministicControl>), PolicyError> {
    let text = source.to_owned();
    let feed: RawFeed = toml::from_str(source).map_err(|source| PolicyError::Parse {
        path: origin.to_owned(),
        source,
    })?;

    let provenance = format!("{}@{}", feed.source, feed.version);
    let mut compiled = Vec::with_capacity(feed.signatures.len());
    let mut entries = Vec::with_capacity(feed.signatures.len());
    for signature in feed.signatures {
        let id = format!("signature.{}", signature.external_id);
        entries.push(FeedEntry {
            external_id: signature.external_id.clone(),
            title: signature.title.clone(),
            kind: signature.kind.clone(),
            severity: signature.severity,
            pattern: signature.pattern.clone(),
        });

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
    let info = Feed {
        source: feed.source,
        version: feed.version,
        entries,
        text,
    };
    Ok((info, compiled))
}
