//! The policy engine: parse, validate and compile the control catalog.
//!
//! The TOML file is the authored source of truth (task.md §4.1). Everything
//! here is pure — parsing and validation with no I/O beyond reading the file —
//! so it is cheap to test, which is where most of the real bugs in a policy
//! engine live.

mod budget;
mod feed;
mod watch;

pub use budget::{Budget, Budgets, Price};
pub use watch::{PolicyHandle, spawn_watcher};

use feed::compile_feed;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The four enforcement points. Mirrors the `hook` enum in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Hook {
    PromptIn,
    ResponseOut,
    ToolCall,
    ToolResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// What a control does when it fires. `Flag` records the detection and lets the
/// request through — it is how a cheap tier-1 control marks traffic as
/// suspicious so tier 2 knows to look.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Flag,
    Redact,
    Block,
}

/// Who pays for a semantic control's latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalateWhen {
    /// Every request through this hook.
    Always,
    /// Only once a deterministic control has flagged something.
    Suspicious,
    /// Disabled without deleting the configuration.
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// Deny when a control errors or times out.
    Closed,
    Open,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("reading {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("control {id}: pattern does not compile: {source}")]
    Pattern {
        id: String,
        #[source]
        source: regex::Error,
    },
    #[error("control {id}: threshold {threshold} is outside 0.0..=1.0")]
    Threshold { id: String, threshold: f32 },
    #[error("control {id}: declares no hooks, so it can never run")]
    NoHooks { id: String },
    #[error("duplicate control id {id}")]
    DuplicateId { id: String },
    #[error("unsupported schema_version {found}, expected {expected}")]
    SchemaVersion { found: u32, expected: u32 },
}

const SCHEMA_VERSION: u32 = 1;

// ------------------------------------------------------------------ raw TOML

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCatalog {
    schema_version: u32,
    #[serde(default)]
    defaults: RawDefaults,
    #[serde(default)]
    models: Models,
    #[serde(default)]
    budgets: Budgets,
    #[serde(default)]
    pricing: HashMap<String, Price>,
    #[serde(default)]
    controls: RawControls,
    signatures: Option<SignatureFeed>,
    #[serde(default)]
    mcp: McpSettings,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDefaults {
    on_detect: Action,
    fail_mode: FailMode,
}

impl Default for RawDefaults {
    fn default() -> Self {
        Self {
            on_detect: Action::Block,
            fail_mode: FailMode::Closed,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawControls {
    #[serde(default)]
    deterministic: Vec<RawDeterministic>,
    #[serde(default)]
    semantic: Vec<RawSemantic>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDeterministic {
    id: String,
    #[serde(default = "default_true")]
    enabled: bool,
    hooks: Vec<Hook>,
    severity: Severity,
    action: Option<Action>,
    pattern: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSemantic {
    id: String,
    #[serde(default = "default_true")]
    enabled: bool,
    hooks: Vec<Hook>,
    severity: Severity,
    action: Option<Action>,
    detector: String,
    threshold: f32,
    #[serde(default = "default_escalation")]
    escalate_when: EscalateWhen,
    /// Plain-language description of what the detector is looking for. It is
    /// handed to the model, so it is part of the control, not a comment.
    describes: Option<String>,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    /// Overrides `defaults.fail_mode` for this control only.
    fail_mode: Option<FailMode>,
}

fn default_timeout_ms() -> u64 {
    2_000
}

fn default_escalation() -> EscalateWhen {
    EscalateWhen::Suspicious
}

// ------------------------------------------------------------------ compiled

/// A deterministic control with its pattern already compiled.
#[derive(Debug)]
pub struct DeterministicControl {
    pub id: String,
    pub hooks: HashSet<Hook>,
    pub severity: Severity,
    pub action: Action,
    pub regex: Regex,
    /// `source@version` of the signature feed this came from; `None` for a
    /// catalog control. Recorded with every match (§4.4).
    pub feed: Option<String>,
}

#[derive(Debug)]
pub struct SemanticControl {
    pub id: String,
    pub hooks: HashSet<Hook>,
    pub severity: Severity,
    pub action: Action,
    pub detector: String,
    pub threshold: f32,
    pub escalate_when: EscalateWhen,
    pub describes: String,
    pub timeout: std::time::Duration,
    pub fail_mode: FailMode,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Models {
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub denied: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// What to do with a caller we have no `principals` row for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownPrincipal {
    /// Refuse tool access. The right default for a control layer.
    #[default]
    Deny,
    Allow,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpServer {
    pub name: String,
    pub url: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpSettings {
    #[serde(default)]
    pub unknown_principal: UnknownPrincipal,
    #[serde(default, rename = "server")]
    pub servers: Vec<McpServer>,
}

impl McpSettings {
    pub fn enabled_servers(&self) -> impl Iterator<Item = &McpServer> {
        self.servers.iter().filter(|s| s.enabled)
    }

    pub fn server(&self, name: &str) -> Option<&McpServer> {
        self.enabled_servers().find(|s| s.name == name)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureFeed {
    pub source: String,
    pub path: Option<String>,
    #[serde(default = "default_refresh")]
    pub refresh_secs: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_refresh() -> u64 {
    300
}

/// A validated, compiled catalog. Swapped in atomically on reload.
#[derive(Debug)]
pub struct Policy {
    /// sha256 of the file this was built from — the version recorded against
    /// every decision in the audit log.
    pub sha256: String,
    pub source: String,
    pub on_detect: Action,
    pub fail_mode: FailMode,
    pub models: Models,
    pub budgets: Budgets,
    /// Per-model price, keyed by model name. An unpriced model costs nothing.
    pub pricing: HashMap<String, Price>,
    pub deterministic: Vec<DeterministicControl>,
    pub semantic: Vec<SemanticControl>,
    pub signatures: Option<SignatureFeed>,
    /// Compiled from the external feed (§4.4). Kept separate from the catalog
    /// controls because the two have different lifecycles: a feed refresh is an
    /// operational event, a catalog edit is a policy change.
    pub signature_controls: Vec<DeterministicControl>,
    /// The resolved feed file, so the watcher can reload when it changes.
    pub feed_path: Option<PathBuf>,
    pub mcp: McpSettings,
}

impl Policy {
    /// Read, parse, validate and compile a catalog from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        let display = path.display().to_string();
        let source = std::fs::read_to_string(path).map_err(|source| PolicyError::Read {
            path: display.clone(),
            source,
        })?;
        let mut policy = Self::from_str(&source, &display)?;

        // §4.4: the feed only becomes a control once it is compiled. Its bytes
        // join the version hash, so editing signatures.toml is a policy change
        // the audit log can point at.
        if let Some(feed) = policy.signatures.clone()
            && feed.enabled
            && let Some(feed_path) = feed.path.as_deref()
        {
            // Relative to the catalog, not to the working directory: a path
            // written inside a config file means "next to this file", and the
            // gateway must not care where it was launched from.
            let resolved = path
                .parent()
                .map_or_else(|| PathBuf::from(feed_path), |dir| dir.join(feed_path));
            let raw = std::fs::read_to_string(&resolved).map_err(|source| PolicyError::Read {
                path: resolved.display().to_string(),
                source,
            })?;
            policy.signature_controls = compile_feed(&raw, &resolved.display().to_string())?;
            policy.sha256 = sha256_hex(&format!("{source}{raw}"));
            policy.feed_path = Some(resolved);
            tracing::debug!(
                signatures = policy.signature_controls.len(),
                "attack signature feed loaded"
            );
        }

        Ok(policy)
    }

    /// Compile from an in-memory catalog. Kept separate from [`Policy::load`]
    /// so the tests never touch the filesystem.
    pub fn from_str(source: &str, origin: &str) -> Result<Self, PolicyError> {
        let raw: RawCatalog = toml::from_str(source).map_err(|source| PolicyError::Parse {
            path: origin.to_owned(),
            source,
        })?;

        if raw.schema_version != SCHEMA_VERSION {
            return Err(PolicyError::SchemaVersion {
                found: raw.schema_version,
                expected: SCHEMA_VERSION,
            });
        }

        let mut seen = HashSet::new();
        let mut deterministic = Vec::with_capacity(raw.controls.deterministic.len());
        for control in raw.controls.deterministic {
            check_unique(&mut seen, &control.id)?;
            if control.hooks.is_empty() {
                return Err(PolicyError::NoHooks { id: control.id });
            }
            let regex = Regex::new(&control.pattern).map_err(|source| PolicyError::Pattern {
                id: control.id.clone(),
                source,
            })?;
            if !control.enabled {
                continue;
            }
            deterministic.push(DeterministicControl {
                id: control.id,
                hooks: control.hooks.into_iter().collect(),
                severity: control.severity,
                action: control.action.unwrap_or(raw.defaults.on_detect),
                regex,
                feed: None,
            });
        }

        let mut semantic = Vec::with_capacity(raw.controls.semantic.len());
        for control in raw.controls.semantic {
            check_unique(&mut seen, &control.id)?;
            if control.hooks.is_empty() {
                return Err(PolicyError::NoHooks { id: control.id });
            }
            if !(0.0..=1.0).contains(&control.threshold) {
                return Err(PolicyError::Threshold {
                    id: control.id,
                    threshold: control.threshold,
                });
            }
            if !control.enabled {
                continue;
            }
            semantic.push(SemanticControl {
                describes: control.describes.unwrap_or_else(|| control.id.clone()),
                id: control.id,
                hooks: control.hooks.into_iter().collect(),
                severity: control.severity,
                action: control.action.unwrap_or(raw.defaults.on_detect),
                timeout: std::time::Duration::from_millis(control.timeout_ms),
                fail_mode: control.fail_mode.unwrap_or(raw.defaults.fail_mode),
                detector: control.detector,
                threshold: control.threshold,
                escalate_when: control.escalate_when,
            });
        }

        Ok(Self {
            sha256: sha256_hex(source),
            source: origin.to_owned(),
            on_detect: raw.defaults.on_detect,
            fail_mode: raw.defaults.fail_mode,
            models: raw.models,
            budgets: raw.budgets,
            pricing: raw.pricing,
            deterministic,
            semantic,
            signatures: raw.signatures,
            signature_controls: Vec::new(),
            feed_path: None,
            mcp: raw.mcp,
        })
    }

    /// Deterministic controls that apply at `hook`: catalog controls first,
    /// then anything the signature feed contributed. The engine does not need
    /// to know the difference.
    pub fn deterministic_for(&self, hook: Hook) -> impl Iterator<Item = &DeterministicControl> {
        self.deterministic
            .iter()
            .chain(self.signature_controls.iter())
            .filter(move |c| c.hooks.contains(&hook))
    }

    /// Semantic controls that apply at `hook`, given whether tier 1 flagged
    /// anything. This is the escalation rule that keeps p50 latency low.
    pub fn semantic_for(
        &self,
        hook: Hook,
        suspicious: bool,
    ) -> impl Iterator<Item = &SemanticControl> {
        self.semantic.iter().filter(move |c| {
            c.hooks.contains(&hook)
                && match c.escalate_when {
                    EscalateWhen::Always => true,
                    EscalateWhen::Suspicious => suspicious,
                    EscalateWhen::Never => false,
                }
        })
    }

    /// What a call cost in USD, from the pricing table.
    pub fn cost_usd(&self, model: &str, prompt_tokens: i32, completion_tokens: i32) -> f64 {
        self.pricing
            .get(model)
            .map_or(0.0, |price| price.cost(prompt_tokens, completion_tokens))
    }

    /// Deny wins over allow. An empty allow list means "anything not denied".
    pub fn model_allowed(&self, model: &str) -> bool {
        if self.models.denied.iter().any(|m| m == model) {
            return false;
        }
        self.models.allowed.is_empty() || self.models.allowed.iter().any(|m| m == model)
    }
}

/// sha2 0.11 no longer formats its digest as hex, and one loop is cheaper than
/// another dependency.
fn sha256_hex(source: &str) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(source.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest.iter() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn check_unique(seen: &mut HashSet<String>, id: &str) -> Result<(), PolicyError> {
    if !seen.insert(id.to_owned()) {
        return Err(PolicyError::DuplicateId { id: id.to_owned() });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
