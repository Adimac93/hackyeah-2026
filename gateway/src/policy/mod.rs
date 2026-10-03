//! The policy engine: parse, validate and compile the control catalog.
//!
//! The TOML file is the authored source of truth (task.md §4.1). Everything
//! here is pure — parsing and validation with no I/O beyond reading the file —
//! so it is cheap to test, which is where most of the real bugs in a policy
//! engine live.

mod watch;

pub use watch::{PolicyHandle, spawn_watcher};

use std::collections::{HashMap, HashSet};
use std::path::Path;

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
struct RawCatalog {
    schema_version: u32,
    #[serde(default)]
    defaults: RawDefaults,
    #[serde(default)]
    models: Models,
    #[serde(default)]
    budgets: Budgets,
    #[serde(default)]
    controls: RawControls,
    signatures: Option<SignatureFeed>,
}

#[derive(Debug, Deserialize)]
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
struct RawControls {
    #[serde(default)]
    deterministic: Vec<RawDeterministic>,
    #[serde(default)]
    semantic: Vec<RawSemantic>,
}

#[derive(Debug, Deserialize)]
struct RawDeterministic {
    id: String,
    hooks: Vec<Hook>,
    severity: Severity,
    action: Option<Action>,
    pattern: String,
}

#[derive(Debug, Deserialize)]
struct RawSemantic {
    id: String,
    hooks: Vec<Hook>,
    severity: Severity,
    action: Option<Action>,
    detector: String,
    threshold: f32,
    #[serde(default = "default_escalation")]
    escalate_when: EscalateWhen,
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
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct Models {
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub denied: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Budget {
    #[serde(default = "default_window")]
    pub window_secs: i32,
    pub limit_usd: Option<f64>,
    pub limit_tokens: Option<i64>,
    #[serde(default = "default_true")]
    pub hard: bool,
}

fn default_window() -> i32 {
    86_400
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct Budgets {
    pub global: Option<Budget>,
    #[serde(default)]
    pub principal: HashMap<String, Budget>,
    #[serde(default)]
    pub model: HashMap<String, Budget>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    pub deterministic: Vec<DeterministicControl>,
    pub semantic: Vec<SemanticControl>,
    pub signatures: Option<SignatureFeed>,
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
        Self::from_str(&source, &display)
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
            deterministic.push(DeterministicControl {
                id: control.id,
                hooks: control.hooks.into_iter().collect(),
                severity: control.severity,
                action: control.action.unwrap_or(raw.defaults.on_detect),
                regex,
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
            semantic.push(SemanticControl {
                id: control.id,
                hooks: control.hooks.into_iter().collect(),
                severity: control.severity,
                action: control.action.unwrap_or(raw.defaults.on_detect),
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
            deterministic,
            semantic,
            signatures: raw.signatures,
        })
    }

    /// Deterministic controls that apply at `hook`, in catalog order.
    pub fn deterministic_for(&self, hook: Hook) -> impl Iterator<Item = &DeterministicControl> {
        self.deterministic
            .iter()
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
