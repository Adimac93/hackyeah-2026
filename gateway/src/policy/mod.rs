//! The policy engine: parse, validate and compile the control catalog.
//!
//! The TOML catalog is the authored source of truth (task.md §4.1). It lives
//! in the database (`store`); everything else here is pure — parsing and
//! validation with no I/O — so it is cheap to test, which is where most of the
//! real bugs in a policy engine live.

mod diff;
mod feed;
mod handle;
mod limits;
mod mcp;
mod pricing;
pub mod store;

pub use diff::diff;
pub use feed::{Feed, FeedEntry};
pub use handle::PolicyHandle;
pub use limits::{Resources, Risk, Runaway};
pub use mcp::{McpServer, McpSettings, UnknownPrincipal};
pub use pricing::Price;

use feed::compile_feed;

use std::collections::{HashMap, HashSet};

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
    #[error("active profile {name:?} is not defined")]
    Profile { name: String },
    #[error("MCP server name {name:?} is reserved for the gateway's own tools")]
    ReservedServer { name: String },
    #[error("resources: table {table:?} is both granted and requestable for {identity}")]
    RequestableGranted { identity: String, table: String },
}

const SCHEMA_VERSION: u32 = 1;

/// The documented sample, compiled into the binary. The gateway never reads
/// these files at runtime; they seed an empty database on first start.
pub const BUILTIN_CATALOG: &str = include_str!("../../../policy/control-catalog.toml");
pub const BUILTIN_SIGNATURES: &str = include_str!("../../../policy/signatures.toml");

// ------------------------------------------------------------------ raw TOML

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCatalog {
    schema_version: u32,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    profiles: HashMap<String, RawDefaults>,
    #[serde(default)]
    defaults: RawDefaults,
    #[serde(default)]
    models: Models,
    #[serde(default)]
    pricing: HashMap<String, Price>,
    #[serde(default)]
    controls: RawControls,
    #[serde(default)]
    mcp: McpSettings,
    #[serde(default)]
    risk: Risk,
    #[serde(default)]
    runaway: Runaway,
    #[serde(default)]
    resources: Resources,
}

#[derive(Debug, Clone, Copy, Deserialize)]
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
    /// What the `dev` mock judge treats as a hit. Ignored by real detectors.
    #[serde(default)]
    mock_keywords: Vec<String>,
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
    pub mock_keywords: Vec<String>,
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

/// A validated, compiled catalog. Swapped in atomically on activation.
#[derive(Debug)]
pub struct Policy {
    /// sha256 of the catalog and feed text this was built from.
    pub sha256: String,
    /// `policy_versions.id` of that text — what every decision in the audit
    /// log points at. `None` only for a policy that was never stored (tests).
    pub version_id: Option<i64>,
    pub source: String,
    pub on_detect: Action,
    pub fail_mode: FailMode,
    pub profile: Option<String>,
    pub models: Models,
    /// Per-model price, keyed by model name. An unpriced model costs nothing.
    pub pricing: HashMap<String, Price>,
    pub deterministic: Vec<DeterministicControl>,
    pub semantic: Vec<SemanticControl>,
    /// The external feed (§4.4) uploaded alongside the catalog, if any.
    pub feed: Option<Feed>,
    /// Compiled from the feed. Kept separate from the catalog controls so the
    /// dashboard can tell a feed match from a catalog rule.
    pub signature_controls: Vec<DeterministicControl>,
    pub mcp: McpSettings,
    pub risk: Risk,
    pub runaway: Runaway,
    pub resources: Resources,
}

impl Policy {
    /// Compile a catalog and, optionally, the attack-signature feed uploaded
    /// with it. Both texts join the version hash, so a feed edit is a policy
    /// change the audit log can point at.
    pub fn compile(
        catalog: &str,
        signatures: Option<&str>,
        origin: &str,
    ) -> Result<Self, PolicyError> {
        let mut policy = Self::from_str(catalog, origin)?;
        if let Some(raw) = signatures.filter(|raw| !raw.trim().is_empty()) {
            let (feed, controls) = compile_feed(raw, &format!("{origin} (signatures)"))?;
            for control in &controls {
                if policy.deterministic.iter().any(|c| c.id == control.id) {
                    return Err(PolicyError::DuplicateId {
                        id: control.id.clone(),
                    });
                }
            }
            policy.signature_controls = controls;
            policy.feed = Some(feed);
            policy.sha256 = sha256_hex(&format!("{catalog}{raw}"));
        }
        Ok(policy)
    }

    /// The documented sample shipped in the binary.
    pub fn builtin() -> Result<Self, PolicyError> {
        Self::compile(BUILTIN_CATALOG, Some(BUILTIN_SIGNATURES), "builtin")
    }

    /// Compile a catalog alone, without a feed.
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

        let (on_detect, fail_mode) = match raw.profile.as_deref() {
            Some(name) => raw
                .profiles
                .get(name)
                .map(|profile| (profile.on_detect, profile.fail_mode))
                .ok_or_else(|| PolicyError::Profile {
                    name: name.to_owned(),
                })?,
            None => (raw.defaults.on_detect, raw.defaults.fail_mode),
        };

        // `control__*` tools are served by the gateway; an upstream with that
        // name would let it impersonate them.
        if let Some(server) = raw.mcp.servers.iter().find(|s| s.name == "control") {
            return Err(PolicyError::ReservedServer {
                name: server.name.clone(),
            });
        }

        if let Some((identity, table)) = raw.resources.overlap() {
            return Err(PolicyError::RequestableGranted {
                identity: identity.to_owned(),
                table: table.to_owned(),
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
                action: control.action.unwrap_or(on_detect),
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
                action: control.action.unwrap_or(on_detect),
                timeout: std::time::Duration::from_millis(control.timeout_ms),
                fail_mode: control.fail_mode.unwrap_or(fail_mode),
                mock_keywords: control.mock_keywords,
                detector: control.detector,
                threshold: control.threshold,
                escalate_when: control.escalate_when,
            });
        }

        Ok(Self {
            sha256: sha256_hex(source),
            version_id: None,
            source: origin.to_owned(),
            on_detect,
            fail_mode,
            profile: raw.profile,
            models: raw.models,
            pricing: raw.pricing,
            deterministic,
            semantic,
            feed: None,
            signature_controls: Vec::new(),
            mcp: raw.mcp,
            risk: raw.risk,
            runaway: raw.runaway,
            resources: raw.resources,
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
