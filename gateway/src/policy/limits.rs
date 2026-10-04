//! Catalog sections that are limits rather than detectors: the attack-history
//! risk score, runaway-agent protection and resource access rules.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How past violations tighten checks (§4.4). The score is the sum of
/// `attack_history.risk_score` for the identity inside the window.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Risk {
    #[serde(default = "default_risk_window")]
    pub window_secs: i32,
    /// At or above this, every request runs the `suspicious` semantic tier.
    pub escalate_at: Option<f32>,
    /// At or above this, the identity is refused until the window passes.
    pub block_at: Option<f32>,
}

impl Default for Risk {
    fn default() -> Self {
        Self {
            window_secs: default_risk_window(),
            escalate_at: None,
            block_at: None,
        }
    }
}

const fn default_risk_window() -> i32 {
    3_600
}

/// Runaway agent protection (§4.3, task.md §1): limits on tool calls per
/// identity, counted over a trailing window.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Runaway {
    #[serde(default = "default_runaway_window")]
    pub window_secs: i32,
    /// Tool calls of any kind inside the window.
    pub max_tool_calls: Option<i64>,
    /// The same tool with the same arguments inside the window: a loop.
    pub max_identical_calls: Option<i64>,
    /// Nesting depth an agent reports in `_meta.depth` of a tool call.
    pub max_depth: Option<u64>,
}

impl Default for Runaway {
    fn default() -> Self {
        Self {
            window_secs: default_runaway_window(),
            max_tool_calls: None,
            max_identical_calls: None,
            max_depth: None,
        }
    }
}

const fn default_runaway_window() -> i32 {
    60
}

/// Which tables of the protected resource database each identity may query
/// through `resources__describe` / `resources__query`. Deny-by-default: an
/// identity with no entry sees no table.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    /// identity slug -> table names in the `resources` schema
    #[serde(default)]
    pub grants: BTreeMap<String, Vec<String>>,
    /// identity slug -> tables it may ask for through
    /// `control__request_access {table}`: refused until a human approves, then
    /// granted to that one end user for the approved time.
    #[serde(default)]
    pub requestable: BTreeMap<String, Vec<String>>,
    #[serde(default = "default_max_rows")]
    pub max_rows: i64,
    #[serde(default = "default_statement_timeout")]
    pub statement_timeout_ms: u64,
}

impl Default for Resources {
    fn default() -> Self {
        Self {
            grants: BTreeMap::new(),
            requestable: BTreeMap::new(),
            max_rows: default_max_rows(),
            statement_timeout_ms: default_statement_timeout(),
        }
    }
}

const fn default_max_rows() -> i64 {
    200
}

const fn default_statement_timeout() -> u64 {
    2_000
}

impl Resources {
    pub fn tables_for(&self, slug: &str) -> &[String] {
        self.grants.get(slug).map_or(&[], Vec::as_slice)
    }

    pub fn requestable_for(&self, slug: &str) -> &[String] {
        self.requestable.get(slug).map_or(&[], Vec::as_slice)
    }

    /// A table both granted and requestable for one identity is a catalog
    /// mistake: it is unclear whether the author meant to require approval.
    pub fn overlap(&self) -> Option<(&str, &str)> {
        self.requestable.iter().find_map(|(slug, tables)| {
            let granted = self.tables_for(slug);
            tables
                .iter()
                .find(|table| granted.contains(table))
                .map(|table| (slug.as_str(), table.as_str()))
        })
    }
}
