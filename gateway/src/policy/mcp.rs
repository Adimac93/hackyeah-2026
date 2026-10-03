//! Which upstream MCP servers sit behind the gateway, and who may reach them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::default_true;

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
    /// Approved tools: name -> sha256 of the tool definition (name,
    /// description, input schema) as the security team reviewed it. When any
    /// tool is pinned, an unpinned or changed tool is hidden and reported —
    /// a rug-pull or poisoned description never reaches the model.
    #[serde(default)]
    pub pinned: BTreeMap<String, String>,
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
