//! Budgets and the pricing table that turns tokens into money (task.md §4.3).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::default_true;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    pub global: Option<Budget>,
    #[serde(default)]
    pub principal: HashMap<String, Budget>,
    #[serde(default)]
    pub model: HashMap<String, Budget>,
}

/// USD per million tokens. Local models carry an internal chargeback rate, so
/// a money budget means something without a paid API behind it.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Price {
    pub input_per_mtok: f64,
    pub output_per_mtok: f64,
}

impl Price {
    pub fn cost(&self, prompt_tokens: i32, completion_tokens: i32) -> f64 {
        (f64::from(prompt_tokens) * self.input_per_mtok
            + f64::from(completion_tokens) * self.output_per_mtok)
            / 1_000_000.0
    }
}
