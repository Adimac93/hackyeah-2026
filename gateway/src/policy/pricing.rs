//! The pricing table that turns tokens into money (task.md §4.3).

use serde::{Deserialize, Serialize};

/// USD per million tokens. Local models carry an internal chargeback rate, so
/// a money budget means something without a paid API behind it.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
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
