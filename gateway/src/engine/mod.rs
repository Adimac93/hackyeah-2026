//! Control evaluation: run the catalog against one piece of text at one hook
//! and decide what happens to it.
//!
//! Pure except for the clock. The semantic tier is not wired yet; the shape
//! below is what it plugs into — `suspicious` is the signal tier 1 hands it.

use std::borrow::Cow;
use std::time::Instant;

use serde::Serialize;

use crate::policy::{Action, DeterministicControl, Hook, Policy, Severity};

/// What the caller observes. Distinct from [`Action`], which is what a single
/// control asks for — a control may `flag`, but no request is ever "flagged".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Redact,
    Block,
}

impl Verdict {
    /// Block beats redact beats allow, regardless of catalog order.
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Block, _) | (_, Self::Block) => Self::Block,
            (Self::Redact, _) | (_, Self::Redact) => Self::Redact,
            _ => Self::Allow,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlKind {
    Deterministic,
    Semantic,
}

/// One control firing. `evidence` deliberately never carries the matched text:
/// an audit log that copies the secrets it was built to protect has defeated
/// itself.
#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub control_id: String,
    pub kind: ControlKind,
    pub severity: Severity,
    pub action: Action,
    pub score: Option<f32>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    /// How many times the control matched.
    pub matches: usize,
    /// Byte offset of the first match, for locating it without storing it.
    pub first_offset: usize,
    /// A masked excerpt: enough to recognise the finding, not enough to use it.
    pub excerpt: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evaluation {
    pub verdict: Verdict,
    /// The text to forward. Equal to the input unless something was redacted.
    pub text: String,
    pub detections: Vec<Detection>,
    /// Did tier 1 see anything worth escalating to tier 2?
    pub suspicious: bool,
    pub deterministic_us: u64,
}

impl Evaluation {
    pub fn blocked_by(&self) -> Option<&Detection> {
        self.detections.iter().find(|d| d.action == Action::Block)
    }
}

/// Run every deterministic control registered at `hook`.
pub fn evaluate(policy: &Policy, hook: Hook, text: &str) -> Evaluation {
    let started = Instant::now();

    let mut verdict = Verdict::Allow;
    let mut suspicious = false;
    let mut detections = Vec::new();
    let mut current: Cow<'_, str> = Cow::Borrowed(text);

    for control in policy.deterministic_for(hook) {
        let Some(evidence) = scan(control, &current) else {
            continue;
        };

        match control.action {
            Action::Block => verdict = verdict.merge(Verdict::Block),
            Action::Redact => {
                verdict = verdict.merge(Verdict::Redact);
                let replacement = format!("[REDACTED:{}]", control.id);
                current = Cow::Owned(
                    control
                        .regex
                        .replace_all(&current, replacement.as_str())
                        .into_owned(),
                );
            }
            // `flag` and `allow` do not change the outcome; `flag` marks the
            // request for the semantic tier.
            Action::Flag => suspicious = true,
            Action::Allow => {}
        }

        if control.action != Action::Allow {
            suspicious = true;
        }

        detections.push(Detection {
            control_id: control.id.clone(),
            kind: ControlKind::Deterministic,
            severity: control.severity,
            action: control.action,
            score: None,
            evidence,
        });
    }

    Evaluation {
        verdict,
        text: current.into_owned(),
        detections,
        suspicious,
        #[expect(
            clippy::cast_possible_truncation,
            reason = "a control pass that runs for 500_000 years is not our failure mode"
        )]
        deterministic_us: started.elapsed().as_micros() as u64,
    }
}

/// Match a control, returning evidence that identifies the finding without
/// reproducing it.
fn scan(control: &DeterministicControl, text: &str) -> Option<Evidence> {
    let mut matches = control.regex.find_iter(text);
    let first = matches.next()?;
    let count = 1 + matches.count();

    Some(Evidence {
        matches: count,
        first_offset: first.start(),
        excerpt: mask(first.as_str()),
    })
}

/// Keep the first four characters so a human can recognise the finding, and
/// drop the rest. `AKIAIOSFODNN7EXAMPLE` becomes `AKIA…(20 chars)`.
fn mask(matched: &str) -> String {
    let head: String = matched.chars().take(4).collect();
    format!("{head}…({} chars)", matched.chars().count())
}

#[cfg(test)]
mod tests;
