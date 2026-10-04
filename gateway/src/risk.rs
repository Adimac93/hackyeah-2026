//! Attack history as a risk score (§4.4): users with recent violations get
//! stricter treatment. The score is the sum of `attack_history.risk_score`
//! for the user (the delegated end user, or the calling principal) inside the
//! catalog's `[risk]` window.

use sqlx::PgPool;
use crate::budget::BUDGET_PREFIX;
use crate::engine::{Detection, Evaluation};
use crate::policy::{Action, Risk, Severity};

/// Detection id for a decision taken on history rather than on content. Not
/// written back to the history itself, so a refusal does not feed on itself.
pub const RISK_CONTROL: &str = "risk.history";

/// Blocked and flagged content feeds the risk score. Refusals on spend or on
/// the score itself do not: an exhausted budget is not an attack, and a
/// history refusal that raised the history would never expire.
pub fn counts(detection: &Detection) -> bool {
    matches!(detection.action, Action::Block | Action::Flag)
        && !detection.control_id.starts_with(BUDGET_PREFIX)
        && detection.control_id != RISK_CONTROL
}

/// What one counted detection adds to the score.
pub const fn weight(severity: Severity) -> f32 {
    match severity {
        Severity::Info => 0.05,
        Severity::Low => 0.15,
        Severity::Medium => 0.35,
        Severity::High => 0.65,
        Severity::Critical => 1.0,
    }
}

/// What one evaluated piece of traffic adds to its user's score: the sum the
/// audit log writes to `attack_history` for it.
pub fn of(evaluation: &Evaluation) -> f32 {
    evaluation
        .detections
        .iter()
        .filter(|d| counts(d))
        .map(|d| weight(d.severity))
        .fold(0.0, |total, weight| total + weight)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Normal,
    /// Run the `suspicious` semantic tier on every request.
    Escalate,
    Block,
}

pub fn assess(risk: &Risk, score: f32) -> Outcome {
    if risk.block_at.is_some_and(|limit| score >= limit) {
        Outcome::Block
    } else if risk.escalate_at.is_some_and(|limit| score >= limit) {
        Outcome::Escalate
    } else {
        Outcome::Normal
    }
}

pub async fn score(pool: &PgPool, user: &str, window_secs: i32) -> f32 {
    sqlx::query_scalar::<_, f64>(
        "select coalesce(sum(risk_score), 0)::float8 from attack_history
         where end_user = $1 and created_at > now() - make_interval(secs => $2::int)",
    )
    .bind(user)
    .bind(window_secs)
    .fetch_one(pool)
    .await
    .map_or_else(
        |error| {
            tracing::error!(%error, "risk score lookup failed");
            0.0
        },
        #[expect(clippy::cast_possible_truncation, reason = "a score needs no more than f32")]
        |score| score as f32,
    )
}

/// Look up the user's score and apply the catalog's thresholds.
pub async fn apply(pool: &PgPool, risk: &Risk, user: &str, evaluation: &mut Evaluation) {
    if risk.escalate_at.is_none() && risk.block_at.is_none() {
        return;
    }
    let score = score(pool, user, risk.window_secs).await;
    match assess(risk, score) {
        Outcome::Normal => {}
        Outcome::Escalate => {
            evaluation.suspicious = true;
            evaluation.gate(
                RISK_CONTROL.to_owned(),
                Severity::Info,
                Action::Allow,
                format!("risk score {score:.2}: escalated to the semantic tier"),
            );
        }
        Outcome::Block => evaluation.gate(
            RISK_CONTROL.to_owned(),
            Severity::High,
            Action::Block,
            format!("risk score {score:.2} from recent violations"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Iterator::sum` over floats starts at -0.0, which reaches the API as
    /// `-0.0` for a clean request.
    #[test]
    fn clean_traffic_adds_exactly_zero() {
        let clean = crate::engine::evaluate(&crate::policy::Policy::builtin().unwrap(), crate::policy::Hook::PromptIn, "hi");
        assert!(of(&clean).to_bits() == 0.0_f32.to_bits());
    }

    #[test]
    fn thresholds_tighten_then_block() {
        let risk = Risk {
            window_secs: 3_600,
            escalate_at: Some(1.0),
            block_at: Some(3.0),
        };
        assert_eq!(assess(&risk, 0.0), Outcome::Normal);
        assert_eq!(assess(&risk, 0.99), Outcome::Normal);
        assert_eq!(assess(&risk, 1.0), Outcome::Escalate);
        assert_eq!(assess(&risk, 3.0), Outcome::Block);
        assert_eq!(assess(&Risk::default(), 100.0), Outcome::Normal, "no thresholds, no effect");
    }
}
