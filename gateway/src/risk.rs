//! Attack history as a risk score (§4.4): users with recent violations get
//! stricter treatment. The score is the sum of `attack_history.risk_score`
//! for the user (the delegated end user, or the calling principal) inside the
//! catalog's `[risk]` window.

use sqlx::PgPool;
use crate::engine::Evaluation;
use crate::policy::{Action, Risk, Severity};

/// Detection id for a decision taken on history rather than on content. Not
/// written back to the history itself, so a refusal does not feed on itself.
pub const RISK_CONTROL: &str = "risk.history";

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
