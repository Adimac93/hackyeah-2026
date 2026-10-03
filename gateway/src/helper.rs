//! The prompt helper (docs/BACKEND.md, "security policy path"): when a prompt
//! is refused, tell the user which policy it violated — never which pattern or
//! score caught it — and propose a compliant rewrite. The rewrite is returned
//! for explicit resubmission only; it is never sent to the model, and a
//! resubmission runs the full pipeline again.

use serde::Serialize;

use crate::engine::{self, Detection, Evaluation, Verdict};
use crate::policy::{Action, Hook, Policy};
use crate::semantic::Registry;

#[derive(Debug, Clone, Serialize)]
pub struct Help {
    pub violated_policy: String,
    /// `None` when no compliant version could be produced.
    pub suggestion: Option<String>,
}

/// The policy a control enforces, in words a user can act on. Deliberately
/// coarse: naming the control or its pattern would teach an attacker what to
/// change.
pub fn policy_for(control_id: &str) -> &'static str {
    let family = control_id.split('.').next().unwrap_or_default();
    match family {
        "secret" => "credentials and secrets must not be shared with the assistant",
        "pii" => "personal data must not be shared with the assistant",
        "injection" => "requests must not try to change or bypass the assistant's instructions",
        "exploit" | "signature" => "requests must not contain executable payloads or known attack code",
        "exfiltration" => "requests must not move organisational data outside approved channels",
        "obfuscation" => "requests must not hide content with encoding or invisible characters",
        _ => "the request violates the organisation's AI usage policy",
    }
}

/// Remove what the given detections matched, so the suggestion never echoes
/// the secret or payload back.
pub fn sanitize(policy: &Policy, hook: Hook, text: &str, detections: &[&Detection]) -> String {
    policy
        .deterministic_for(hook)
        .filter(|c| detections.iter().any(|d| d.control_id == c.id))
        .fold(text.to_owned(), |text, control| {
            control.regex.replace_all(&text, "[removed]").into_owned()
        })
}

/// Build the help for a blocked prompt. Only the sanitized text ever reaches
/// the local rewrite model, and a suggestion that would itself be blocked is
/// not offered.
pub async fn help(
    policy: &Policy,
    detectors: &Registry,
    prompt: &str,
    evaluation: &Evaluation,
) -> Option<Help> {
    let blockers: Vec<&Detection> = evaluation
        .detections
        .iter()
        .filter(|d| d.action == Action::Block)
        .collect();
    let first = blockers.first()?;
    let violated = policy_for(&first.control_id);

    // Flagged matches are removed too: they are what made the request look
    // like an attack in the first place.
    let removable: Vec<&Detection> = evaluation
        .detections
        .iter()
        .filter(|d| matches!(d.action, Action::Block | Action::Flag))
        .collect();
    let sanitized = sanitize(policy, Hook::PromptIn, prompt, &removable);
    let candidates = [detectors.rewrite(violated, &sanitized).await, Some(sanitized)];
    let mut suggestion = None;
    for candidate in candidates.into_iter().flatten() {
        let mut check = engine::evaluate(policy, Hook::PromptIn, &candidate);
        engine::escalate(policy, Hook::PromptIn, &mut check, detectors).await;
        if check.verdict != Verdict::Block && candidate.trim() != prompt.trim() {
            suggestion = Some(check.text);
            break;
        }
    }

    Some(Help {
        violated_policy: violated.to_owned(),
        suggestion,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CATALOG: &str = r#"
schema_version = 1

[[controls.deterministic]]
id = "secret.aws"
hooks = ["prompt_in"]
severity = "critical"
action = "block"
pattern = '\bAKIA[0-9A-Z]{16}\b'
"#;

    #[test]
    fn the_policy_is_named_without_the_control() {
        assert!(policy_for("secret.aws-access-key").contains("secrets"));
        assert!(!policy_for("secret.aws-access-key").contains("aws"));
        assert!(policy_for("signature.AIS-0001").contains("attack code"));
        assert!(policy_for("whatever").contains("policy"));
    }

    #[tokio::test]
    async fn the_suggestion_drops_the_secret_and_passes_the_pipeline() {
        let policy = Policy::from_str(CATALOG, "test").unwrap();
        let prompt = "debug this: key AKIAIOSFODNN7EXAMPLE fails";
        let evaluation = engine::evaluate(&policy, Hook::PromptIn, prompt);
        let help = help(&policy, &Registry::mock(), prompt, &evaluation)
            .await
            .expect("a blocked prompt gets help");
        let suggestion = help.suggestion.expect("a compliant rewrite exists");
        assert!(!suggestion.contains("AKIA"), "{suggestion}");
        assert_eq!(suggestion, "debug this: key [removed] fails");
        assert!(help.violated_policy.contains("secrets"));
    }

    #[tokio::test]
    async fn an_allowed_prompt_gets_no_help() {
        let policy = Policy::from_str(CATALOG, "test").unwrap();
        let evaluation = engine::evaluate(&policy, Hook::PromptIn, "hello");
        assert!(help(&policy, &Registry::mock(), "hello", &evaluation).await.is_none());
    }
}
