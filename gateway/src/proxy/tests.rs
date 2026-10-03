use super::*;

const CATALOG: &str = r#"
schema_version = 1

[models]
allowed = ["llama3.1:8b", "qwen2.5:7b"]
denied = ["qwen2.5:7b"]

[[controls.deterministic]]
id = "pii.email"
hooks = ["prompt_in"]
severity = "medium"
action = "redact"
pattern = '\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
"#;

fn policy() -> Policy {
    Policy::from_str(CATALOG, "test").unwrap()
}

fn principal(models: &[&str]) -> Principal {
    Principal {
        id: Uuid::nil(),
        slug: "agent".into(),
        allowed_models: models.iter().map(|m| (*m).to_owned()).collect(),
        allowed_tools: vec![],
    }
}

fn model_verdict(principal: &Principal, model: &str) -> Verdict {
    let mut evaluation = engine::evaluate(&policy(), Hook::PromptIn, "hi");
    gate_model(&policy(), principal, model, &mut evaluation);
    evaluation.verdict
}

#[test]
fn an_identity_with_no_model_grant_reaches_no_model() {
    assert_eq!(model_verdict(&principal(&[]), "llama3.1:8b"), Verdict::Block);
}

#[test]
fn deny_beats_the_global_allow_and_the_grant_narrows_it() {
    let granted = principal(&["llama3.1:8b", "qwen2.5:7b", "mistral:7b"]);
    assert_eq!(model_verdict(&granted, "llama3.1:8b"), Verdict::Allow);
    assert_eq!(model_verdict(&granted, "qwen2.5:7b"), Verdict::Block, "global deny wins");
    assert_eq!(model_verdict(&granted, "mistral:7b"), Verdict::Block, "not globally allowed");
    assert_eq!(model_verdict(&principal(&["qwen2.5:7b"]), "llama3.1:8b"), Verdict::Block);
}

/// The old redaction wrote the whole joined conversation into the last
/// message. Each message must keep its own content.
#[test]
fn redaction_rewrites_each_message_in_place() {
    let mut body = json!({
        "model": "llama3.1:8b",
        "messages": [
            { "role": "system", "content": "you help a@b.com" },
            { "role": "user", "content": "mail c@d.org please" },
        ],
    });
    redact_messages(&policy(), &mut body);
    assert_eq!(body["messages"][0]["content"], "you help [REDACTED:pii.email]");
    assert_eq!(body["messages"][1]["content"], "mail [REDACTED:pii.email] please");
}

/// OpenAI clients may send content as an array of parts. Those parts are what
/// the model reads, so they must be both checked and redacted.
#[test]
fn array_content_parts_are_checked_and_redacted() {
    let mut body = json!({
        "messages": [{ "role": "user", "content": [
            { "type": "text", "text": "write to a@b.com" },
            { "type": "image_url", "image_url": { "url": "https://x/y.png" } },
        ]}],
    });
    assert_eq!(extract_prompt(&body), "write to a@b.com");
    redact_messages(&policy(), &mut body);
    assert_eq!(body["messages"][0]["content"][0]["text"], "write to [REDACTED:pii.email]");
    assert_eq!(body["messages"][0]["content"][1]["type"], "image_url");
}

#[test]
fn refusals_name_their_category() {
    assert!(is_content_control("secret.aws-access-key"));
    assert!(!is_content_control(MODEL_NOT_ALLOWED));
    assert!(!is_content_control("budget.principal.demo-agent"));
    assert!(!is_content_control(RISK_CONTROL));
}
