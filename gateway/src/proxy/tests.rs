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
        role: "member".into(),
        allowed_models: models.iter().map(|m| (*m).to_owned()).collect(),
        allowed_tools: vec![],
        delegates_users: false,
        user: "agent".into(),
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
    assert!(!is_content_control("budget.user.demo-agent"));
    assert!(!is_content_control(RISK_CONTROL));
}

#[test]
fn a_caller_that_delegates_nothing_is_its_own_user() {
    assert_eq!(delegated_user(&principal(&[]), None).unwrap(), "agent");
}

#[test]
fn only_a_delegating_principal_may_name_an_end_user() {
    let agent = principal(&[]);
    assert!(delegated_user(&agent, Some("anna@example.com")).is_err());

    let console = Principal { delegates_users: true, ..principal(&[]) };
    assert_eq!(
        delegated_user(&console, Some(" anna@example.com ")).unwrap(),
        "anna@example.com"
    );
    assert_eq!(delegated_user(&console, None).unwrap(), "agent");
    assert!(delegated_user(&console, Some("")).is_err());
    assert!(delegated_user(&console, Some("anna\nadmin")).is_err());
    assert!(delegated_user(&console, Some(&"a".repeat(255))).is_err());
}

async fn refusal_error(hook: Hook, blocker: &Detection) -> (StatusCode, Value) {
    let response = refusal_for(Uuid::nil(), hook, blocker, None);
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice::<Value>(&body).unwrap()["error"].clone())
}

#[tokio::test]
async fn a_refusal_says_which_stage_and_hook_stopped_it() {
    let mut evaluation = engine::evaluate(&policy(), Hook::PromptIn, "hi");
    gate_model(&policy(), &principal(&[]), "llama3.1:8b", &mut evaluation);
    let mut blocker = evaluation.blocked_by().unwrap().clone();

    let (status, error) = refusal_error(Hook::PromptIn, &blocker).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error["type"], "model_not_allowed");
    assert_eq!(error["stage"], "access");

    blocker.control_id = "secret.aws-access-key".into();
    let (_, error) = refusal_error(Hook::PromptIn, &blocker).await;
    assert_eq!(error["type"], "blocked_by_control");
    assert_eq!(error["stage"], "deterministic");
    assert_eq!(error["hook"], "prompt_in");
    assert_eq!(error["message"], "request blocked by secret.aws-access-key");

    blocker.kind = ControlKind::Semantic;
    let (_, error) = refusal_error(Hook::ResponseOut, &blocker).await;
    assert_eq!(error["stage"], "semantic");
    assert_eq!(error["message"], "response blocked by secret.aws-access-key");
}
