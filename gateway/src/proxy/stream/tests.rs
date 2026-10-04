use super::*;

const CATALOG: &str = r#"
schema_version = 1

[models]
allowed = ["llama3.1:8b"]

[[controls.deterministic]]
id = "pii.email"
hooks = ["response_out"]
severity = "medium"
action = "redact"
pattern = '\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'

[[controls.deterministic]]
id = "secrets.private-key"
hooks = ["response_out"]
severity = "critical"
action = "block"
pattern = '-----BEGIN [A-Z ]*PRIVATE KEY-----'
"#;

fn policy() -> Policy {
    Policy::from_str(CATALOG, "test").unwrap()
}

/// Feed `deltas` one by one, then finish; returns everything released, in order.
fn stream(policy: &Policy, deltas: &[&str]) -> (Vec<String>, Step) {
    let mut releaser = Releaser::default();
    let mut released = Vec::new();
    for delta in deltas {
        match releaser.push(policy, delta) {
            Step::Release(text) => released.push(text),
            stop => return (released, stop),
        }
    }
    let last = engine::evaluate(policy, Hook::ResponseOut, releaser.raw());
    let end = releaser.release_from(&last, 0);
    (released, end)
}

fn sent(released: &[String], end: &Step) -> String {
    let mut text = released.concat();
    if let Step::Release(rest) = end {
        text.push_str(rest);
    }
    text
}

#[test]
fn the_parser_decodes_split_lines_usage_and_done() {
    let mut parser = UpstreamParser::default();
    let first = parser.feed(b"data: {\"choices\":[{\"delta\":{\"content\":\"Hel");
    assert!(first.is_empty(), "half a line waits for the rest");
    let rest = parser.feed(
        "lo ż\"}}]}\n\n: keep-alive\ndata: not json\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3}}\ndata: [DONE]\n"
            .as_bytes(),
    );
    assert_eq!(
        rest,
        vec![
            Upstream::Delta("Hello ż".to_owned()),
            Upstream::Usage(7, 3),
            Upstream::Done,
        ]
    );
}

#[test]
fn the_parser_keeps_a_character_split_across_chunks() {
    let mut parser = UpstreamParser::default();
    let line = "data: {\"choices\":[{\"delta\":{\"content\":\"zażółć\"}}]}\n".as_bytes();
    // split inside the two-byte `ż`
    let split = line.iter().position(|&b| b == 0xC5).unwrap() + 1;
    assert!(parser.feed(&line[..split]).is_empty());
    assert_eq!(parser.feed(&line[split..]), vec![Upstream::Delta("zażółć".to_owned())]);
}

#[test]
fn the_tail_is_held_back_until_the_end() {
    let policy = policy();
    let text = "word ".repeat(100);
    let deltas: Vec<&str> = text.split_inclusive(' ').collect();
    let (released, end) = stream(&policy, &deltas);
    let streamed = released.concat();
    assert!(!streamed.is_empty(), "long answers stream before they end");
    assert!(streamed.len() <= text.len() - HOLDBACK, "the last {HOLDBACK} bytes wait");
    assert_eq!(sent(&released, &end), text);
}

#[test]
fn an_email_split_across_deltas_is_never_sent_in_clear() {
    let policy = policy();
    let padding = "x ".repeat(200);
    let deltas = [padding.as_str(), "mail jane.", "doe@exam", "ple.com now ", padding.as_str()];
    let (released, end) = stream(&policy, &deltas);
    let all = sent(&released, &end);
    assert!(!all.contains("jane.doe"), "the address never leaves: {all}");
    assert!(all.contains("[REDACTED:pii.email]"));
    for piece in &released {
        assert!(!piece.contains("jane") && !piece.contains("example.com"));
    }
}

#[test]
fn a_block_control_stops_the_stream() {
    let policy = policy();
    let deltas = ["here is the key ", "-----BEGIN RSA PRIVATE KEY-----", " abc"];
    let (released, end) = stream(&policy, &deltas);
    assert!(matches!(end, Step::Block(ref d) if d.control_id == "secrets.private-key"));
    assert!(!released.concat().contains("BEGIN"));
}

#[test]
fn a_redaction_reaching_sent_text_retracts_the_answer() {
    let policy = policy();
    let mut releaser = Releaser::default();
    // A local part longer than the holdback: its start is released before the
    // domain arrives and makes it an address.
    let local = "a".repeat(HOLDBACK + 100);
    let mut released = String::new();
    for piece in local.as_bytes().chunks(40) {
        if let Step::Release(text) = releaser.push(&policy, std::str::from_utf8(piece).unwrap()) {
            released.push_str(&text);
        }
    }
    assert!(!released.is_empty());
    let step = releaser.push(&policy, &format!("@example.com{}", " ".repeat(STEP)));
    assert!(matches!(step, Step::Diverged), "{step:?}");
}
