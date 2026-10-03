use super::*;

const MINIMAL: &str = r#"
schema_version = 1

[[controls.deterministic]]
id = "a"
hooks = ["prompt_in"]
severity = "high"
pattern = 'foo'
"#;

fn parse(src: &str) -> Result<Policy, PolicyError> {
    Policy::from_str(src, "test")
}

/// The catalog we actually ship must compile. This is the one test that would
/// have caught every policy typo made during the build.
#[test]
fn shipped_catalog_compiles() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../policy/control-catalog.toml"
    );
    let policy = Policy::load(path).expect("shipped catalog must load");
    assert!(!policy.deterministic.is_empty());
    assert!(!policy.semantic.is_empty());
    assert_eq!(policy.sha256.len(), 64);
}

#[test]
fn action_falls_back_to_the_default() {
    let policy = parse(MINIMAL).unwrap();
    assert_eq!(policy.deterministic[0].action, Action::Block);

    let permissive = parse(&MINIMAL.replace(
        "schema_version = 1",
        "schema_version = 1\n[defaults]\non_detect = \"flag\"\nfail_mode = \"open\"",
    ))
    .unwrap();
    assert_eq!(permissive.deterministic[0].action, Action::Flag);
    assert_eq!(permissive.fail_mode, FailMode::Open);
}

#[test]
fn rejects_a_pattern_that_does_not_compile() {
    let src = MINIMAL.replace("pattern = 'foo'", "pattern = '([unclosed'");
    assert!(matches!(parse(&src), Err(PolicyError::Pattern { .. })));
}

#[test]
fn rejects_a_control_with_no_hooks() {
    let src = MINIMAL.replace(r#"hooks = ["prompt_in"]"#, "hooks = []");
    assert!(matches!(parse(&src), Err(PolicyError::NoHooks { .. })));
}

#[test]
fn rejects_duplicate_ids() {
    let src = format!("{MINIMAL}{MINIMAL}").replace("schema_version = 1\n", "");
    let src = format!("schema_version = 1\n{src}");
    assert!(matches!(parse(&src), Err(PolicyError::DuplicateId { .. })));
}

#[test]
fn rejects_an_unknown_schema_version() {
    let src = MINIMAL.replace("schema_version = 1", "schema_version = 99");
    assert!(matches!(
        parse(&src),
        Err(PolicyError::SchemaVersion { .. })
    ));
}

#[test]
fn rejects_a_threshold_outside_the_unit_range() {
    let src = format!(
        r#"{MINIMAL}
[[controls.semantic]]
id = "s"
hooks = ["prompt_in"]
severity = "high"
detector = "prompt_guard_2"
threshold = 1.4
"#
    );
    assert!(matches!(parse(&src), Err(PolicyError::Threshold { .. })));
}

#[test]
fn escalation_decides_which_semantic_controls_run() {
    let src = format!(
        r#"{MINIMAL}
[[controls.semantic]]
id = "always"
hooks = ["prompt_in"]
severity = "low"
detector = "d"
threshold = 0.5
escalate_when = "always"

[[controls.semantic]]
id = "suspicious"
hooks = ["prompt_in"]
severity = "low"
detector = "d"
threshold = 0.5
escalate_when = "suspicious"

[[controls.semantic]]
id = "never"
hooks = ["prompt_in"]
severity = "low"
detector = "d"
threshold = 0.5
escalate_when = "never"
"#
    );
    let policy = parse(&src).unwrap();

    let calm: Vec<_> = policy
        .semantic_for(Hook::PromptIn, false)
        .map(|c| c.id.as_str())
        .collect();
    assert_eq!(calm, ["always"], "a clean request must not pay for tier 2");

    let flagged: Vec<_> = policy
        .semantic_for(Hook::PromptIn, true)
        .map(|c| c.id.as_str())
        .collect();
    assert_eq!(flagged, ["always", "suspicious"]);
}

#[test]
fn controls_only_run_at_their_own_hooks() {
    let policy = parse(MINIMAL).unwrap();
    assert_eq!(policy.deterministic_for(Hook::PromptIn).count(), 1);
    assert_eq!(policy.deterministic_for(Hook::ToolResult).count(), 0);
}

#[test]
fn denied_models_beat_allowed_ones() {
    let src = format!("{MINIMAL}\n[models]\nallowed = [\"good\", \"both\"]\ndenied = [\"both\"]\n");
    let policy = parse(&src).unwrap();
    assert!(policy.model_allowed("good"));
    assert!(!policy.model_allowed("both"), "deny must win over allow");
    assert!(!policy.model_allowed("unlisted"));

    // An empty allow list means "anything not explicitly denied".
    let open = parse(MINIMAL).unwrap();
    assert!(open.model_allowed("anything"));
}

#[test]
fn the_version_tracks_the_content() {
    let a = parse(MINIMAL).unwrap();
    let b = parse(MINIMAL).unwrap();
    let c = parse(&MINIMAL.replace("'foo'", "'bar'")).unwrap();
    assert_eq!(a.sha256, b.sha256);
    assert_ne!(a.sha256, c.sha256);
}
