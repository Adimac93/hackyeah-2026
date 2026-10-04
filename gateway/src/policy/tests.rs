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
    let policy = Policy::builtin().expect("shipped catalog must load");
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
fn named_profile_supplies_the_control_defaults() {
    let src = MINIMAL.replace(
        "schema_version = 1",
        "schema_version = 1\nprofile = \"permissive\"\n[profiles.permissive]\non_detect = \"flag\"\nfail_mode = \"open\"",
    );
    let policy = parse(&src).unwrap();
    assert_eq!(policy.profile.as_deref(), Some("permissive"));
    assert_eq!(policy.deterministic[0].action, Action::Flag);
    assert_eq!(policy.fail_mode, FailMode::Open);
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

#[test]
fn a_disabled_control_is_not_compiled() {
    let src = MINIMAL.replace(r#"id = "a""#, "id = \"a\"\nenabled = false");
    assert!(parse(&src).unwrap().deterministic.is_empty());
}

/// A judge who types `enabeld = false` must see an error, not a control that
/// quietly keeps firing.
#[test]
fn rejects_an_unknown_key() {
    let src = MINIMAL.replace(r#"id = "a""#, "id = \"a\"\nenabeld = false");
    assert!(matches!(parse(&src), Err(PolicyError::Parse { .. })));
}

const FEED: &str = r#"
source = "test-feed"
version = 7

[[signature]]
external_id = "T-1"
title = "test"
severity = "high"
pattern = 'evil'
"#;

#[test]
fn feed_signatures_carry_their_feed_version() {
    let (feed, compiled) = compile_feed(FEED, "test").unwrap();
    assert_eq!(compiled[0].id, "signature.T-1");
    assert_eq!(compiled[0].feed.as_deref(), Some("test-feed@7"));
    assert_eq!(feed.entries[0].title, "test");
    assert_eq!(feed.text, FEED);
}

#[test]
fn rejects_an_unknown_feed_key() {
    let src = FEED.replace("title", "titel");
    assert!(matches!(
        compile_feed(&src, "test"),
        Err(PolicyError::Parse { .. })
    ));
}

#[test]
fn shipped_feed_is_compiled_into_the_builtin_policy() {
    let policy = Policy::builtin().unwrap();
    assert!(!policy.signature_controls.is_empty());
    assert_eq!(
        policy.feed.as_ref().map(|f| f.source.as_str()),
        Some("local-demo-feed")
    );
}

#[test]
fn the_feed_joins_the_version_and_an_empty_feed_is_none() {
    let alone = Policy::compile(MINIMAL, None, "test").unwrap();
    let blank = Policy::compile(MINIMAL, Some("  "), "test").unwrap();
    let fed = Policy::compile(MINIMAL, Some(FEED), "test").unwrap();
    assert_eq!(alone.sha256, blank.sha256);
    assert!(blank.feed.is_none());
    assert_ne!(alone.sha256, fed.sha256, "a feed edit is a policy change");
    assert_eq!(fed.signature_controls.len(), 1);
}

#[test]
fn an_invalid_feed_rejects_the_whole_upload() {
    let broken = FEED.replace("pattern = 'evil'", "pattern = '([unclosed'");
    assert!(matches!(
        Policy::compile(MINIMAL, Some(&broken), "test"),
        Err(PolicyError::Pattern { .. })
    ));
}

/// An upload that removes or disables a control must show it in the diff and
/// stop it from firing as soon as it is active.
#[test]
fn removing_a_control_disables_it_and_the_diff_says_so() {
    let before = parse(MINIMAL).unwrap();
    let after = parse("schema_version = 1\n").unwrap();
    assert_eq!(before.deterministic_for(Hook::PromptIn).count(), 1);
    assert_eq!(after.deterministic_for(Hook::PromptIn).count(), 0);
    assert_eq!(diff(&before, &after), ["- control a (removed or disabled)"]);

    let disabled = parse(&MINIMAL.replace(r#"id = "a""#, "id = \"a\"\nenabled = false")).unwrap();
    assert_eq!(
        diff(&before, &disabled),
        ["- control a (removed or disabled)"]
    );
}

#[test]
fn the_diff_names_each_changed_field() {
    let before = parse(MINIMAL).unwrap();
    let after = parse(&MINIMAL.replace(
        "severity = \"high\"",
        "severity = \"low\"\naction = \"redact\"",
    ))
    .unwrap();
    assert_eq!(
        diff(&before, &after),
        ["~ control a: action block -> redact; severity high -> low"]
    );
    assert!(diff(&before, &parse(MINIMAL).unwrap()).is_empty());

    let added = parse(&format!("{MINIMAL}\n[models]\ndenied = [\"x\"]\n")).unwrap();
    assert_eq!(
        diff(&before, &added),
        [r#"~ models: {"allowed":[],"denied":[]} -> {"allowed":[],"denied":["x"]}"#]
    );
}

#[test]
fn a_threshold_change_shows_in_the_diff() {
    let semantic = |threshold: &str| {
        parse(&format!(
            "{MINIMAL}\n[[controls.semantic]]\nid = \"s\"\nhooks = [\"prompt_in\"]\nseverity = \"high\"\ndetector = \"d\"\nthreshold = {threshold}\n"
        ))
        .unwrap()
    };
    assert_eq!(
        diff(&semantic("0.8"), &semantic("0.5")),
        ["~ control s: threshold 0.8 -> 0.5"]
    );
}

#[test]
fn budgets_are_not_catalog_settings_any_more() {
    let src = format!("{MINIMAL}\n[budgets.global]\nlimit_tokens = 1\n");
    assert!(matches!(parse(&src), Err(PolicyError::Parse { .. })));
}

#[test]
fn cost_comes_from_the_pricing_table() {
    let src = format!("{MINIMAL}\n[pricing.\"m\"]\ninput_per_mtok = 2.0\noutput_per_mtok = 10.0\n");
    let policy = parse(&src).unwrap();
    let cost = policy.cost_usd("m", 500_000, 100_000);
    assert!((cost - 2.0).abs() < 1e-9, "{cost}");
    assert!(policy.cost_usd("unpriced", 1_000_000, 1_000_000).abs() < f64::EPSILON);
}

#[test]
fn requestable_tables_parse_and_may_not_also_be_granted() {
    let src = format!(
        "{MINIMAL}\n[resources.grants]\napp = [\"invoices\"]\n[resources.requestable]\napp = [\"customers\"]\n"
    );
    let policy = parse(&src).unwrap();
    assert_eq!(policy.resources.tables_for("app"), ["invoices"]);
    assert_eq!(policy.resources.requestable_for("app"), ["customers"]);
    assert!(policy.resources.requestable_for("other").is_empty());

    let both = format!(
        "{MINIMAL}\n[resources.grants]\napp = [\"customers\"]\n[resources.requestable]\napp = [\"customers\"]\n"
    );
    assert!(matches!(
        parse(&both),
        Err(PolicyError::RequestableGranted { identity, table }) if identity == "app" && table == "customers"
    ));
}
