use super::*;

fn row() -> BudgetRow {
    BudgetRow {
        id: 1,
        scope: "principal".into(),
        scope_id: Some("demo-agent".into()),
        window_secs: 3_600,
        limit_tokens: None,
        limit_usd: None,
        limit_requests: None,
        limit_concurrency: None,
        hard: true,
    }
}

#[test]
fn under_every_limit_nothing_is_exceeded() {
    let row = BudgetRow {
        limit_tokens: Some(100),
        limit_usd: Some(1.0),
        limit_requests: Some(10),
        limit_concurrency: Some(2),
        ..row()
    };
    let used = Used {
        tokens: 99,
        usd: 0.5,
        requests: 9,
        inflight: 1,
    };
    assert_eq!(exceeded(&row, &used), None);
}

#[test]
fn each_budget_type_blocks_when_reached() {
    let cases = [
        (
            BudgetRow { limit_tokens: Some(100), ..row() },
            Used { tokens: 100, ..Used::default() },
            "100/100 tokens",
        ),
        (
            BudgetRow { limit_usd: Some(1.0), ..row() },
            Used { usd: 1.2, ..Used::default() },
            "$1.2000/$1.00",
        ),
        (
            BudgetRow { limit_requests: Some(5), ..row() },
            Used { requests: 5, ..Used::default() },
            "5/5 requests",
        ),
        (
            BudgetRow { limit_concurrency: Some(2), ..row() },
            Used { inflight: 2, ..Used::default() },
            "2/2 requests in flight",
        ),
    ];
    for (row, used, expected) in cases {
        let reason = exceeded(&row, &used).expect("budget must be exceeded");
        assert!(reason.contains(expected), "{reason}");
        assert!(reason.starts_with("principal.demo-agent budget exhausted"), "{reason}");
    }
}

#[test]
fn scope_decides_who_a_budget_applies_to() {
    let principal = Principal {
        id: uuid::Uuid::nil(),
        slug: "demo-agent".into(),
        allowed_models: vec![],
        allowed_tools: vec![],
    };
    let global = BudgetRow { scope: "global".into(), scope_id: None, ..row() };
    let other = BudgetRow { scope_id: Some("red-team".into()), ..row() };
    let model = BudgetRow { scope: "model".into(), scope_id: Some("m".into()), ..row() };
    assert!(global.applies(&principal, None));
    assert!(row().applies(&principal, None));
    assert!(!other.applies(&principal, None));
    assert!(model.applies(&principal, Some("m")));
    assert!(!model.applies(&principal, None), "a tool call has no model");
}

fn input(scope: &str, scope_id: Option<&str>) -> BudgetInput {
    BudgetInput {
        scope: scope.into(),
        scope_id: scope_id.map(Into::into),
        window_secs: 60,
        limit_tokens: Some(1),
        limit_usd: None,
        limit_requests: None,
        limit_concurrency: None,
        hard: true,
        enabled: true,
    }
}

#[test]
fn budget_input_is_validated_before_it_reaches_the_table() {
    assert!(input("global", None).validate().is_ok());
    assert!(input("principal", Some("demo-agent")).validate().is_ok());
    assert!(input("global", Some("x")).validate().is_err());
    assert!(input("principal", None).validate().is_err());
    assert!(input("team", Some("x")).validate().is_err());
    let no_limit = BudgetInput { limit_tokens: None, ..input("global", None) };
    assert!(no_limit.validate().is_err());
    let negative = BudgetInput { limit_tokens: Some(-1), ..input("global", None) };
    assert!(negative.validate().is_err());
}
