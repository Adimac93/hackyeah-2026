use std::sync::Arc;

use super::*;

fn principal(allowed_tools: &[&str]) -> Principal {
    Principal {
        id: Uuid::new_v4(),
        slug: "red-team".to_owned(),
        role: "member".to_owned(),
        allowed_models: Vec::new(),
        allowed_tools: allowed_tools.iter().map(|t| (*t).to_owned()).collect(),
        delegates_users: false,
        user: "red-team".to_owned(),
    }
}

fn policy() -> Policy {
    Policy::builtin().unwrap()
}

#[test]
fn ttl_defaults_and_clamps() {
    assert_eq!(clamp_ttl(None), DEFAULT_TTL_MINUTES);
    assert_eq!(clamp_ttl(Some(0)), 1);
    assert_eq!(clamp_ttl(Some(30)), 30);
    assert_eq!(clamp_ttl(Some(10_000)), MAX_TTL_MINUTES);
}

fn tool(name: &str) -> Access {
    Access::Tool(name.to_owned())
}

fn table(name: &str) -> Access {
    Access::Table(name.to_owned())
}

#[test]
fn one_open_request_per_user_and_target() {
    let me = Uuid::new_v4();
    let open = || {
        [
            (me, "anna".to_owned(), tool("docs__read")),
            (me, "anna".to_owned(), table("customers")),
        ]
        .into_iter()
    };
    assert!(admit(open(), me, "anna", &tool("docs__read")).is_err());
    assert!(admit(open(), me, "anna", &table("customers")).is_err());
    assert!(admit(open(), me, "anna", &tool("docs__search")).is_ok());
    // A table and a tool of the same name are different targets.
    assert!(admit(open(), me, "anna", &table("docs__read")).is_ok());
    // Another end user of the same principal asks for themselves.
    assert!(admit(open(), me, "ben", &table("customers")).is_ok());
    // Someone else's open request does not count against me.
    assert!(admit(open(), Uuid::new_v4(), "anna", &tool("docs__read")).is_ok());
}

#[test]
fn a_principal_cannot_flood_the_approvers() {
    let me = Uuid::new_v4();
    let open: Vec<_> = (0..MAX_PENDING_PER_PRINCIPAL)
        .map(|i| (me, format!("user{i}"), tool(&format!("docs__t{i}"))))
        .collect();
    assert!(admit(open.into_iter(), me, "someone", &tool("docs__other")).is_err());
}

#[test]
fn tables_are_requestable_only_where_the_catalog_says() {
    let policy = Policy::from_str(
        r#"
schema_version = 1
[resources.grants]
console-chat = ["invoices"]
[resources.requestable]
console-chat = ["customers"]
"#,
        "test",
    )
    .unwrap();
    let mut chat = principal(&[]);
    chat.slug = "console-chat".to_owned();

    assert_eq!(
        validate_table(&policy, &chat, false, "customers"),
        Target::Requestable
    );
    assert_eq!(
        validate_table(&policy, &chat, true, "customers"),
        Target::AlreadyPermitted
    );
    assert_eq!(
        validate_table(&policy, &chat, false, "invoices"),
        Target::AlreadyPermitted
    );
    assert!(matches!(
        validate_table(&policy, &chat, false, "payroll"),
        Target::Refused(_)
    ));
    // Requestable for one identity is not requestable for another.
    assert!(matches!(
        validate_table(&policy, &principal(&[]), false, "customers"),
        Target::Refused(_)
    ));
}

#[test]
fn targets_are_validated() {
    let policy = policy();
    let narrow = principal(&["docs__search"]);

    assert_eq!(
        validate_target(&policy, &narrow, false, "docs__read"),
        Target::Requestable
    );
    assert_eq!(
        validate_target(&policy, &narrow, false, "docs__search"),
        Target::AlreadyPermitted
    );
    assert_eq!(
        validate_target(&policy, &narrow, true, "docs__read"),
        Target::AlreadyPermitted
    );
    // Grants are deny-by-default: an empty list grants nothing.
    assert_eq!(
        validate_target(&policy, &principal(&[]), false, "docs__read"),
        Target::Requestable
    );
    for refused in ["control__my_access", "docs", "nowhere__read"] {
        assert!(
            matches!(
                validate_target(&policy, &narrow, false, refused),
                Target::Refused(_)
            ),
            "{refused} must be refused"
        );
    }
}

/// The demo happy path, minus HTTP: an agent asks, a human approves, the
/// agent gets a grant the tool gate will honour.
#[tokio::test]
async fn an_approved_request_becomes_a_grant() {
    let approvals = Arc::new(Approvals::new(None));
    let agent = principal(&["docs__search"]);
    let mut console = approvals.subscribe();

    let waiting = {
        let approvals = Arc::clone(&approvals);
        let agent = agent.clone();
        tokio::spawn(async move {
            approvals
                .request(&agent, &tool("docs__read"), "need the Q3 summary", 15)
                .await
        })
    };

    let ApprovalEvent::Request(request) = console.recv().await.unwrap() else {
        panic!("the console must be told about the request first");
    };
    assert_eq!(request.tool.as_deref(), Some("docs__read"));
    assert_eq!(request.resource, None);
    assert_eq!(request.end_user, "red-team");
    assert_eq!(approvals.snapshot().len(), 1);

    approvals
        .decide(
            request.id,
            Decision {
                approve: true,
                ttl_minutes: 15,
                note: None,
                decided_by: "analyst@example.com".to_owned(),
            },
        )
        .await
        .unwrap();

    assert!(matches!(waiting.await.unwrap(), Outcome::Granted { .. }));
    assert!(approvals.has_grant(agent.id, "red-team", &tool("docs__read")));
    assert!(!approvals.has_grant(agent.id, "red-team", &tool("docs__search")));
    assert!(approvals.snapshot().is_empty());

    // Deciding twice is a conflict, not a second grant.
    let again = approvals
        .decide(
            request.id,
            Decision {
                approve: false,
                ttl_minutes: 15,
                note: None,
                decided_by: "analyst@example.com".to_owned(),
            },
        )
        .await;
    assert!(matches!(again, Err(DecideError::NotPending)));
}

#[tokio::test]
async fn a_dropped_caller_expires_its_request() {
    let approvals = Arc::new(Approvals::new(None));
    let agent = principal(&[]);
    let mut console = approvals.subscribe();

    let waiting = {
        let approvals = Arc::clone(&approvals);
        tokio::spawn(async move {
            approvals
                .request(&agent, &tool("docs__read"), "x", 15)
                .await
        })
    };
    let ApprovalEvent::Request(request) = console.recv().await.unwrap() else {
        panic!("expected a request");
    };

    waiting.abort();
    let _ = waiting.await;

    let ApprovalEvent::Expired { id } = console.recv().await.unwrap() else {
        panic!("the console must hear that the request is gone");
    };
    assert_eq!(id, request.id);
    assert!(approvals.snapshot().is_empty());
}

/// A delegating principal acts for many people; approving a table for one of
/// them must not open it to the rest.
#[tokio::test]
async fn a_table_grant_covers_only_the_end_user_it_was_asked_for() {
    let approvals = Arc::new(Approvals::new(None));
    let mut anna = principal(&[]);
    anna.slug = "console-chat".to_owned();
    anna.user = "anna@example.com".to_owned();
    let mut ben = anna.clone();
    ben.user = "ben@example.com".to_owned();
    let mut console = approvals.subscribe();

    let waiting = {
        let approvals = Arc::clone(&approvals);
        let anna = anna.clone();
        tokio::spawn(async move {
            approvals
                .request(&anna, &table("customers"), "overdue customers by email", 10)
                .await
        })
    };
    let ApprovalEvent::Request(request) = console.recv().await.unwrap() else {
        panic!("expected a request");
    };
    assert_eq!(request.resource.as_deref(), Some("customers"));
    assert_eq!(request.tool, None);
    assert_eq!(request.end_user, "anna@example.com");
    let shown = serde_json::to_value(&request).unwrap();
    assert_eq!(shown["resource"], "customers");
    assert!(shown.get("access").is_none());

    approvals
        .decide(
            request.id,
            Decision {
                approve: true,
                ttl_minutes: 10,
                note: None,
                decided_by: "analyst@example.com".to_owned(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(waiting.await.unwrap(), Outcome::Granted { .. }));

    assert_eq!(approvals.granted_tables(anna.id, &anna.user), ["customers"]);
    assert!(approvals.granted_tables(ben.id, &ben.user).is_empty());
    assert!(!approvals.has_grant(ben.id, &ben.user, &table("customers")));
    // A table grant is not a tool grant.
    assert!(!approvals.has_grant(anna.id, &anna.user, &tool("customers")));
    let grant = serde_json::to_value(&approvals.active_grants(anna.id, &anna.user)[0]).unwrap();
    assert_eq!(grant["table"], "customers");
    assert_eq!(grant["end_user"], "anna@example.com");
}
