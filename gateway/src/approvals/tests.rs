use std::sync::Arc;

use super::*;

fn principal(allowed_tools: &[&str]) -> Principal {
    Principal {
        id: Uuid::new_v4(),
        slug: "red-team".to_owned(),
        role: "member".to_owned(),
        allowed_models: Vec::new(),
        allowed_tools: allowed_tools.iter().map(|t| (*t).to_owned()).collect(),
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

#[test]
fn one_open_request_per_tool() {
    let me = Uuid::new_v4();
    let open = [(me, "docs__read")];
    assert!(admit(open.iter().copied(), me, "docs__read").is_err());
    assert!(admit(open.iter().copied(), me, "docs__search").is_ok());
    // Someone else's open request does not count against me.
    assert!(admit(open.iter().copied(), Uuid::new_v4(), "docs__read").is_ok());
}

#[test]
fn a_principal_cannot_flood_the_approvers() {
    let me = Uuid::new_v4();
    let tools: Vec<String> = (0..MAX_PENDING_PER_PRINCIPAL)
        .map(|i| format!("docs__t{i}"))
        .collect();
    let open: Vec<_> = tools.iter().map(|t| (me, t.as_str())).collect();
    assert!(admit(open.iter().copied(), me, "docs__other").is_err());
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
                .request(&agent, "docs__read", "need the Q3 summary", 15)
                .await
        })
    };

    let ApprovalEvent::Request(request) = console.recv().await.unwrap() else {
        panic!("the console must be told about the request first");
    };
    assert_eq!(request.tool, "docs__read");
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
    assert!(approvals.has_grant(agent.id, "docs__read"));
    assert!(!approvals.has_grant(agent.id, "docs__search"));
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
        tokio::spawn(async move { approvals.request(&agent, "docs__read", "x", 15).await })
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
