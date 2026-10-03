//! Human-approved access requests.
//!
//! An agent missing a tool can ask for it through `control__request_access`.
//! The call blocks while the request is pushed to the SecOps console; a member
//! of the security team approves or denies it there, and the agent gets the
//! answer in the same tool call. An approval is a time-boxed grant that the
//! `tools/call` gate honours next to the principal's static `allowed_tools`.
//!
//! Pending requests live in memory — the blocked call and the decision must
//! meet in the same process — so the gateway runs as a single instance.
//! Postgres keeps the record (and the grants, across restarts).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sqlx::PgPool;
use tokio::sync::{broadcast, oneshot};
use uuid::Uuid;

use crate::audit::Principal;
use crate::mcp::federation;
use crate::policy::Policy;

/// Prefix of the tools the gateway serves itself. Never requestable, never
/// a federated server name.
pub const NATIVE_PREFIX: &str = "control__";
/// How long a requesting agent waits for a human before giving up.
pub const WAIT: Duration = Duration::from_secs(120);
pub const DEFAULT_TTL_MINUTES: u32 = 15;
pub const MAX_TTL_MINUTES: u32 = 60;
/// One open request per principal and tool, a handful per principal: an agent
/// must not be able to bury the approvers in popups.
pub const MAX_PENDING_PER_PRINCIPAL: usize = 5;

/// What the console is shown. Times are unix milliseconds.
#[derive(Debug, Clone, Serialize)]
pub struct AccessRequest {
    pub id: Uuid,
    pub principal_id: Uuid,
    pub principal: String,
    pub tool: String,
    /// The reason after the `tool_call` controls ran — possibly redacted.
    pub reason: String,
    pub ttl_minutes: u32,
    pub requested_at_ms: u64,
    pub deadline_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApprovalEvent {
    Request(AccessRequest),
    Decided {
        id: Uuid,
        approved: bool,
        decided_by: String,
    },
    Expired {
        id: Uuid,
    },
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub approve: bool,
    pub ttl_minutes: u32,
    pub note: Option<String>,
    pub decided_by: String,
}

/// What `control__request_access` hands back to the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    Granted { expires_at_ms: u64 },
    Denied { note: Option<String> },
    Expired,
    AlreadyPermitted,
    Refused { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Requestable,
    AlreadyPermitted,
    Refused(String),
}

#[derive(Debug, thiserror::Error)]
pub enum DecideError {
    #[error("request is not pending (already decided, expired or unknown)")]
    NotPending,
    #[error("the decision could not be recorded")]
    Unavailable,
}

#[derive(Debug, Clone, Serialize)]
pub struct Grant {
    pub tool: String,
    pub expires_at_ms: u64,
}

struct Pending {
    request: AccessRequest,
    tx: oneshot::Sender<Decision>,
}

pub struct Approvals {
    db: Option<PgPool>,
    pending: Mutex<HashMap<Uuid, Pending>>,
    /// principal -> active grants. The source of truth for enforcement; the
    /// database is the record and refills this on boot.
    grants: Mutex<HashMap<Uuid, Vec<Grant>>>,
    events: broadcast::Sender<ApprovalEvent>,
}

impl Approvals {
    pub fn new(db: Option<PgPool>) -> Self {
        let (events, _) = broadcast::channel(64);
        Self {
            db,
            pending: Mutex::new(HashMap::new()),
            grants: Mutex::new(HashMap::new()),
            events,
        }
    }

    /// A restart forgets every waiting agent, so their rows can never be
    /// decided. Mark them expired and reload the grants that are still live.
    pub async fn boot(&self) {
        let Some(pool) = &self.db else { return };
        if let Err(error) =
            sqlx::query("update access_requests set status = 'expired' where status = 'pending'")
                .execute(pool)
                .await
        {
            tracing::error!(%error, "could not expire stale access requests");
        }
        let rows = sqlx::query_as::<_, (Uuid, String, i64)>(
            "select principal_id, tool, (extract(epoch from expires_at) * 1000)::bigint
             from access_requests
             where status = 'approved' and expires_at > now()",
        )
        .fetch_all(pool)
        .await;
        match rows {
            Ok(rows) => {
                let mut grants = self.grants.lock().expect("grants lock");
                for (principal_id, tool, expires_at_ms) in rows {
                    grants.entry(principal_id).or_default().push(Grant {
                        tool,
                        expires_at_ms: u64::try_from(expires_at_ms).unwrap_or(0),
                    });
                }
            }
            Err(error) => tracing::error!(%error, "could not reload access grants"),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ApprovalEvent> {
        self.events.subscribe()
    }

    /// Requests still waiting — replayed to a console that (re)connects.
    pub fn snapshot(&self) -> Vec<AccessRequest> {
        let pending = self.pending.lock().expect("pending lock");
        let mut list: Vec<_> = pending.values().map(|p| p.request.clone()).collect();
        list.sort_by_key(|r| r.requested_at_ms);
        list
    }

    pub fn active_grants(&self, principal_id: Uuid) -> Vec<Grant> {
        let now = now_ms();
        let mut grants = self.grants.lock().expect("grants lock");
        let list = grants.entry(principal_id).or_default();
        list.retain(|g| g.expires_at_ms > now);
        list.clone()
    }

    pub fn has_grant(&self, principal_id: Uuid, tool: &str) -> bool {
        self.active_grants(principal_id)
            .iter()
            .any(|g| g.tool == tool)
    }

    /// Block until a human decides, the wait runs out, or the caller goes
    /// away. `reason` must already have been through the controls.
    pub async fn request(
        &self,
        principal: &Principal,
        tool: &str,
        reason: &str,
        ttl_minutes: u32,
    ) -> Outcome {
        let now = now_ms();
        let request = AccessRequest {
            id: Uuid::new_v4(),
            principal_id: principal.id,
            principal: principal.slug.clone(),
            tool: tool.to_owned(),
            reason: reason.to_owned(),
            ttl_minutes,
            requested_at_ms: now,
            deadline_ms: now + u64::try_from(WAIT.as_millis()).unwrap_or(u64::MAX),
        };

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().expect("pending lock");
            let open = pending
                .values()
                .map(|p| (p.request.principal_id, p.request.tool.as_str()));
            if let Err(message) = admit(open, principal.id, tool) {
                return Outcome::Refused { message };
            }
            pending.insert(
                request.id,
                Pending {
                    request: request.clone(),
                    tx,
                },
            );
        }
        // From here on the guard owns cleanup, whichever way this ends.
        let guard = PendingGuard {
            approvals: self,
            id: request.id,
        };

        if let Some(pool) = &self.db {
            let inserted = sqlx::query(
                "insert into access_requests (id, principal_id, tool, reason, ttl_minutes)
                 values ($1, $2, $3, $4, $5)",
            )
            .bind(request.id)
            .bind(request.principal_id)
            .bind(&request.tool)
            .bind(&request.reason)
            .bind(i32::try_from(ttl_minutes).unwrap_or(DEFAULT_TTL_MINUTES as i32))
            .execute(pool)
            .await;
            if let Err(error) = inserted {
                // An approval nobody can audit is not an approval.
                tracing::error!(%error, "could not record access request");
                self.pending
                    .lock()
                    .expect("pending lock")
                    .remove(&request.id);
                return Outcome::Refused {
                    message: "approvals are unavailable right now".to_owned(),
                };
            }
        }

        let _ = self.events.send(ApprovalEvent::Request(request));

        match tokio::time::timeout(WAIT, rx).await {
            Ok(Ok(decision)) if decision.approve => Outcome::Granted {
                expires_at_ms: now_ms() + u64::from(decision.ttl_minutes) * 60_000,
            },
            Ok(Ok(decision)) => Outcome::Denied {
                note: decision.note,
            },
            // Timed out, or the sender was dropped without a decision. The
            // guard below marks the row expired and tells the console.
            Ok(Err(_)) | Err(_) => {
                drop(guard);
                Outcome::Expired
            }
        }
    }

    pub async fn decide(&self, id: Uuid, decision: Decision) -> Result<(), DecideError> {
        let Some(entry) = self.pending.lock().expect("pending lock").remove(&id) else {
            return Err(DecideError::NotPending);
        };
        let ttl = clamp_ttl(Some(decision.ttl_minutes));
        let decision = Decision {
            ttl_minutes: ttl,
            ..decision
        };

        if let Some(pool) = &self.db {
            let status = if decision.approve {
                "approved"
            } else {
                "denied"
            };
            let updated = sqlx::query(
                "update access_requests
                 set status = $2::access_status, decided_at = now(), decided_by = $3, note = $4,
                     ttl_minutes = $5,
                     expires_at = case when $2 = 'approved'
                                       then now() + make_interval(mins => $5) end
                 where id = $1 and status = 'pending'",
            )
            .bind(id)
            .bind(status)
            .bind(&decision.decided_by)
            .bind(&decision.note)
            .bind(i32::try_from(ttl).unwrap_or(DEFAULT_TTL_MINUTES as i32))
            .execute(pool)
            .await;
            if let Err(error) = updated {
                tracing::error!(%error, "could not record access decision");
                // Fail closed: the agent hears "denied", the console hears why.
                let _ = entry.tx.send(Decision {
                    approve: false,
                    note: Some("the decision could not be recorded".to_owned()),
                    ..decision
                });
                let _ = self.events.send(ApprovalEvent::Expired { id });
                return Err(DecideError::Unavailable);
            }
        }

        if decision.approve {
            self.grants
                .lock()
                .expect("grants lock")
                .entry(entry.request.principal_id)
                .or_default()
                .push(Grant {
                    tool: entry.request.tool.clone(),
                    expires_at_ms: now_ms() + u64::from(ttl) * 60_000,
                });
        }

        let _ = self.events.send(ApprovalEvent::Decided {
            id,
            approved: decision.approve,
            decided_by: decision.decided_by.clone(),
        });
        // The agent may have hung up in the meantime; the grant stands anyway.
        let _ = entry.tx.send(decision);
        Ok(())
    }
}

/// Removes a request that ended without a decision: timed out, or the agent's
/// connection dropped and took the waiting future with it.
struct PendingGuard<'a> {
    approvals: &'a Approvals,
    id: Uuid,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        let removed = self
            .approvals
            .pending
            .lock()
            .map(|mut pending| pending.remove(&self.id))
            .ok()
            .flatten();
        if removed.is_none() {
            return; // decided
        }
        let _ = self
            .approvals
            .events
            .send(ApprovalEvent::Expired { id: self.id });
        if let (Some(pool), Ok(runtime)) = (
            self.approvals.db.clone(),
            tokio::runtime::Handle::try_current(),
        ) {
            let id = self.id;
            runtime.spawn(async move {
                let result = sqlx::query(
                    "update access_requests set status = 'expired'
                     where id = $1 and status = 'pending'",
                )
                .bind(id)
                .execute(&pool)
                .await;
                if let Err(error) = result {
                    tracing::error!(%error, "could not expire an access request");
                }
            });
        }
    }
}

pub fn clamp_ttl(requested: Option<u32>) -> u32 {
    requested
        .unwrap_or(DEFAULT_TTL_MINUTES)
        .clamp(1, MAX_TTL_MINUTES)
}

/// Rate limit over the currently open `(principal, tool)` pairs.
pub fn admit<'a>(
    open: impl Iterator<Item = (Uuid, &'a str)>,
    principal_id: Uuid,
    tool: &str,
) -> Result<(), String> {
    let mut mine = 0;
    for (owner, open_tool) in open {
        if owner != principal_id {
            continue;
        }
        if open_tool == tool {
            return Err(format!("a request for {tool} is already waiting"));
        }
        mine += 1;
    }
    if mine >= MAX_PENDING_PER_PRINCIPAL {
        return Err(format!(
            "{mine} requests are already waiting; wait for a decision"
        ));
    }
    Ok(())
}

/// Is `tool` something this principal can meaningfully ask for?
pub fn validate_target(
    policy: &Policy,
    principal: &Principal,
    has_grant: bool,
    tool: &str,
) -> Target {
    if tool.starts_with(NATIVE_PREFIX) {
        return Target::Refused(format!("{tool} is a gateway tool and always available"));
    }
    let Some((server, _)) = federation::split(tool) else {
        return Target::Refused(format!(
            "{tool} is not a federated tool name (expected server__tool)"
        ));
    };
    if policy.mcp.server(server).is_none() {
        return Target::Refused(format!("no enabled server named {server}"));
    }
    if principal.allowed_tools.is_empty()
        || principal.allowed_tools.iter().any(|t| t == tool)
        || has_grant
    {
        return Target::AlreadyPermitted;
    }
    Target::Requestable
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests;
