//! Who may call the admin API: a signed-in console user of the security team.
//!
//! The console authenticates with Supabase Auth, so the gateway accepts that
//! session's access token rather than a second credential. Supabase Auth
//! verifies the token (`GET /auth/v1/user`), and the user's `team_members.role`
//! decides what they may do. No secret is shared with the browser.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::audit::sha256_hex;

/// A verified token is trusted this long before Supabase is asked again. A
/// revoked session or changed role takes effect within this window.
const CACHE_TTL: Duration = Duration::from_secs(60);

/// What a console role may do here. `developer` and users without a team row
/// have no access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Access {
    Read,
    Write,
}

#[derive(Debug, Clone)]
pub struct Admin {
    pub user_id: Uuid,
    pub email: Option<String>,
    pub role: String,
}

impl Admin {
    pub fn access(&self) -> Option<Access> {
        access_for(&self.role)
    }
}

/// `viewer` and `analyst` read; only `admin` changes gateway state.
pub fn access_for(role: &str) -> Option<Access> {
    match role {
        "admin" => Some(Access::Write),
        "analyst" | "viewer" => Some(Access::Read),
        _ => None,
    }
}

pub struct AdminAuth {
    http: reqwest::Client,
    /// `None` when SUPABASE_URL or SUPABASE_PUBLISHABLE_KEY is unset: the admin
    /// API then refuses every call rather than trusting anyone.
    supabase: Option<(String, String)>,
    cache: Mutex<HashMap<String, (Instant, Admin)>>,
}

#[derive(Deserialize)]
struct SupabaseUser {
    id: Uuid,
    email: Option<String>,
}

impl AdminAuth {
    pub fn from_env(http: reqwest::Client) -> Self {
        let url = std::env::var("SUPABASE_URL").ok().filter(|v| !v.is_empty());
        let key = std::env::var("SUPABASE_PUBLISHABLE_KEY")
            .ok()
            .filter(|v| !v.is_empty());
        Self {
            http,
            supabase: url
                .zip(key)
                .map(|(url, key)| (url.trim_end_matches('/').to_owned(), key)),
            cache: Mutex::default(),
        }
    }

    pub fn configured(&self) -> bool {
        self.supabase.is_some()
    }

    /// Authenticate the caller and require `needed`. The error is the
    /// response to return as-is.
    pub async fn require(
        &self,
        pool: &PgPool,
        headers: &HeaderMap,
        needed: Access,
    ) -> Result<Admin, Response> {
        let admin = self.authenticate(pool, headers).await?;
        match admin.access() {
            Some(access) if access >= needed => Ok(admin),
            _ => Err(refusal(
                StatusCode::FORBIDDEN,
                "admin_required",
                match needed {
                    Access::Read => "a security team role is required",
                    Access::Write => "the security team admin role is required",
                },
            )),
        }
    }

    async fn authenticate(&self, pool: &PgPool, headers: &HeaderMap) -> Result<Admin, Response> {
        let Some((url, key)) = &self.supabase else {
            return Err(refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "admin_auth_unconfigured",
                "SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY are not set on the gateway",
            ));
        };
        let Some(token) = bearer(headers) else {
            return Err(refusal(
                StatusCode::UNAUTHORIZED,
                "authentication_required",
                "missing or malformed Bearer access token",
            ));
        };

        let digest = sha256_hex(token.as_bytes());
        if let Ok(cache) = self.cache.lock()
            && let Some((at, admin)) = cache.get(&digest)
            && at.elapsed() < CACHE_TTL
        {
            return Ok(admin.clone());
        }

        let response = self
            .http
            .get(format!("{url}/auth/v1/user"))
            .bearer_auth(token)
            .header("apikey", key)
            .send()
            .await
            .map_err(|error| {
                tracing::error!(%error, "Supabase Auth unreachable");
                refusal(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "admin_auth_unavailable",
                    "the identity provider is unreachable",
                )
            })?;
        if !response.status().is_success() {
            return Err(refusal(
                StatusCode::UNAUTHORIZED,
                "authentication_required",
                "invalid or expired access token",
            ));
        }
        let user: SupabaseUser = response.json().await.map_err(|_| {
            refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "admin_auth_unavailable",
                "the identity provider returned an unexpected response",
            )
        })?;

        let role = sqlx::query_scalar::<_, String>(
            "select role::text from team_members where user_id = $1",
        )
        .bind(user.id)
        .fetch_optional(pool)
        .await
        .map_err(|error| {
            tracing::error!(%error, "team role lookup failed");
            refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "admin_auth_unavailable",
                "could not read the team role",
            )
        })?
        .unwrap_or_default();

        let admin = Admin {
            user_id: user.id,
            email: user.email,
            role,
        };
        if let Ok(mut cache) = self.cache.lock() {
            cache.retain(|_, (at, _)| at.elapsed() < CACHE_TTL);
            cache.insert(digest, (Instant::now(), admin.clone()));
        }
        Ok(admin)
    }
}

pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
}

pub fn refusal(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({ "error": { "type": code, "message": message } })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_admins_write_and_only_the_security_team_reads() {
        assert_eq!(access_for("admin"), Some(Access::Write));
        assert_eq!(access_for("analyst"), Some(Access::Read));
        assert_eq!(access_for("viewer"), Some(Access::Read));
        assert_eq!(access_for("developer"), None);
        assert_eq!(access_for(""), None);
        assert!(Access::Write >= Access::Read);
        assert!(Access::Read < Access::Write);
    }
}
