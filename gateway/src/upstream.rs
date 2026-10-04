//! Where a chat request goes.
//!
//! The console's LLM connections (`llm_providers`, written only by admins) are
//! the routing table: a model that an enabled OpenAI or OpenAI-compatible
//! connection lists goes to that connection's base URL with its key from
//! Supabase Vault. Everything else goes to `UPSTREAM_URL`, as before. The
//! policy catalog never names a URL or a key, so editing it cannot redirect
//! traffic or a credential. Anthropic connections are not routed: this
//! gateway speaks the OpenAI chat API.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sqlx::PgPool;
use uuid::Uuid;

use crate::mock;

/// A connection edited on the Models page takes effect within this long.
const CACHE_TTL: Duration = Duration::from_secs(30);

/// Where an `openai` connection with no base URL goes.
const OPENAI_BASE: &str = "https://api.openai.com/v1";

/// One resolved destination for a chat completion.
#[derive(Clone, PartialEq, Eq)]
pub struct Upstream {
    /// The full `…/chat/completions` URL. Empty for the mock.
    pub endpoint: String,
    /// Sent as `Authorization: Bearer`. Never logged.
    pub key: Option<String>,
    /// For audit and logs: the connection's name, or `default`.
    pub name: String,
    /// The deterministic stand-in (`UPSTREAM_URL=mock`).
    pub mock: bool,
}

impl std::fmt::Debug for Upstream {
    // the key stays out of every log line
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("endpoint", &self.endpoint)
            .field("key", &self.key.as_ref().map(|_| "<set>"))
            .field("name", &self.name)
            .field("mock", &self.mock)
            .finish()
    }
}

/// The destination for models no connection claims: `UPSTREAM_URL`.
pub fn default_for(url: &str) -> Upstream {
    if url == mock::MOCK {
        return Upstream {
            endpoint: String::new(),
            key: None,
            name: mock::MOCK.to_owned(),
            mock: true,
        };
    }
    Upstream {
        endpoint: format!("{}/v1/chat/completions", url.trim_end_matches('/')),
        key: None,
        name: "default".to_owned(),
        mock: false,
    }
}

/// A connection's chat endpoint. Its base URL is an SDK base URL, version
/// included (`https://api.openai.com/v1`), as the console stores it. `None`
/// for a compatible connection without one: there is nowhere to send it.
pub fn connection_endpoint(kind: &str, base_url: Option<&str>) -> Option<String> {
    let base = match base_url.map(str::trim).filter(|base| !base.is_empty()) {
        Some(base) => base.trim_end_matches('/').to_owned(),
        None if kind == "openai" => OPENAI_BASE.to_owned(),
        None => return None,
    };
    Some(format!("{base}/chat/completions"))
}

type Cached = (Instant, Option<Upstream>);

pub struct Upstreams {
    default: Upstream,
    pool: PgPool,
    cache: Mutex<HashMap<String, Cached>>,
}

impl Upstreams {
    pub fn new(default_url: &str, pool: PgPool) -> Self {
        Self {
            default: default_for(default_url),
            pool,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Where `model` goes: the first enabled connection that lists it, or the
    /// default upstream.
    pub async fn resolve(&self, model: &str) -> Upstream {
        if let Ok(cache) = self.cache.lock()
            && let Some((at, hit)) = cache.get(model)
            && at.elapsed() < CACHE_TTL
        {
            return hit.clone().unwrap_or_else(|| self.default.clone());
        }
        match self.lookup(model).await {
            Ok(found) => {
                if let Ok(mut cache) = self.cache.lock() {
                    cache.insert(model.to_owned(), (Instant::now(), found.clone()));
                }
                found.unwrap_or_else(|| self.default.clone())
            }
            // not cached: the next request asks again
            Err(error) => {
                tracing::error!(%error, model, "reading LLM connections failed; using the default upstream");
                self.default.clone()
            }
        }
    }

    async fn lookup(&self, model: &str) -> sqlx::Result<Option<Upstream>> {
        let row = sqlx::query_as::<_, (Uuid, String, String, Option<String>, Option<String>)>(
            "select p.id, p.name, p.kind, p.base_url, s.decrypted_secret
             from public.llm_providers p
             left join vault.decrypted_secrets s on s.id = p.api_key_secret_id
             where p.enabled and p.kind in ('openai', 'compatible') and $1 = any(p.models)
             order by p.created_at
             limit 1",
        )
        .bind(model)
        .fetch_optional(&self.pool)
        .await?;
        let Some((id, name, kind, base_url, key)) = row else {
            return Ok(None);
        };
        let Some(endpoint) = connection_endpoint(&kind, base_url.as_deref()) else {
            tracing::warn!(connection = %id, "LLM connection has no base URL; not routing to it");
            return Ok(None);
        };
        Ok(Some(Upstream {
            endpoint,
            key: key.filter(|key| !key.trim().is_empty()),
            name,
            mock: false,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_upstream_keeps_its_old_shape() {
        let ollama = default_for("https://ollama.example.run.app/");
        assert_eq!(ollama.endpoint, "https://ollama.example.run.app/v1/chat/completions");
        assert_eq!(ollama.key, None);
        assert!(!ollama.mock);
        assert!(default_for("mock").mock);
    }

    #[test]
    fn a_connection_base_url_is_an_sdk_base() {
        assert_eq!(
            connection_endpoint("openai", Some("https://api.openai.com/v1")).as_deref(),
            Some("https://api.openai.com/v1/chat/completions")
        );
        assert_eq!(
            connection_endpoint("compatible", Some(" https://llm.example.com/v1/ ")).as_deref(),
            Some("https://llm.example.com/v1/chat/completions")
        );
        assert_eq!(
            connection_endpoint("openai", None).as_deref(),
            Some("https://api.openai.com/v1/chat/completions")
        );
        assert_eq!(connection_endpoint("openai", Some("  ")).as_deref(), Some("https://api.openai.com/v1/chat/completions"));
        assert_eq!(connection_endpoint("compatible", None), None);
    }

    #[test]
    fn debug_output_never_shows_the_key() {
        let upstream = Upstream {
            endpoint: "https://api.openai.com/v1/chat/completions".to_owned(),
            key: Some("sk-secret-value".to_owned()),
            name: "OpenAI".to_owned(),
            mock: false,
        };
        let shown = format!("{upstream:?}");
        assert!(!shown.contains("sk-secret"), "{shown}");
        assert!(shown.contains("<set>"));
    }
}
