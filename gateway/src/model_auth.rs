//! Credentials for the model host.
//!
//! Locally the model host is an Ollama on localhost and takes no credentials.
//! On Cloud Run it is a private service (`ollama/cloudbuild.yaml`): every call
//! needs a Google identity token whose audience is that service's URL. The
//! gateway's own service account mints one from the metadata server.
//!
//! `MODEL_AUTH=google` turns this on. Anything else sends requests unchanged.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

const METADATA_IDENTITY: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity";

/// Identity tokens live an hour. Refreshing well before that means a request
/// never leaves with a token that expires in flight.
const REFRESH_AFTER: Duration = Duration::from_secs(45 * 60);

#[derive(Clone)]
pub struct ModelAuth {
    http: reqwest::Client,
    google: bool,
    cache: Arc<Mutex<HashMap<String, (String, Instant)>>>,
}

impl ModelAuth {
    pub fn from_env(http: reqwest::Client) -> Self {
        let google = std::env::var("MODEL_AUTH").is_ok_and(|v| v == "google");
        if google {
            tracing::info!("model host auth: Google identity tokens");
        }
        Self {
            http,
            google,
            cache: Arc::default(),
        }
    }

    /// No credentials, for tests and local work.
    pub fn none(http: reqwest::Client) -> Self {
        Self {
            http,
            google: false,
            cache: Arc::default(),
        }
    }

    /// Attach whatever `url` needs. A token that cannot be minted is logged
    /// and the request goes out bare: the model host refuses it, and the
    /// caller's failure handling (fail_mode, 502) takes over from there.
    pub async fn apply(
        &self,
        request: reqwest::RequestBuilder,
        url: &str,
    ) -> reqwest::RequestBuilder {
        if !self.google {
            return request;
        }
        match self.token(audience(url)).await {
            Ok(token) => request.bearer_auth(token),
            Err(error) => {
                tracing::error!(%error, "could not mint an identity token for the model host");
                request
            }
        }
    }

    async fn token(&self, audience: &str) -> Result<String, reqwest::Error> {
        let mut cache = self.cache.lock().await;
        if let Some((token, minted)) = cache.get(audience)
            && minted.elapsed() < REFRESH_AFTER
        {
            return Ok(token.clone());
        }
        let token = self
            .http
            // An audience is scheme and host only, nothing that needs escaping.
            .get(format!("{METADATA_IDENTITY}?audience={audience}"))
            .header("Metadata-Flavor", "Google")
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        cache.insert(audience.to_owned(), (token.clone(), Instant::now()));
        Ok(token)
    }
}

/// Cloud Run checks the audience against the service URL: scheme and host,
/// no path.
fn audience(url: &str) -> &str {
    let after_scheme = url.find("://").map_or(0, |i| i + 3);
    url[after_scheme..]
        .find('/')
        .map_or(url, |i| &url[..after_scheme + i])
}

#[cfg(test)]
mod tests {
    use super::audience;

    #[test]
    fn audience_is_scheme_and_host() {
        assert_eq!(
            audience("https://ollama-1.europe-west1.run.app/api/generate"),
            "https://ollama-1.europe-west1.run.app"
        );
        assert_eq!(
            audience("https://ollama-1.europe-west1.run.app"),
            "https://ollama-1.europe-west1.run.app"
        );
        assert_eq!(
            audience("http://localhost:11434/v1/chat/completions"),
            "http://localhost:11434"
        );
    }
}
