use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use bytes::Bytes;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures_util::TryStreamExt;
use parking_lot::Mutex as ParkingMutex;
use reqwest::redirect::Policy;
use thiserror::Error;
use tokio::sync::Mutex;
use url::Url;
use zeroize::Zeroizing;

use crate::auth::{AuthError, Authenticator, CredentialSnapshot};
use crate::egress::{DestinationPolicy, ProxyChain, ProxyEndpoint};
use crate::providers::{ProviderAccount, prepare_request};
use crate::routing::{RouteRequest, Router, UpstreamOutcome};
use crate::secrets::SecretInput;

#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("account repository is unavailable")]
    Unavailable,
    #[error("account does not exist")]
    NotFound,
    #[error("account repository contains invalid data")]
    InvalidData,
}

#[async_trait]
pub trait AccountRepository: Send + Sync {
    async fn credential_snapshot(
        &self,
        authenticator: &Authenticator,
        now: DateTime<Utc>,
    ) -> Result<CredentialSnapshot, RepositoryError>;

    async fn load_account(
        &self,
        account_id: &str,
    ) -> Result<(ProviderAccount, SecretInput), RepositoryError>;
}

pub struct UpstreamRequest {
    pub account_id: String,
    pub method: Method,
    pub url: Url,
    pub body: Bytes,
    pub egress_proxies: Vec<String>,
    headers: BTreeMap<String, Zeroizing<String>>,
}

impl UpstreamRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(|value| value.as_str())
    }
}

impl fmt::Debug for UpstreamRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpstreamRequest")
            .field("account_id", &self.account_id)
            .field("method", &self.method)
            .field("url", &self.url)
            .field("body_bytes", &self.body.len())
            .field("egress_proxies", &self.egress_proxies.len())
            .field("headers", &"[REDACTED]")
            .finish()
    }
}

pub struct UpstreamResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Body,
}

#[derive(Debug, Error)]
#[error("upstream transport failed before a response was available")]
pub struct TransportError;

#[async_trait]
pub trait UpstreamTransport: Send + Sync {
    async fn send(&self, request: UpstreamRequest) -> Result<UpstreamResponse, TransportError>;
}

pub struct ProxyRequest {
    pub method: Method,
    pub path_and_query: String,
    pub session_from_path: Option<String>,
    pub headers: HeaderMap,
    pub body: Bytes,
}

pub struct ProxyResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Body,
}

impl fmt::Debug for ProxyResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyResponse")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("body", &"[STREAM]")
            .finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DataPlaneError {
    #[error("client authentication failed")]
    Unauthorized,
    #[error("credential state is unavailable")]
    CredentialStoreUnavailable,
    #[error("request is invalid: {0}")]
    BadRequest(String),
    #[error("no eligible account is available")]
    NoCapacity,
    #[error("upstream request failed")]
    UpstreamUnavailable,
}

impl DataPlaneError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::CredentialStoreUnavailable | Self::NoCapacity => StatusCode::SERVICE_UNAVAILABLE,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::UpstreamUnavailable => StatusCode::BAD_GATEWAY,
        }
    }
}

pub struct DataPlane {
    pub(crate) auth_mode: crate::auth::AuthMode,
    pub(crate) authenticator: Authenticator,
    pub(crate) repository: Arc<dyn AccountRepository>,
    pub(crate) router: Mutex<Router>,
    pub(crate) transport: Arc<dyn UpstreamTransport>,
    pub(crate) max_request_bytes: usize,
}

impl DataPlane {
    pub fn new(
        auth_mode: crate::auth::AuthMode,
        authenticator: Authenticator,
        repository: Arc<dyn AccountRepository>,
        router: Router,
        transport: Arc<dyn UpstreamTransport>,
        max_request_bytes: usize,
    ) -> Self {
        Self {
            auth_mode,
            authenticator,
            repository,
            router: Mutex::new(router),
            transport,
            max_request_bytes,
        }
    }

    pub async fn handle(&self, _request: ProxyRequest) -> Result<ProxyResponse, DataPlaneError> {
        let request = _request;
        if request.body.len() > self.max_request_bytes {
            return Err(DataPlaneError::BadRequest(format!(
                "request body exceeds the {} byte limit",
                self.max_request_bytes
            )));
        }

        let presented_token = presented_token(&request.headers)?;
        let now = Utc::now();
        let snapshot = self
            .repository
            .credential_snapshot(&self.authenticator, now)
            .await
            .map_err(|_| DataPlaneError::CredentialStoreUnavailable)?;
        self.authenticator
            .authorize(self.auth_mode, presented_token.as_deref(), &snapshot, now)
            .map_err(|error| match error {
                AuthError::Unauthorized => DataPlaneError::Unauthorized,
                AuthError::CredentialStoreUnavailable => DataPlaneError::CredentialStoreUnavailable,
            })?;

        let session_id = session_id(&request)?;
        let mut json = if request.body.is_empty() {
            None
        } else {
            serde_json::from_slice::<serde_json::Value>(&request.body).ok()
        };
        let requested_model = json
            .as_ref()
            .and_then(|value| value.get("model"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if request.path_and_query.starts_with("/v1/messages") && requested_model.is_empty() {
            return Err(DataPlaneError::BadRequest(
                "messages requests require a JSON model field".into(),
            ));
        }

        let selection = self
            .router
            .lock()
            .await
            .choose(
                &RouteRequest {
                    session_id,
                    model: requested_model.clone(),
                },
                now,
            )
            .map_err(|_| DataPlaneError::NoCapacity)?;
        let (account, credential) = self
            .repository
            .load_account(&selection.account_id)
            .await
            .map_err(|error| match error {
                RepositoryError::Unavailable => DataPlaneError::CredentialStoreUnavailable,
                RepositoryError::NotFound | RepositoryError::InvalidData => {
                    DataPlaneError::NoCapacity
                }
            })?;
        let prepared = prepare_request(
            &account,
            &credential,
            &request.path_and_query,
            &requested_model,
        )
        .map_err(|_| DataPlaneError::UpstreamUnavailable)?;
        let (url, upstream_model, mut headers) = prepared.into_parts();
        copy_safe_request_headers(&request.headers, &mut headers)?;
        let body = if let Some(value) = json.as_mut() {
            if let Some(model) = value.get_mut("model") {
                *model = serde_json::Value::String(upstream_model);
            }
            Bytes::from(
                serde_json::to_vec(value)
                    .map_err(|_| DataPlaneError::BadRequest("invalid JSON body".into()))?,
            )
        } else {
            request.body
        };

        let upstream = self
            .transport
            .send(UpstreamRequest {
                account_id: account.id.clone(),
                method: request.method,
                url,
                body,
                egress_proxies: account.egress_proxies,
                headers,
            })
            .await
            .map_err(|_| DataPlaneError::UpstreamUnavailable)?;

        let outcome = classify_status(upstream.status, &upstream.headers, now);
        self.router
            .lock()
            .await
            .record_outcome(&account.id, outcome)
            .map_err(|_| DataPlaneError::NoCapacity)?;

        Ok(ProxyResponse {
            status: upstream.status,
            headers: safe_response_headers(&upstream.headers),
            body: upstream.body,
        })
    }

    pub async fn replace_route_accounts(&self, accounts: Vec<crate::routing::RouteAccount>) {
        self.router.lock().await.replace_accounts(accounts);
    }
}

pub struct ReqwestTransport {
    destination_policy: DestinationPolicy,
    proxy_chains: ParkingMutex<HashMap<String, AccountProxyChain>>,
}

struct AccountProxyChain {
    sources: Vec<String>,
    chain: ProxyChain,
}

impl ReqwestTransport {
    pub fn new(destination_policy: DestinationPolicy) -> Self {
        Self {
            destination_policy,
            proxy_chains: ParkingMutex::new(HashMap::new()),
        }
    }

    fn selected_proxy(
        &self,
        account_id: &str,
        sources: &[String],
    ) -> Result<Option<ProxyEndpoint>, TransportError> {
        if sources.is_empty() {
            self.proxy_chains.lock().remove(account_id);
            return Ok(None);
        }
        let mut chains = self.proxy_chains.lock();
        let needs_rebuild = chains
            .get(account_id)
            .is_none_or(|existing| existing.sources != sources);
        if needs_rebuild {
            let endpoints = sources
                .iter()
                .map(|source| ProxyEndpoint::parse(source))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| TransportError)?;
            chains.insert(
                account_id.to_owned(),
                AccountProxyChain {
                    sources: sources.to_vec(),
                    chain: ProxyChain::new(endpoints).map_err(|_| TransportError)?,
                },
            );
        }
        Ok(chains
            .get(account_id)
            .map(|state| state.chain.active().clone()))
    }

    fn record_transport_result(&self, account_id: &str, success: bool) {
        if let Some(state) = self.proxy_chains.lock().get_mut(account_id) {
            if success {
                state.chain.record_success();
            } else {
                state.chain.record_failure();
            }
        }
    }
}

#[async_trait]
impl UpstreamTransport for ReqwestTransport {
    async fn send(&self, request: UpstreamRequest) -> Result<UpstreamResponse, TransportError> {
        self.destination_policy
            .authorize(&request.url)
            .map_err(|_| TransportError)?;
        let selected_proxy = self.selected_proxy(&request.account_id, &request.egress_proxies)?;
        let mut client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(15))
            .http2_adaptive_window(true)
            .redirect(Policy::none());
        if let Some(endpoint) = selected_proxy {
            client = client.proxy(
                reqwest::Proxy::all(endpoint.as_url().as_str()).map_err(|_| TransportError)?,
            );
        }
        let client = match client.build() {
            Ok(client) => client,
            Err(_) => {
                self.record_transport_result(&request.account_id, false);
                return Err(TransportError);
            }
        };
        let mut outbound = client
            .request(request.method, request.url)
            .body(request.body);
        for (name, value) in request.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| TransportError)?;
            let value = HeaderValue::from_str(value.as_str()).map_err(|_| TransportError)?;
            outbound = outbound.header(name, value);
        }
        let response = match outbound.send().await {
            Ok(response) => response,
            Err(_) => {
                self.record_transport_result(&request.account_id, false);
                return Err(TransportError);
            }
        };
        self.record_transport_result(&request.account_id, true);
        let status = response.status();
        let headers = response.headers().clone();
        let body = Body::from_stream(response.bytes_stream().map_err(std::io::Error::other));
        Ok(UpstreamResponse {
            status,
            headers,
            body,
        })
    }
}

fn presented_token(headers: &HeaderMap) -> Result<Option<String>, DataPlaneError> {
    let api_key = headers
        .get("x-api-key")
        .map(|value| value.to_str().map(str::trim))
        .transpose()
        .map_err(|_| DataPlaneError::Unauthorized)?
        .filter(|value| !value.is_empty());
    let bearer = headers
        .get("authorization")
        .map(|value| value.to_str())
        .transpose()
        .map_err(|_| DataPlaneError::Unauthorized)?
        .and_then(|value| {
            let (scheme, token) = value.split_once(' ')?;
            (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty())
                .then(|| token.trim())
        });
    if let (Some(api_key), Some(bearer)) = (api_key, bearer) {
        if api_key != bearer {
            return Err(DataPlaneError::Unauthorized);
        }
    }
    Ok(api_key.or(bearer).map(str::to_owned))
}

fn session_id(request: &ProxyRequest) -> Result<Option<String>, DataPlaneError> {
    let header = request
        .headers
        .get("x-llmap-session")
        .map(|value| value.to_str())
        .transpose()
        .map_err(|_| DataPlaneError::BadRequest("invalid session header".into()))?
        .map(str::to_owned);
    if let (Some(path), Some(header)) = (&request.session_from_path, &header) {
        if path != header {
            return Err(DataPlaneError::BadRequest(
                "path and header session identifiers disagree".into(),
            ));
        }
    }
    let value = request.session_from_path.clone().or(header);
    if let Some(value) = &value {
        let valid = !value.is_empty()
            && value.len() <= 256
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte));
        if !valid {
            return Err(DataPlaneError::BadRequest(
                "session identifiers must be 1-256 URL-safe characters".into(),
            ));
        }
    }
    Ok(value)
}

fn copy_safe_request_headers(
    incoming: &HeaderMap,
    outgoing: &mut BTreeMap<String, Zeroizing<String>>,
) -> Result<(), DataPlaneError> {
    for (name, value) in incoming {
        let name = name.as_str();
        let allowed = matches!(
            name,
            "accept" | "content-type" | "anthropic-version" | "anthropic-beta" | "user-agent"
        ) || name.starts_with("x-stainless-");
        if allowed {
            let value = value.to_str().map_err(|_| {
                DataPlaneError::BadRequest(format!("header {name} is not valid text"))
            })?;
            outgoing.insert(name.to_owned(), Zeroizing::new(value.to_owned()));
        }
    }
    Ok(())
}

fn safe_response_headers(incoming: &HeaderMap) -> HeaderMap {
    let mut outgoing = HeaderMap::new();
    for (name, value) in incoming {
        let name_text = name.as_str();
        let allowed = matches!(
            name_text,
            "content-type"
                | "content-length"
                | "cache-control"
                | "retry-after"
                | "request-id"
                | "x-request-id"
        ) || name_text.starts_with("anthropic-ratelimit-");
        if allowed {
            outgoing.append(name.clone(), value.clone());
        }
    }
    outgoing
}

fn classify_status(status: StatusCode, headers: &HeaderMap, now: DateTime<Utc>) -> UpstreamOutcome {
    match status.as_u16() {
        401 | 403 => UpstreamOutcome::Unauthorized,
        429 => UpstreamOutcome::RateLimited {
            retry_at: now + retry_after(headers, 60),
        },
        529 => UpstreamOutcome::Overloaded {
            retry_at: now + retry_after(headers, 30),
        },
        500..=599 => UpstreamOutcome::TransientFailure,
        _ => UpstreamOutcome::Success,
    }
}

fn retry_after(headers: &HeaderMap, fallback_seconds: i64) -> ChronoDuration {
    let seconds = headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|seconds| (1..=3600).contains(seconds))
        .unwrap_or(fallback_seconds);
    ChronoDuration::seconds(seconds)
}

#[cfg(test)]
mod transport_tests {
    use super::*;

    #[test]
    fn configured_proxy_failover_changes_only_subsequent_requests() {
        let transport = ReqwestTransport::new(DestinationPolicy::new(
            vec!["api.anthropic.com".into()],
            false,
        ));
        let sources = vec![
            "socks5h://fake-user:fake-pass@res-a.invalid:1080".into(),
            "https://res-b.invalid:8443".into(),
        ];

        assert_eq!(
            transport
                .selected_proxy("account-a", &sources)
                .unwrap()
                .unwrap()
                .redacted_authority(),
            "socks5h://res-a.invalid:1080"
        );
        for _ in 0..3 {
            transport.record_transport_result("account-a", false);
        }
        assert_eq!(
            transport
                .selected_proxy("account-a", &sources)
                .unwrap()
                .unwrap()
                .redacted_authority(),
            "https://res-b.invalid:8443"
        );
    }
}
