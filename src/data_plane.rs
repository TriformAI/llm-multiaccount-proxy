use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use thiserror::Error;
use tokio::sync::Mutex;
use url::Url;
use zeroize::Zeroizing;

use crate::auth::{Authenticator, CredentialSnapshot};
use crate::providers::ProviderAccount;
use crate::routing::Router;
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
        unimplemented!("RED: authenticated streaming reverse data plane")
    }
}

pub struct ReqwestTransport;

#[async_trait]
impl UpstreamTransport for ReqwestTransport {
    async fn send(&self, _request: UpstreamRequest) -> Result<UpstreamResponse, TransportError> {
        unimplemented!("RED: reqwest upstream transport")
    }
}
