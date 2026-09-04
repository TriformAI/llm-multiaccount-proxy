use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::BodyExt;
use llmap::auth::{AccountCredential, AuthMode, Authenticator, CredentialSnapshot};
use llmap::data_plane::{
    AccountRepository, DataPlane, DataPlaneError, ProxyRequest, RepositoryError, TransportError,
    UpstreamRequest, UpstreamResponse, UpstreamTransport,
};
use llmap::providers::{ProviderAccount, ProviderKind};
use llmap::routing::{RouteAccount, Router};
use llmap::secrets::SecretInput;
use parking_lot::Mutex;
use url::Url;

struct FakeRepository {
    accounts: HashMap<String, (ProviderAccount, String)>,
    unavailable: bool,
}

#[async_trait]
impl AccountRepository for FakeRepository {
    async fn credential_snapshot(
        &self,
        authenticator: &Authenticator,
        _now: DateTime<Utc>,
    ) -> Result<CredentialSnapshot, RepositoryError> {
        if self.unavailable {
            return Err(RepositoryError::Unavailable);
        }
        Ok(CredentialSnapshot::Available(
            self.accounts
                .values()
                .map(|(account, token)| {
                    let credential =
                        AccountCredential::active(authenticator, &account.id, token.as_str());
                    if account.enabled {
                        credential
                    } else {
                        credential.paused()
                    }
                })
                .collect(),
        ))
    }

    async fn load_account(
        &self,
        account_id: &str,
    ) -> Result<(ProviderAccount, SecretInput), RepositoryError> {
        self.accounts
            .get(account_id)
            .map(|(account, secret)| (account.clone(), SecretInput::new(secret.clone())))
            .ok_or(RepositoryError::NotFound)
    }
}

struct RecordingTransport {
    requests: Mutex<Vec<UpstreamRequest>>,
    status: StatusCode,
}

#[async_trait]
impl UpstreamTransport for RecordingTransport {
    async fn send(&self, request: UpstreamRequest) -> Result<UpstreamResponse, TransportError> {
        self.requests.lock().push(request);
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("text/event-stream"),
        );
        headers.insert("x-request-id", HeaderValue::from_static("req_fake_123"));
        headers.insert("set-cookie", HeaderValue::from_static("must-not-escape=1"));
        Ok(UpstreamResponse {
            status: self.status,
            headers,
            body: Body::from("event: message_stop\ndata: {}\n\n"),
        })
    }
}

fn provider(id: &str, token_kind: ProviderKind, mapped_model: &str) -> ProviderAccount {
    ProviderAccount {
        id: id.into(),
        label: id.into(),
        kind: token_kind,
        base_url: Url::parse("https://api.anthropic.com/").unwrap(),
        enabled: true,
        model_map: BTreeMap::from([("client-model".into(), mapped_model.into())]),
        egress_proxies: Vec::new(),
        compatible_auth_header: None,
        compatible_auth_prefix: None,
    }
}

fn route_account(id: &str, load: u16) -> RouteAccount {
    RouteAccount {
        id: id.into(),
        provider: "anthropic".into(),
        enabled: true,
        healthy: true,
        in_flight: 0,
        utilization_basis_points: load,
        models: HashSet::from(["client-model".into()]),
        depleted_until: None,
    }
}

fn request(token: &str, session: &str) -> ProxyRequest {
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_str(token).unwrap());
    headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
    headers.insert("connection", HeaderValue::from_static("keep-alive"));
    ProxyRequest {
        method: Method::POST,
        path_and_query: "/v1/messages?beta=true".into(),
        session_from_path: None,
        headers: {
            headers.insert("x-llmap-session", HeaderValue::from_str(session).unwrap());
            headers
        },
        body: Bytes::from_static(
            br#"{"model":"client-model","max_tokens":16,"messages":[{"role":"user","content":"hello"}]}"#,
        ),
    }
}

fn fixture(
    mode: AuthMode,
    upstream_status: StatusCode,
) -> (Arc<DataPlane>, Arc<RecordingTransport>) {
    let repository = Arc::new(FakeRepository {
        accounts: HashMap::from([
            (
                "quiet".into(),
                (
                    provider("quiet", ProviderKind::AnthropicApiKey, "claude-quiet"),
                    "fake-quiet-token".into(),
                ),
            ),
            (
                "caller".into(),
                (
                    provider("caller", ProviderKind::AnthropicApiKey, "claude-caller"),
                    "fake-caller-token".into(),
                ),
            ),
        ]),
        unavailable: false,
    });
    let transport = Arc::new(RecordingTransport {
        requests: Mutex::new(Vec::new()),
        status: upstream_status,
    });
    let plane = Arc::new(DataPlane::new(
        mode,
        Authenticator::new([31; 32]),
        repository,
        Router::new(vec![
            route_account("quiet", 100),
            route_account("caller", 9000),
        ]),
        transport.clone(),
        32 * 1024 * 1024,
    ));
    (plane, transport)
}

#[tokio::test]
async fn caller_account_token_authorizes_routing_to_a_different_pool_account() {
    let (plane, transport) = fixture(AuthMode::Enforce, StatusCode::OK);

    let response = plane
        .handle(request("fake-caller-token", "sticky-agent"))
        .await
        .unwrap();

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.headers.get("x-request-id").unwrap(),
        "req_fake_123"
    );
    assert!(response.headers.get("set-cookie").is_none());
    assert_eq!(
        response.body.collect().await.unwrap().to_bytes(),
        "event: message_stop\ndata: {}\n\n"
    );

    let requests = transport.requests.lock();
    assert_eq!(requests.len(), 1);
    let upstream = &requests[0];
    assert_eq!(upstream.account_id, "quiet");
    assert_eq!(upstream.header("x-api-key"), Some("fake-quiet-token"));
    assert!(upstream.header("connection").is_none());
    let body: serde_json::Value = serde_json::from_slice(&upstream.body).unwrap();
    assert_eq!(body["model"], "claude-quiet");
}

#[tokio::test]
async fn unknown_tokens_are_indistinguishable_and_never_reach_upstream_in_enforce_mode() {
    let (plane, transport) = fixture(AuthMode::Enforce, StatusCode::OK);

    let error = plane
        .handle(request("fake-unknown-token", "unknown-agent"))
        .await
        .unwrap_err();

    assert_eq!(error, DataPlaneError::Unauthorized);
    assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
    assert!(transport.requests.lock().is_empty());
}

#[tokio::test]
async fn upstream_rate_limit_evicts_the_sticky_binding_for_the_next_request() {
    let (plane, transport) = fixture(AuthMode::Observe, StatusCode::TOO_MANY_REQUESTS);

    let response = plane
        .handle(request("ignored", "rate-agent"))
        .await
        .unwrap();

    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(transport.requests.lock()[0].account_id, "quiet");
}

#[tokio::test]
async fn request_body_limit_is_enforced_before_transport() {
    let (plane, transport) = fixture(AuthMode::Off, StatusCode::OK);
    let oversized = ProxyRequest {
        method: Method::POST,
        path_and_query: "/v1/messages".into(),
        session_from_path: None,
        headers: HeaderMap::new(),
        body: Bytes::from(vec![b'x'; 32 * 1024 * 1024 + 1]),
    };

    let error = plane.handle(oversized).await.unwrap_err();

    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert!(transport.requests.lock().is_empty());
}
