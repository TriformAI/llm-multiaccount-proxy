use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body as AxumBody;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use hudsucker::hyper::{Method, Request};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};
use llmap::auth::{AuthMode, Authenticator, CredentialSnapshot};
use llmap::data_plane::{
    AccountRepository, DataPlane, RepositoryError, TransportError, UpstreamRequest,
    UpstreamResponse, UpstreamTransport,
};
use llmap::egress::DestinationPolicy;
use llmap::forward_proxy::{ForwardProxyHandler, generate_ca, load_ca};
use llmap::providers::ProviderAccount;
use llmap::routing::Router;
use llmap::secrets::SecretInput;

struct EmptyRepository;

#[async_trait]
impl AccountRepository for EmptyRepository {
    async fn credential_snapshot(
        &self,
        _authenticator: &Authenticator,
        _now: DateTime<Utc>,
    ) -> Result<CredentialSnapshot, RepositoryError> {
        Ok(CredentialSnapshot::Available(Vec::new()))
    }

    async fn load_account(
        &self,
        _account_id: &str,
    ) -> Result<(ProviderAccount, SecretInput), RepositoryError> {
        Err(RepositoryError::NotFound)
    }
}

struct UnusedTransport;

#[async_trait]
impl UpstreamTransport for UnusedTransport {
    async fn send(&self, _request: UpstreamRequest) -> Result<UpstreamResponse, TransportError> {
        Ok(UpstreamResponse {
            status: StatusCode::OK,
            headers: Default::default(),
            body: AxumBody::empty(),
        })
    }
}

fn handler() -> ForwardProxyHandler {
    let plane = Arc::new(DataPlane::new(
        AuthMode::Enforce,
        Authenticator::new([71; 32]),
        Arc::new(EmptyRepository),
        Router::new(Vec::new()),
        Arc::new(UnusedTransport),
        1024,
    ));
    ForwardProxyHandler::new(
        plane,
        DestinationPolicy::new(vec!["api.anthropic.com".into()], false),
        1024,
    )
}

#[tokio::test]
async fn mitm_connect_is_allowlisted_and_metadata_destinations_are_denied() {
    let context = HttpContext {
        client_addr: "127.0.0.1:4242".parse().unwrap(),
    };
    let mut handler = handler();
    let denied = Request::builder()
        .method(Method::CONNECT)
        .uri("169.254.169.254:80")
        .body(Body::empty())
        .unwrap();
    match handler.handle_request(&context, denied).await {
        RequestOrResponse::Response(response) => {
            assert_eq!(response.status(), StatusCode::FORBIDDEN)
        }
        RequestOrResponse::Request(_) => panic!("unsafe CONNECT escaped the destination policy"),
    }

    let allowed = Request::builder()
        .method(Method::CONNECT)
        .uri("api.anthropic.com:443")
        .body(Body::empty())
        .unwrap();
    assert!(matches!(
        handler.handle_request(&context, allowed).await,
        RequestOrResponse::Request(_)
    ));
}

#[test]
fn ca_is_generated_once_with_a_private_key_and_can_be_loaded() {
    let directory = tempfile::tempdir().unwrap();
    let cert = directory.path().join("llmap-ca.pem");
    let key = directory.path().join("llmap-ca-key.pem");

    generate_ca(&cert, &key).unwrap();
    let cert_text = std::fs::read_to_string(&cert).unwrap();
    let key_text = std::fs::read_to_string(&key).unwrap();
    assert!(cert_text.contains("BEGIN CERTIFICATE"));
    assert!(key_text.contains("BEGIN PRIVATE KEY"));
    load_ca(&cert, &key).unwrap();
    assert!(generate_ca(&cert, &key).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
