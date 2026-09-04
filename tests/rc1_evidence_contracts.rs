use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::Infallible;
use std::fs;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::stream;
use http_body_util::BodyExt;
use llmap::auth::{AccountCredential, AuthMode, Authenticator, CredentialSnapshot};
use llmap::data_plane::{
    AccountRepository, DataPlane, ProxyAuditRecord, ProxyRequest, RepositoryError, TransportError,
    UpstreamRequest, UpstreamResponse, UpstreamTransport,
};
use llmap::providers::{ProviderAccount, ProviderKind};
use llmap::routing::{RouteAccount, Router};
use llmap::secrets::SecretInput;
use parking_lot::Mutex;
use tokio::sync::Barrier;
use url::Url;

const CALLER_TOKEN: &str = "fake-rc1-caller-token";
const PROMPT_SENTINEL: &str = "fake-sensitive-prompt-never-record";

#[test]
fn release_workflow_never_presents_a_prerelease_as_ga() {
    let workflow = fs::read_to_string(format!(
        "{}/.github/workflows/release.yml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();

    assert!(workflow.contains("prerelease: ${{ contains(github.ref_name, '-') }}"));
    assert!(workflow.contains("make_latest: ${{ !contains(github.ref_name, '-') }}"));
}

struct EvidenceRepository {
    accounts: HashMap<String, (ProviderAccount, String)>,
    audits: Mutex<Vec<ProxyAuditRecord>>,
}

#[async_trait]
impl AccountRepository for EvidenceRepository {
    async fn credential_snapshot(
        &self,
        authenticator: &Authenticator,
        _now: DateTime<Utc>,
    ) -> Result<CredentialSnapshot, RepositoryError> {
        Ok(CredentialSnapshot::Available(
            self.accounts
                .values()
                .map(|(account, token)| {
                    AccountCredential::active(authenticator, &account.id, token)
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
            .map(|(account, token)| (account.clone(), SecretInput::new(token.clone())))
            .ok_or(RepositoryError::NotFound)
    }

    async fn append_proxy_audit(&self, record: ProxyAuditRecord) -> Result<(), RepositoryError> {
        self.audits.lock().push(record);
        Ok(())
    }
}

#[derive(Clone)]
enum SyntheticOutcome {
    Response(StatusCode),
    DisconnectBeforeResponse,
    ConcurrentStream(Arc<Barrier>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransportObservation {
    account_id: String,
    body_bytes: usize,
    egress_hops: usize,
}

struct SyntheticTransport {
    outcome: SyntheticOutcome,
    observations: Mutex<Vec<TransportObservation>>,
}

#[async_trait]
impl UpstreamTransport for SyntheticTransport {
    async fn send(&self, request: UpstreamRequest) -> Result<UpstreamResponse, TransportError> {
        self.observations.lock().push(TransportObservation {
            account_id: request.account_id,
            body_bytes: request.body.len(),
            egress_hops: request.egress_proxies.len(),
        });
        let status = match &self.outcome {
            SyntheticOutcome::Response(status) => *status,
            SyntheticOutcome::DisconnectBeforeResponse => return Err(TransportError),
            SyntheticOutcome::ConcurrentStream(barrier) => {
                barrier.wait().await;
                StatusCode::OK
            }
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("text/event-stream"),
        );
        if matches!(status.as_u16(), 429 | 529) {
            headers.insert("retry-after", HeaderValue::from_static("1"));
        }
        let body = if matches!(&self.outcome, SyntheticOutcome::ConcurrentStream(_)) {
            Body::from_stream(stream::iter((0..128).map(|index| {
                Ok::<_, Infallible>(Bytes::from(format!(
                    "event: content_block_delta\ndata: {{\"index\":{index}}}\n\n"
                )))
            })))
        } else {
            Body::from("event: message_stop\ndata: {}\n\n")
        };
        Ok(UpstreamResponse {
            status,
            headers,
            body,
        })
    }
}

fn provider(id: &str, token: &str) -> (ProviderAccount, String) {
    (
        ProviderAccount {
            id: id.into(),
            label: id.into(),
            kind: ProviderKind::AnthropicApiKey,
            base_url: Url::parse("https://api.anthropic.com/").unwrap(),
            enabled: true,
            model_map: BTreeMap::from([("rc1-model".into(), "claude-sonnet-4-6".into())]),
            egress_proxies: vec!["socks5h://fixture.invalid:1080".into()],
            compatible_auth_header: None,
            compatible_auth_prefix: None,
        },
        token.into(),
    )
}

fn route_account(id: &str) -> RouteAccount {
    RouteAccount {
        id: id.into(),
        provider: "anthropic_api_key".into(),
        enabled: true,
        healthy: true,
        in_flight: 0,
        utilization_basis_points: 0,
        models: HashSet::from(["rc1-model".into()]),
        depleted_until: None,
    }
}

fn fixture(
    outcome: SyntheticOutcome,
) -> (
    Arc<DataPlane>,
    Arc<EvidenceRepository>,
    Arc<SyntheticTransport>,
) {
    let repository = Arc::new(EvidenceRepository {
        accounts: HashMap::from([
            ("account-a".into(), provider("account-a", CALLER_TOKEN)),
            (
                "account-b".into(),
                provider("account-b", "fake-rc1-pool-token"),
            ),
        ]),
        audits: Mutex::new(Vec::new()),
    });
    let transport = Arc::new(SyntheticTransport {
        outcome,
        observations: Mutex::new(Vec::new()),
    });
    let plane = Arc::new(DataPlane::new(
        AuthMode::Enforce,
        Authenticator::new([71; 32]),
        repository.clone(),
        Router::new(vec![route_account("account-a"), route_account("account-b")]),
        transport.clone(),
        1024 * 1024,
    ));
    (plane, repository, transport)
}

fn request(session: &str) -> ProxyRequest {
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static(CALLER_TOKEN));
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert("x-llmap-session", HeaderValue::from_str(session).unwrap());
    ProxyRequest {
        method: Method::POST,
        path_and_query: "/v1/messages".into(),
        session_from_path: None,
        headers,
        body: Bytes::from(format!(
            r#"{{"model":"rc1-model","max_tokens":16,"messages":[{{"role":"user","content":"{PROMPT_SENTINEL}"}}]}}"#
        )),
    }
}

#[tokio::test]
async fn synthetic_fault_matrix_records_only_classified_metadata() {
    let cases = [
        (StatusCode::UNAUTHORIZED, "upstream_unauthorized"),
        (StatusCode::FORBIDDEN, "upstream_unauthorized"),
        (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
        (StatusCode::from_u16(529).unwrap(), "overloaded"),
    ];

    for (status, expected_outcome) in cases {
        let (plane, repository, transport) = fixture(SyntheticOutcome::Response(status));
        let response = plane.handle(request("fault-matrix")).await.unwrap();
        assert_eq!(response.status, status);
        assert_eq!(transport.observations.lock().len(), 1);
        let audits = repository.audits.lock();
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].status, status.as_u16());
        assert_eq!(audits[0].outcome, expected_outcome);
        let evidence = format!("{audits:?}");
        assert!(!evidence.contains(PROMPT_SENTINEL));
        assert!(!evidence.contains(CALLER_TOKEN));
    }

    let (plane, repository, transport) = fixture(SyntheticOutcome::DisconnectBeforeResponse);
    let error = plane
        .handle(request("pre-response-disconnect"))
        .await
        .unwrap_err();
    assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(transport.observations.lock().len(), 1);
    let audits = repository.audits.lock();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].status, StatusCode::BAD_GATEWAY.as_u16());
    assert_eq!(audits[0].outcome, "transport_failure");
}

#[tokio::test]
async fn concurrent_synthetic_long_streams_are_balanced_and_fully_accounted() {
    const REQUESTS: usize = 64;
    let barrier = Arc::new(Barrier::new(REQUESTS + 1));
    let (plane, repository, transport) =
        fixture(SyntheticOutcome::ConcurrentStream(barrier.clone()));
    let mut tasks = Vec::new();
    for index in 0..REQUESTS {
        let plane = plane.clone();
        tasks.push(tokio::spawn(async move {
            let response = plane
                .handle(request(&format!("concurrent-{index}")))
                .await
                .unwrap();
            assert_eq!(response.status, StatusCode::OK);
            let body = response.body.collect().await.unwrap().to_bytes();
            assert!(body.ends_with(b"event: content_block_delta\ndata: {\"index\":127}\n\n"));
        }));
    }
    barrier.wait().await;
    for task in tasks {
        task.await.unwrap();
    }

    let metrics = plane.metrics();
    assert_eq!(metrics.requests_total, REQUESTS as u64);
    assert_eq!(metrics.responses_total, REQUESTS as u64);
    assert_eq!(metrics.authentication_failures_total, 0);
    assert_eq!(metrics.upstream_failures_total, 0);
    let observations = transport.observations.lock();
    assert_eq!(observations.len(), REQUESTS);
    assert!(observations.iter().all(|item| item.body_bytes > 0));
    assert!(observations.iter().all(|item| item.egress_hops == 1));
    assert_eq!(
        observations
            .iter()
            .map(|item| item.account_id.as_str())
            .collect::<HashSet<_>>(),
        HashSet::from(["account-a", "account-b"])
    );
    let audits = repository.audits.lock();
    assert_eq!(audits.len(), REQUESTS);
    let evidence = format!("{audits:?}");
    assert!(!evidence.contains(PROMPT_SENTINEL));
    assert!(!evidence.contains(CALLER_TOKEN));
}
