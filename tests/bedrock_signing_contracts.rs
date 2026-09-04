use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Method, StatusCode},
};
use bytes::Bytes;
use chrono::{DateTime, TimeZone, Utc};
use llmap::auth::{AuthMode, Authenticator, CredentialSnapshot};
use llmap::data_plane::{
    AccountRepository, DataPlane, ProxyRequest, RepositoryError, TransportError, UpstreamRequest,
    UpstreamResponse, UpstreamTransport,
};
use llmap::providers::{
    ProviderAccount, ProviderKind, decode_bedrock_frame, finalize_request_auth, prepare_request,
    prepare_request_for_stream, translate_bedrock_eventstream,
};
use llmap::routing::{RouteAccount, Router};
use llmap::secrets::SecretInput;
use parking_lot::Mutex;
use url::Url;

fn account(kind: ProviderKind) -> ProviderAccount {
    ProviderAccount {
        id: "bedrock-us-east".into(),
        label: "Bedrock us-east-1".into(),
        kind,
        base_url: Url::parse("https://bedrock-runtime.us-east-1.amazonaws.com/").unwrap(),
        enabled: true,
        model_map: BTreeMap::from([(
            "claude-default".into(),
            "us.anthropic.claude-sonnet-4-6".into(),
        )]),
        egress_proxies: Vec::new(),
        compatible_auth_header: None,
        compatible_auth_prefix: None,
    }
}

fn event_stream_header(name: &str, value: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.push(u8::try_from(name.len()).unwrap());
    encoded.extend_from_slice(name.as_bytes());
    encoded.push(7); // Smithy Amazon EventStream string header.
    encoded.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    encoded.extend_from_slice(value.as_bytes());
    encoded
}

fn event_stream_frame(message_type: &str, event_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut headers = event_stream_header(":message-type", message_type);
    headers.extend_from_slice(&event_stream_header(":event-type", event_type));
    headers.extend_from_slice(&event_stream_header(":content-type", "application/json"));

    let total_length = 16 + headers.len() + payload.len();
    let mut frame = Vec::new();
    frame.extend_from_slice(&(total_length as u32).to_be_bytes());
    frame.extend_from_slice(&(headers.len() as u32).to_be_bytes());
    let prelude_crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&prelude_crc.to_be_bytes());
    frame.extend_from_slice(&headers);
    frame.extend_from_slice(payload);
    let message_crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&message_crc.to_be_bytes());
    frame
}

#[test]
fn bedrock_api_key_uses_native_invoke_path() {
    let prepared = prepare_request(
        &account(ProviderKind::BedrockApiKey),
        &SecretInput::new("fake-bedrock-bearer"),
        "/v1/messages",
        "claude-default",
    )
    .unwrap();

    assert_eq!(
        prepared.url.as_str(),
        "https://bedrock-runtime.us-east-1.amazonaws.com/model/us.anthropic.claude-sonnet-4-6/invoke"
    );
    assert_eq!(
        prepared.header("authorization"),
        Some("Bearer fake-bedrock-bearer")
    );
}

#[tokio::test]
async fn bedrock_stream_path_and_event_frames_translate_to_anthropic_sse() {
    let prepared = prepare_request_for_stream(
        &account(ProviderKind::BedrockApiKey),
        &SecretInput::new("fake-bedrock-bearer"),
        "/v1/messages",
        "claude-default",
        true,
    )
    .unwrap();
    assert!(
        prepared
            .url
            .path()
            .ends_with("/invoke-with-response-stream")
    );

    let anthropic_event =
        br#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}"#;
    let payload = serde_json::to_vec(&serde_json::json!({
        "bytes": base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            anthropic_event
        )
    }))
    .unwrap();
    let frame = event_stream_frame("event", "chunk", &payload);

    let sse = decode_bedrock_frame(&frame).unwrap();
    assert_eq!(
        String::from_utf8(sse.to_vec()).unwrap(),
        format!(
            "event: content_block_delta\ndata: {}\n\n",
            String::from_utf8_lossy(anthropic_event)
        )
    );

    let translated = translate_bedrock_eventstream(Body::from(frame));
    let translated = axum::body::to_bytes(translated, 1024).await.unwrap();
    assert_eq!(translated, sse);
}

#[test]
fn aws_published_sigv4_lifecycle_vector_matches_exactly() {
    let mut s3 = account(ProviderKind::BedrockSigV4);
    s3.base_url = Url::parse("https://examplebucket.s3.amazonaws.com/").unwrap();
    let credential = SecretInput::new(
        r#"{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","region":"us-east-1","service":"s3"}"#,
    );
    let mut prepared = prepare_request(&s3, &credential, "/?lifecycle", "unused").unwrap();

    finalize_request_auth(
        &s3,
        &credential,
        &Method::GET,
        b"",
        Utc.with_ymd_and_hms(2013, 5, 24, 0, 0, 0).unwrap(),
        &mut prepared,
    )
    .unwrap();

    let authorization = prepared.header("authorization").unwrap();
    assert!(
        authorization
            .contains("Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request")
    );
    assert!(authorization.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
    assert!(
        authorization.ends_with(
            "Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
        )
    );
}

#[test]
fn eventstream_requires_aws_semantic_headers() {
    let event = br#"{"type":"message_stop"}"#;
    let payload = serde_json::to_vec(&serde_json::json!({
        "bytes": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, event)
    }))
    .unwrap();
    let total_length = 16 + payload.len();
    let mut frame = Vec::new();
    frame.extend_from_slice(&(total_length as u32).to_be_bytes());
    frame.extend_from_slice(&0_u32.to_be_bytes());
    let prelude_crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&prelude_crc.to_be_bytes());
    frame.extend_from_slice(&payload);
    let message_crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&message_crc.to_be_bytes());

    assert!(decode_bedrock_frame(&frame).is_err());
}

#[test]
fn modeled_bedrock_stream_exception_becomes_safe_anthropic_error_sse() {
    let frame = event_stream_frame(
        "exception",
        "throttlingException",
        br#"{"message":"fake-sensitive-provider-detail"}"#,
    );

    let sse = String::from_utf8(decode_bedrock_frame(&frame).unwrap().to_vec()).unwrap();

    assert!(sse.starts_with("event: error\ndata: "));
    assert!(sse.contains("bedrock_throttling_exception"));
    assert!(!sse.contains("fake-sensitive-provider-detail"));
}

struct BedrockRepository {
    account: ProviderAccount,
    credential: String,
}

#[async_trait]
impl AccountRepository for BedrockRepository {
    async fn credential_snapshot(
        &self,
        _authenticator: &Authenticator,
        _now: DateTime<Utc>,
    ) -> Result<CredentialSnapshot, RepositoryError> {
        Ok(CredentialSnapshot::Available(Vec::new()))
    }

    async fn load_account(
        &self,
        account_id: &str,
    ) -> Result<(ProviderAccount, SecretInput), RepositoryError> {
        (account_id == self.account.id)
            .then(|| {
                (
                    self.account.clone(),
                    SecretInput::new(self.credential.clone()),
                )
            })
            .ok_or(RepositoryError::NotFound)
    }
}

#[derive(Default)]
struct BedrockTransport {
    requests: Mutex<Vec<UpstreamRequest>>,
}

#[async_trait]
impl UpstreamTransport for BedrockTransport {
    async fn send(&self, request: UpstreamRequest) -> Result<UpstreamResponse, TransportError> {
        self.requests.lock().push(request);
        Ok(UpstreamResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Body::from("{}"),
        })
    }
}

#[tokio::test]
async fn bedrock_sigv4_covers_forwarded_content_type() {
    let account = account(ProviderKind::BedrockSigV4);
    let repository = Arc::new(BedrockRepository {
        account: account.clone(),
        credential: r#"{"access_key_id":"AKIDEXAMPLE","secret_access_key":"fake-secret-key","region":"us-east-1"}"#.into(),
    });
    let transport = Arc::new(BedrockTransport::default());
    let plane = DataPlane::new(
        AuthMode::Off,
        Authenticator::new([44; 32]),
        repository,
        Router::new(vec![RouteAccount {
            id: account.id,
            provider: "bedrock".into(),
            enabled: true,
            healthy: true,
            in_flight: 0,
            utilization_basis_points: 0,
            models: HashSet::from(["claude-default".into()]),
            depleted_until: None,
        }]),
        transport.clone(),
        1024 * 1024,
    );
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));

    plane
        .handle(ProxyRequest {
            method: Method::POST,
            path_and_query: "/v1/messages".into(),
            session_from_path: None,
            headers,
            body: Bytes::from_static(br#"{"model":"claude-default","max_tokens":1,"messages":[]}"#),
        })
        .await
        .unwrap();

    let requests = transport.requests.lock();
    let authorization = requests[0].header("authorization").unwrap();
    assert!(
        authorization.contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date")
    );
}

#[test]
fn sigv4_signing_adds_scoped_headers_without_exposing_the_secret() {
    let account = account(ProviderKind::BedrockSigV4);
    let credential = SecretInput::new(
        r#"{"access_key_id":"AKIDEXAMPLE","secret_access_key":"fake-secret-key","session_token":"fake-session-token","region":"us-east-1"}"#,
    );
    let mut prepared =
        prepare_request(&account, &credential, "/v1/messages", "claude-default").unwrap();
    finalize_request_auth(
        &account,
        &credential,
        &Method::POST,
        br#"{"anthropic_version":"bedrock-2023-05-31"}"#,
        Utc.with_ymd_and_hms(2026, 9, 4, 10, 30, 0).unwrap(),
        &mut prepared,
    )
    .unwrap();

    assert_eq!(prepared.header("x-amz-date"), Some("20260904T103000Z"));
    assert_eq!(
        prepared.header("x-amz-security-token"),
        Some("fake-session-token")
    );
    assert!(
        prepared
            .header("authorization")
            .unwrap()
            .contains("Credential=AKIDEXAMPLE/20260904/us-east-1/bedrock/aws4_request")
    );
    assert!(prepared.header("x-amz-content-sha256").is_some());
    assert!(!format!("{prepared:?}").contains("fake-secret-key"));
}
