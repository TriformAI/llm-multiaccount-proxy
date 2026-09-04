use std::collections::BTreeMap;

use axum::{body::Body, http::Method};
use chrono::{TimeZone, Utc};
use llmap::providers::{
    ProviderAccount, ProviderKind, decode_bedrock_frame, finalize_request_auth, prepare_request,
    prepare_request_for_stream, translate_bedrock_eventstream,
};
use llmap::secrets::SecretInput;
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
    let total_length = 16 + payload.len();
    let mut frame = Vec::new();
    frame.extend_from_slice(&(total_length as u32).to_be_bytes());
    frame.extend_from_slice(&0_u32.to_be_bytes());
    let prelude_crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&prelude_crc.to_be_bytes());
    frame.extend_from_slice(&payload);
    let message_crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&message_crc.to_be_bytes());

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
