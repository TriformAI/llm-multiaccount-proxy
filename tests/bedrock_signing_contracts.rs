use std::collections::BTreeMap;

use axum::http::Method;
use chrono::{TimeZone, Utc};
use llmap::providers::{ProviderAccount, ProviderKind, finalize_request_auth, prepare_request};
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
