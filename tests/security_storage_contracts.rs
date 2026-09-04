use std::collections::BTreeMap;

use llmap::providers::{ProviderAccount, ProviderError, ProviderKind, prepare_request};
use llmap::secrets::{AdminPasswordHash, SecretBox, SecretInput};
use llmap::storage::SqliteStore;
use url::Url;

fn account(kind: ProviderKind) -> ProviderAccount {
    ProviderAccount {
        id: "account-01".into(),
        label: "Primary".into(),
        kind,
        base_url: Url::parse("https://api.anthropic.com/").unwrap(),
        enabled: true,
        model_map: BTreeMap::from([("claude-default".into(), "claude-sonnet-4-5".into())]),
        compatible_auth_header: None,
        compatible_auth_prefix: None,
    }
}

#[test]
fn xchacha_secret_box_round_trips_and_authenticates_context() {
    let secrets = SecretBox::new([17; 32]);
    let plaintext = SecretInput::new("fake-provider-token-never-log");

    let encrypted = secrets.encrypt(&plaintext, b"account:account-01").unwrap();

    assert!(!encrypted.as_storage_value().contains(plaintext.expose()));
    assert_eq!(
        secrets
            .decrypt(&encrypted, b"account:account-01")
            .unwrap()
            .as_str(),
        plaintext.expose()
    );
    assert!(secrets.decrypt(&encrypted, b"account:different").is_err());
    assert!(!format!("{encrypted:?}").contains("fake-provider-token"));
}

#[test]
fn admin_passwords_are_argon2id_hashes_and_never_debugged() {
    let password = SecretInput::new("fake-admin-password");
    let password_hash = AdminPasswordHash::create(&password).unwrap();

    assert!(password_hash.as_storage_value().starts_with("$argon2id$"));
    assert!(password_hash.verify(&password));
    assert!(!password_hash.verify(&SecretInput::new("fake-wrong-password")));
    assert!(!format!("{password_hash:?}").contains("fake-admin-password"));
}

#[test]
fn sqlite_uses_wal_and_never_persists_plaintext_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("llmap.db");
    let store = SqliteStore::open(&database, SecretBox::new([23; 32])).unwrap();
    let credential = SecretInput::new("fake-sqlite-provider-token");

    store
        .upsert_account(&account(ProviderKind::AnthropicApiKey), &credential)
        .unwrap();
    let (loaded_account, loaded_secret) = store.load_account("account-01").unwrap();

    assert_eq!(store.journal_mode().unwrap(), "wal");
    assert_eq!(loaded_account.label, "Primary");
    assert_eq!(loaded_secret.as_str(), credential.expose());
    let database_bytes = std::fs::read(database).unwrap();
    assert!(
        !database_bytes
            .windows(credential.expose().len())
            .any(|window| window == credential.expose().as_bytes())
    );
}

#[test]
fn provider_adapters_rewrite_model_and_own_upstream_authentication() {
    let credential = SecretInput::new("fake-upstream-token");
    let anthropic = account(ProviderKind::AnthropicApiKey);
    let prepared = prepare_request(
        &anthropic,
        &credential,
        "/v1/messages?beta=true",
        "claude-default",
    )
    .unwrap();

    assert_eq!(
        prepared.url.as_str(),
        "https://api.anthropic.com/v1/messages?beta=true"
    );
    assert_eq!(prepared.upstream_model, "claude-sonnet-4-5");
    assert_eq!(prepared.header("x-api-key"), Some("fake-upstream-token"));
    assert!(!format!("{prepared:?}").contains("fake-upstream-token"));

    let oauth = account(ProviderKind::ClaudeOauth);
    let prepared = prepare_request(&oauth, &credential, "/v1/messages", "claude-default").unwrap();
    assert_eq!(
        prepared.header("authorization"),
        Some("Bearer fake-upstream-token")
    );

    let sigv4 = account(ProviderKind::BedrockSigV4);
    assert_eq!(
        prepare_request(&sigv4, &credential, "/model/x/invoke", "claude-default").unwrap_err(),
        ProviderError::AwsSigningRequired
    );
}

#[test]
fn compatible_provider_auth_header_is_explicit_and_validated() {
    let mut compatible = account(ProviderKind::AnthropicCompatible);
    compatible.base_url = Url::parse("https://api.minimax.invalid/anthropic/").unwrap();
    compatible.compatible_auth_header = Some("Authorization".into());
    compatible.compatible_auth_prefix = Some("Bearer ".into());

    let prepared = prepare_request(
        &compatible,
        &SecretInput::new("fake-compatible-token"),
        "/v1/messages",
        "claude-default",
    )
    .unwrap();
    assert_eq!(
        prepared.url.as_str(),
        "https://api.minimax.invalid/v1/messages"
    );
    assert_eq!(
        prepared.header("authorization"),
        Some("Bearer fake-compatible-token")
    );

    compatible.compatible_auth_header = Some("bad header\r\n".into());
    assert_eq!(
        prepare_request(
            &compatible,
            &SecretInput::new("fake-compatible-token"),
            "/v1/messages",
            "claude-default"
        )
        .unwrap_err(),
        ProviderError::InvalidAuthenticationHeader
    );
}
