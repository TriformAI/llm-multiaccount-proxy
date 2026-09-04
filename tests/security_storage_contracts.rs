use std::collections::BTreeMap;

use llmap::providers::{ProviderAccount, ProviderError, ProviderKind, prepare_request};
use llmap::secrets::{AdminPasswordHash, SecretBox, SecretInput};
use llmap::storage::{AuditEvent, SqliteStore};
use url::Url;

fn account(kind: ProviderKind) -> ProviderAccount {
    ProviderAccount {
        id: "account-01".into(),
        label: "Primary".into(),
        kind,
        base_url: Url::parse("https://api.anthropic.com/").unwrap(),
        enabled: true,
        model_map: BTreeMap::from([("claude-default".into(), "claude-sonnet-4-5".into())]),
        egress_proxies: Vec::new(),
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
    assert_eq!(loaded_secret.expose(), credential.expose());
    let database_bytes = std::fs::read(database).unwrap();
    assert!(
        !database_bytes
            .windows(credential.expose().len())
            .any(|window| window == credential.expose().as_bytes())
    );
}

#[test]
fn sqlite_backup_restores_with_the_external_key_and_contains_no_plaintext_secrets() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("llmap.db");
    let backup = directory.path().join("llmap.backup.db");
    let mut stored_account = account(ProviderKind::AnthropicApiKey);
    stored_account.egress_proxies =
        vec!["socks5h://fake-restore-user:fake-restore-pass@residential.invalid:1080".into()];
    let credential = SecretInput::new("fake-restore-provider-token");
    let store = SqliteStore::open(&database, SecretBox::new([41; 32])).unwrap();
    store.upsert_account(&stored_account, &credential).unwrap();
    store
        .append_audit(&AuditEvent {
            occurred_at: chrono::Utc::now(),
            actor: "client:restore-fixture".into(),
            action: "proxy_request".into(),
            account_id: Some("account-01".into()),
            provider: Some("anthropic_api_key".into()),
            model: Some("claude-default".into()),
            session_id: Some("sha256:fixture".into()),
            status: Some(200),
            outcome: "success".into(),
            latency_ms: Some(12),
        })
        .unwrap();

    store.backup_to(&backup).unwrap();
    assert!(store.backup_to(&backup).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            std::fs::metadata(&backup).unwrap().permissions().mode() & 0o077,
            0
        );
    }
    drop(store);

    let backup_bytes = std::fs::read(&backup).unwrap();
    for secret in [
        credential.expose(),
        "fake-restore-user",
        "fake-restore-pass",
        "fake-sensitive-prompt-never-persist",
    ] {
        assert!(
            !backup_bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "backup contained a plaintext secret sentinel"
        );
    }

    let restored = SqliteStore::open(&backup, SecretBox::new([41; 32])).unwrap();
    let inventory = restored.list_accounts().unwrap();
    assert_eq!(inventory.len(), 1);
    assert_eq!(
        inventory[0].egress,
        vec!["socks5h://residential.invalid:1080"]
    );
    let (restored_account, restored_credential) = restored.load_account("account-01").unwrap();
    assert_eq!(
        restored_account.egress_proxies,
        stored_account.egress_proxies
    );
    assert_eq!(restored_credential.expose(), credential.expose());
    assert_eq!(restored.recent_audit(10).unwrap().len(), 1);
    drop(restored);

    let wrong_key = SqliteStore::open(&backup, SecretBox::new([42; 32])).unwrap();
    assert!(wrong_key.load_account("account-01").is_err());
}

#[test]
fn opening_legacy_sqlite_encrypts_and_scrubs_plaintext_proxy_userinfo() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("legacy.db");
    let account_json = serde_json::to_string(&ProviderAccount {
        egress_proxies: vec![
            "socks5h://fake-legacy-user:fake-legacy-pass@residential.invalid:1080".into(),
        ],
        ..account(ProviderKind::ClaudeOauth)
    })
    .unwrap();
    let legacy = rusqlite::Connection::open(&database).unwrap();
    legacy
        .execute_batch(
            "CREATE TABLE provider_accounts (
                id TEXT PRIMARY KEY,
                account_json TEXT NOT NULL,
                credential_ciphertext TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );",
        )
        .unwrap();
    legacy
        .execute(
            "INSERT INTO provider_accounts VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["account-01", account_json, "legacy-ciphertext", "now"],
        )
        .unwrap();
    drop(legacy);

    let store = SqliteStore::open(&database, SecretBox::new([29; 32])).unwrap();
    assert_eq!(
        store.list_accounts().unwrap()[0].egress,
        vec!["socks5h://residential.invalid:1080"]
    );
    drop(store);
    for candidate in [database.clone(), database.with_extension("db-wal")] {
        if let Ok(bytes) = std::fs::read(candidate) {
            for secret in ["fake-legacy-user", "fake-legacy-pass"] {
                assert!(
                    !bytes
                        .windows(secret.len())
                        .any(|window| window == secret.as_bytes())
                );
            }
        }
    }
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
    let prepared = prepare_request(&sigv4, &credential, "/v1/messages", "claude-default").unwrap();
    assert_eq!(prepared.url.path(), "/model/claude-sonnet-4-5/invoke");
    assert!(prepared.header("authorization").is_none());
}

#[test]
fn provider_model_maps_accept_family_and_default_keys() {
    let credential = SecretInput::new("fake-upstream-token");
    let mut family = account(ProviderKind::AnthropicApiKey);
    family.model_map = BTreeMap::from([("sonnet".into(), "provider-sonnet".into())]);
    let prepared =
        prepare_request(&family, &credential, "/v1/messages", "claude-sonnet-4-6").unwrap();
    assert_eq!(prepared.upstream_model, "provider-sonnet");

    family.model_map = BTreeMap::from([("default".into(), "provider-default".into())]);
    let prepared = prepare_request(&family, &credential, "/v1/messages", "future-model").unwrap();
    assert_eq!(prepared.upstream_model, "provider-default");
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
        "https://api.minimax.invalid/anthropic/v1/messages"
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
