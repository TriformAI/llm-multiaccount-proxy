use std::collections::BTreeMap;

use chrono::{Duration, TimeZone, Utc};
use llmap::auth::{AuthError, AuthMode, Authenticator};
use llmap::data_plane::AccountRepository;
use llmap::providers::{ProviderAccount, ProviderKind};
use llmap::secrets::{SecretBox, SecretInput};
use llmap::storage::SqliteStore;
use url::Url;

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 4, 11, 0, 0).unwrap()
}

fn oauth_account() -> ProviderAccount {
    ProviderAccount {
        id: "oauth-primary".into(),
        label: "OAuth primary".into(),
        kind: ProviderKind::ClaudeOauth,
        base_url: Url::parse("https://api.anthropic.com/").unwrap(),
        enabled: true,
        model_map: BTreeMap::new(),
        egress_proxies: Vec::new(),
        compatible_auth_header: None,
        compatible_auth_prefix: None,
    }
}

fn envelope(access_token: &str, expires_at: &str) -> SecretInput {
    SecretInput::new(format!(
        r#"{{"access_token":"{access_token}","refresh_token":"fake-refresh","expires_at":"{expires_at}","token_endpoint":"https://console.anthropic.com/oauth/token","client_id":"fake-client"}}"#
    ))
}

#[tokio::test]
async fn oauth_access_token_authenticates_without_exposing_the_envelope() {
    let directory = tempfile::tempdir().unwrap();
    let store =
        SqliteStore::open(&directory.path().join("llmap.db"), SecretBox::new([81; 32])).unwrap();
    store
        .upsert_account(
            &oauth_account(),
            &envelope("fake-current-access", "2026-09-04T13:00:00Z"),
        )
        .unwrap();
    let authenticator = Authenticator::new([82; 32]);
    let snapshot = store
        .credential_snapshot(&authenticator, now())
        .await
        .unwrap();

    assert!(
        authenticator
            .authorize(
                AuthMode::Enforce,
                Some("fake-current-access"),
                &snapshot,
                now()
            )
            .unwrap()
            .allowed
    );
    assert_eq!(
        authenticator.authorize(AuthMode::Enforce, Some("fake-refresh"), &snapshot, now()),
        Err(AuthError::Unauthorized)
    );
}

#[tokio::test]
async fn oauth_rotation_keeps_only_a_bounded_previous_access_token() {
    let directory = tempfile::tempdir().unwrap();
    let store =
        SqliteStore::open(&directory.path().join("llmap.db"), SecretBox::new([83; 32])).unwrap();
    store
        .upsert_account(
            &oauth_account(),
            &envelope("fake-old-access", "2026-09-04T11:05:00Z"),
        )
        .unwrap();
    store
        .rotate_account_credential(
            &oauth_account(),
            &envelope("fake-new-access", "2026-09-04T13:00:00Z"),
            now() + Duration::minutes(5),
        )
        .unwrap();
    let authenticator = Authenticator::new([84; 32]);
    let snapshot = store
        .credential_snapshot(&authenticator, now())
        .await
        .unwrap();

    for token in ["fake-old-access", "fake-new-access"] {
        assert!(
            authenticator
                .authorize(AuthMode::Enforce, Some(token), &snapshot, now())
                .unwrap()
                .allowed
        );
    }
    assert_eq!(
        authenticator.authorize(
            AuthMode::Enforce,
            Some("fake-old-access"),
            &snapshot,
            now() + Duration::minutes(6)
        ),
        Err(AuthError::Unauthorized)
    );
}
