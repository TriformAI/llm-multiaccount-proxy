use std::collections::BTreeMap;

use chrono::{Duration, TimeZone, Utc};
use llmap::admin::dashboard_page;
use llmap::auth::{AuthError, AuthMode, Authenticator};
use llmap::data_plane::AccountRepository;
use llmap::providers::{ProviderAccount, ProviderKind};
use llmap::secrets::{SecretBox, SecretInput};
use llmap::storage::{AuditEvent, SqliteStore};
use url::Url;

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 4, 11, 0, 0).unwrap()
}

fn account(id: &str) -> ProviderAccount {
    ProviderAccount {
        id: id.into(),
        label: format!("Account {id}"),
        kind: ProviderKind::ClaudeOauth,
        base_url: Url::parse("https://api.anthropic.com/").unwrap(),
        enabled: true,
        model_map: BTreeMap::from([("claude-default".into(), "claude-sonnet-4-5".into())]),
        egress_proxies: vec!["socks5h://fake-user:fake-pass@residential.invalid:1080".into()],
        compatible_auth_header: None,
        compatible_auth_prefix: None,
    }
}

#[tokio::test]
async fn account_management_redacts_credentials_and_pause_invalidates_auth_immediately() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("llmap.db");
    let store = SqliteStore::open(&database, SecretBox::new([51; 32])).unwrap();
    store
        .upsert_account(&account("a"), &SecretInput::new("fake-account-token"))
        .unwrap();

    let public = store.list_accounts().unwrap();
    assert_eq!(public.len(), 1);
    assert!(public[0].credential_present);
    assert_eq!(public[0].egress, vec!["socks5h://residential.invalid:1080"]);
    assert!(
        !serde_json::to_string(&public)
            .unwrap()
            .contains("fake-pass")
    );
    assert!(
        !serde_json::to_string(&public)
            .unwrap()
            .contains("fake-account-token")
    );
    let database_bytes = std::fs::read(&database).unwrap();
    for sensitive in ["fake-pass", "fake-user", "fake-account-token"] {
        assert!(
            !database_bytes
                .windows(sensitive.len())
                .any(|window| window == sensitive.as_bytes()),
            "SQLite must not contain residential-proxy or provider credentials"
        );
    }

    store.set_account_enabled("a", false).unwrap();
    let authenticator = Authenticator::new([52; 32]);
    let snapshot = store
        .credential_snapshot(&authenticator, now())
        .await
        .unwrap();
    assert_eq!(
        authenticator.authorize(
            AuthMode::Enforce,
            Some("fake-account-token"),
            &snapshot,
            now()
        ),
        Err(AuthError::Unauthorized)
    );

    store.delete_account("a").unwrap();
    assert!(store.list_accounts().unwrap().is_empty());
}

#[test]
fn audit_history_is_metadata_only_and_prunes_at_thirty_days() {
    let directory = tempfile::tempdir().unwrap();
    let store =
        SqliteStore::open(&directory.path().join("llmap.db"), SecretBox::new([53; 32])).unwrap();
    for (age, outcome) in [(31, "old"), (29, "success")] {
        store
            .append_audit(&AuditEvent {
                occurred_at: now() - Duration::days(age),
                actor: "client:matched-account".into(),
                action: "proxy.request".into(),
                account_id: Some("a".into()),
                provider: Some("claude_oauth".into()),
                model: Some("claude-sonnet-4-5".into()),
                session_id: Some("fake-session".into()),
                status: Some(200),
                outcome: outcome.into(),
                latency_ms: Some(42),
            })
            .unwrap();
    }

    assert_eq!(
        store
            .prune_audit_before(now() - Duration::days(30))
            .unwrap(),
        1
    );
    let events = store.recent_audit(20).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "success");
    let json = serde_json::to_string(&events).unwrap();
    assert!(!json.contains("prompt"));
    assert!(!json.contains("response_body"));
}

#[test]
fn dashboard_exposes_account_provider_proxy_and_auth_controls() {
    let page = dashboard_page();
    assert!(page.contains("Routing control plane"));
    assert!(page.contains("Claude OAuth"));
    assert!(page.contains("Anthropic API key"));
    assert!(page.contains("Amazon Bedrock"));
    assert!(page.contains("Anthropic-compatible"));
    assert!(page.contains("SOCKS5h"));
    assert!(page.contains("Authentication mode"));
    assert!(page.contains("Rotate credential"));
    assert!(page.contains("Remove"));
    assert!(page.contains("observe"));
    assert!(page.contains("enforce"));
    assert!(page.contains("aria-live"));
    assert!(!page.contains("fake-account-token"));
}
