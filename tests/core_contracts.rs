use std::collections::{BTreeMap, HashSet};

use chrono::{Duration, TimeZone, Utc};
use llmap::auth::{AccountCredential, AuthError, AuthMode, Authenticator, CredentialSnapshot};
use llmap::config::Config;
use llmap::egress::{DestinationPolicy, EgressError, ProxyChain, ProxyEndpoint};
use llmap::routing::{
    RetryDecision, RouteAccount, RouteRequest, Router, UpstreamOutcome, retry_decision,
};
use url::Url;

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 4, 9, 0, 0).unwrap()
}

#[test]
fn any_active_account_token_authenticates_the_whole_pool() {
    let authenticator = Authenticator::new([7; 32]);
    let snapshot = CredentialSnapshot::Available(vec![
        AccountCredential::active(&authenticator, "account-a", "fake-token-a"),
        AccountCredential::active(&authenticator, "account-b", "fake-token-b"),
    ]);

    let decision = authenticator
        .authorize(AuthMode::Enforce, Some("fake-token-b"), &snapshot, now())
        .unwrap();

    assert!(decision.allowed);
    assert_eq!(decision.matched_account_id.as_deref(), Some("account-b"));
}

#[test]
fn auth_modes_and_rotation_have_fail_closed_boundaries() {
    let authenticator = Authenticator::new([9; 32]);
    let credential = AccountCredential::active(&authenticator, "account-a", "fake-current")
        .with_previous(
            &authenticator,
            "fake-previous",
            now() + Duration::minutes(10),
        );
    let snapshot = CredentialSnapshot::Available(vec![credential.clone()]);

    assert!(
        authenticator
            .authorize(AuthMode::Enforce, Some("fake-previous"), &snapshot, now())
            .unwrap()
            .allowed
    );
    assert_eq!(
        authenticator.authorize(
            AuthMode::Enforce,
            Some("fake-previous"),
            &snapshot,
            now() + Duration::minutes(11),
        ),
        Err(AuthError::Unauthorized)
    );

    let paused = CredentialSnapshot::Available(vec![credential.paused()]);
    assert_eq!(
        authenticator.authorize(AuthMode::Enforce, Some("fake-current"), &paused, now()),
        Err(AuthError::Unauthorized)
    );

    let observed = authenticator
        .authorize(AuthMode::Observe, Some("fake-unknown"), &snapshot, now())
        .unwrap();
    assert!(observed.allowed);
    assert!(observed.observed_failure);

    assert_eq!(
        authenticator.authorize(
            AuthMode::Enforce,
            Some("fake-current"),
            &CredentialSnapshot::Unavailable,
            now()
        ),
        Err(AuthError::CredentialStoreUnavailable)
    );
    assert!(
        authenticator
            .authorize(AuthMode::Off, None, &CredentialSnapshot::Unavailable, now())
            .unwrap()
            .allowed
    );
}

#[test]
fn environment_auth_mode_is_validated_and_locks_the_ui_setting() {
    let source = r#"
        [server]
        bind = "127.0.0.1:8080"
        [auth]
        mode = "observe"
        [storage]
        database_path = "data/llmap.db"
        master_key_env = "LLMAP_MASTER_KEY"
        [admin]
        username = "admin"
        bootstrap_password_env = "LLMAP_ADMIN_PASSWORD"
    "#;
    let environment = BTreeMap::from([("LLMAP_AUTH_MODE".into(), "enforce".into())]);

    let config = Config::from_toml_with_env(source, &environment).unwrap();

    assert_eq!(config.auth.mode, AuthMode::Enforce);
    assert!(config.auth.mode_locked_by_environment);
    config.validate().unwrap();
}

fn account(id: &str, load: u16) -> RouteAccount {
    RouteAccount {
        id: id.into(),
        provider: "anthropic".into(),
        enabled: true,
        healthy: true,
        in_flight: 0,
        utilization_basis_points: load,
        models: HashSet::from(["claude-sonnet-4-5".into()]),
        depleted_until: None,
    }
}

#[test]
fn routing_is_least_loaded_then_sticky_and_evicts_bad_accounts() {
    let mut router = Router::new(vec![account("busy", 8000), account("quiet", 1000)]);
    let request = RouteRequest {
        session_id: Some("agent-session-42".into()),
        model: "claude-sonnet-4-5".into(),
    };

    let first = router.choose(&request, now()).unwrap();
    assert_eq!(first.account_id, "quiet");
    assert!(!first.reused_session);

    let second = router.choose(&request, now()).unwrap();
    assert_eq!(second.account_id, "quiet");
    assert!(second.reused_session);

    router
        .record_outcome("quiet", UpstreamOutcome::Unauthorized)
        .unwrap();
    let replacement = router.choose(&request, now()).unwrap();
    assert_eq!(replacement.account_id, "busy");
    assert!(!replacement.reused_session);
}

#[test]
fn retries_stop_at_the_first_irreversible_streaming_boundary() {
    assert_eq!(
        retry_decision(UpstreamOutcome::TransientFailure, false, false),
        RetryDecision::RetryAnotherAccount
    );
    assert_eq!(
        retry_decision(UpstreamOutcome::TransientFailure, true, false),
        RetryDecision::ReturnFailure
    );
    assert_eq!(
        retry_decision(UpstreamOutcome::TransientFailure, false, true),
        RetryDecision::ReturnFailure
    );
}

#[test]
fn proxy_chains_are_sticky_ordered_and_never_fall_back_to_direct() {
    let first = ProxyEndpoint::parse("socks5h://fake-user:fake-pass@res-a.invalid:1080").unwrap();
    let second = ProxyEndpoint::parse("https://res-b.invalid:8443").unwrap();
    assert_eq!(first.redacted_authority(), "socks5h://res-a.invalid:1080");
    assert!(!format!("{first:?}").contains("fake-pass"));

    let mut chain = ProxyChain::new(vec![first, second]).unwrap();
    assert_eq!(chain.active_index(), 0);
    chain.record_failure();
    chain.record_failure();
    assert_eq!(chain.active_index(), 0);
    chain.record_failure();
    assert_eq!(chain.active_index(), 1);
    chain.record_success();
    assert_eq!(chain.active_index(), 1);
    assert_eq!(
        ProxyChain::new(vec![]).unwrap_err(),
        EgressError::EmptyProxyChain
    );
}

#[test]
fn forward_destination_policy_denies_ssrf_targets() {
    let policy = DestinationPolicy::new(
        vec!["api.anthropic.com".into(), "*.amazonaws.com".into()],
        false,
    );

    policy
        .authorize(&Url::parse("https://api.anthropic.com/v1/messages").unwrap())
        .unwrap();
    policy
        .authorize(&Url::parse("https://bedrock-runtime.eu-north-1.amazonaws.com").unwrap())
        .unwrap();
    assert_eq!(
        policy.authorize(&Url::parse("http://169.254.169.254/latest/meta-data").unwrap()),
        Err(EgressError::UnsafeDestination)
    );
    assert_eq!(
        policy.authorize(&Url::parse("https://example.com").unwrap()),
        Err(EgressError::DestinationNotAllowed)
    );
}
