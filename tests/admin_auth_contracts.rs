use chrono::{Duration, TimeZone, Utc};
use llmap::admin::{
    ADMIN_SESSION_COOKIE, AdminAuthError, AdminSessionManager, SessionPolicy, login_page,
};
use llmap::secrets::{AdminPasswordHash, SecretInput};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 4, 10, 0, 0).unwrap()
}

fn manager() -> AdminSessionManager {
    AdminSessionManager::new(
        "operator",
        AdminPasswordHash::create(&SecretInput::new("fake-correct-password")).unwrap(),
        [41; 32],
        SessionPolicy::default(),
    )
}

#[test]
fn successful_login_issues_a_hardened_cookie_and_csrf_bound_session() {
    let manager = manager();
    let grant = manager
        .login(
            "operator",
            &SecretInput::new("fake-correct-password"),
            "198.51.100.7",
            now(),
        )
        .unwrap();

    let cookie = grant.cookie(true);
    assert!(cookie.starts_with(&format!("{ADMIN_SESSION_COOKIE}=")));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(cookie.contains("Path=/admin"));
    assert!(!format!("{grant:?}").contains(grant.token()));

    assert_eq!(
        manager.authenticate(grant.token(), None, true, now()),
        Err(AdminAuthError::InvalidCsrf)
    );
    manager
        .authenticate(grant.token(), Some(grant.csrf_token()), true, now())
        .unwrap();
}

#[test]
fn login_attempts_are_bounded_without_revealing_which_field_was_wrong() {
    let manager = manager();
    for attempt in 0..5 {
        let result = manager.login(
            if attempt % 2 == 0 {
                "unknown"
            } else {
                "operator"
            },
            &SecretInput::new("fake-wrong-password"),
            "198.51.100.8",
            now(),
        );
        assert!(matches!(result, Err(AdminAuthError::InvalidCredentials)));
    }
    assert!(matches!(
        manager.login(
            "operator",
            &SecretInput::new("fake-correct-password"),
            "198.51.100.8",
            now(),
        ),
        Err(AdminAuthError::RateLimited)
    ));
    manager
        .login(
            "operator",
            &SecretInput::new("fake-correct-password"),
            "198.51.100.8",
            now() + Duration::minutes(16),
        )
        .unwrap();
}

#[test]
fn sessions_expire_on_idle_and_absolute_boundaries() {
    let manager = manager();
    let idle = manager
        .login(
            "operator",
            &SecretInput::new("fake-correct-password"),
            "198.51.100.9",
            now(),
        )
        .unwrap();
    assert_eq!(
        manager.authenticate(
            idle.token(),
            Some(idle.csrf_token()),
            true,
            now() + Duration::minutes(31),
        ),
        Err(AdminAuthError::InvalidSession)
    );

    let absolute = manager
        .login(
            "operator",
            &SecretInput::new("fake-correct-password"),
            "198.51.100.10",
            now(),
        )
        .unwrap();
    for minutes in (20..(12 * 60)).step_by(20) {
        manager
            .authenticate(
                absolute.token(),
                Some(absolute.csrf_token()),
                true,
                now() + Duration::minutes(minutes),
            )
            .unwrap();
    }
    assert_eq!(
        manager.authenticate(
            absolute.token(),
            Some(absolute.csrf_token()),
            true,
            now() + Duration::hours(12),
        ),
        Err(AdminAuthError::InvalidSession)
    );
}

#[test]
fn login_page_is_product_branded_and_not_basic_auth() {
    let page = login_page();
    assert!(page.contains("LLM Multiaccount Proxy"));
    assert!(page.contains("One endpoint. Every account you control."));
    assert!(page.contains("#7c86ff"));
    assert!(page.contains("autocomplete=\"current-password\""));
    assert!(!page.contains("WWW-Authenticate"));
    assert!(!page.contains("Basic realm"));
}
