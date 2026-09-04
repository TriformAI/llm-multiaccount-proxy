use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use http_body_util::BodyExt;
use llmap::admin::{AdminSessionManager, SessionPolicy};
use llmap::auth::{AuthMode, Authenticator};
use llmap::config::Config;
use llmap::data_plane::{
    DataPlane, TransportError, UpstreamRequest, UpstreamResponse, UpstreamTransport,
};
use llmap::http_app::{AdminRuntimeConfig, application_router};
use llmap::routing::Router as AccountRouter;
use llmap::secrets::{AdminPasswordHash, SecretBox, SecretInput};
use llmap::storage::SqliteStore;
use tower::ServiceExt;

struct UnusedTransport;

#[async_trait]
impl UpstreamTransport for UnusedTransport {
    async fn send(&self, _request: UpstreamRequest) -> Result<UpstreamResponse, TransportError> {
        panic!("admin contract must not reach an upstream")
    }
}

fn configured() -> Config {
    Config::from_toml_with_env(
        r#"
            [server]
            bind = "127.0.0.1:8080"
            max_request_bytes = 33554432

            [forward_proxy]
            enabled = true
            bind = "127.0.0.1:8081"
            ca_cert_path = "state/llmap-ca.pem"
            ca_key_path = "state/llmap-ca-key.pem"
            allowed_hosts = ["api.anthropic.com", "bedrock-runtime.*.amazonaws.com"]

            [auth]
            mode = "enforce"

            [storage]
            database_path = "state/llmap.db"
            master_key_env = "LLMAP_MASTER_KEY"

            [admin]
            username = "operator"
            bootstrap_password_env = "LLMAP_ADMIN_PASSWORD"
            secure_cookies = false

            [telemetry]
            audit_retention_days = 30
        "#,
        &BTreeMap::new(),
    )
    .unwrap()
}

#[test]
fn complete_runtime_config_validates_both_proxy_surfaces() {
    let config = configured();

    assert_eq!(config.auth.mode, AuthMode::Enforce);
    assert!(config.forward_proxy.enabled);
    assert_eq!(config.server.max_request_bytes, 32 * 1024 * 1024);
    assert_eq!(config.telemetry.audit_retention_days, 30);
}

#[tokio::test]
async fn branded_admin_session_can_create_a_redacted_routable_account() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        SqliteStore::open(&directory.path().join("llmap.db"), SecretBox::new([61; 32])).unwrap(),
    );
    let data_plane = Arc::new(DataPlane::new(
        AuthMode::Enforce,
        Authenticator::new([62; 32]),
        store.clone(),
        AccountRouter::new(Vec::new()),
        Arc::new(UnusedTransport),
        32 * 1024 * 1024,
    ));
    let sessions = Arc::new(AdminSessionManager::new(
        "operator",
        AdminPasswordHash::create(&SecretInput::new("fake-admin-password")).unwrap(),
        [63; 32],
        SessionPolicy::default(),
    ));
    let app = application_router(
        data_plane,
        store.clone(),
        sessions,
        AdminRuntimeConfig {
            auth_mode: AuthMode::Enforce,
            auth_mode_locked: false,
            secure_cookies: false,
        },
    );

    let login = app
        .clone()
        .oneshot(
            Request::post("/admin/api/v1/login")
                .extension(ConnectInfo("127.0.0.1:40000".parse().unwrap()))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"operator","password":"fake-admin-password"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = login
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();

    let session = app
        .clone()
        .oneshot(
            Request::get("/admin/api/v1/session")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session.status(), StatusCode::OK);
    let session_json: serde_json::Value =
        serde_json::from_slice(&session.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let csrf = session_json["csrf_token"].as_str().unwrap();
    assert_eq!(session_json["auth_mode"], "enforce");

    let create = app
        .clone()
        .oneshot(
            Request::post("/admin/api/v1/accounts")
                .header("content-type", "application/json")
                .header("cookie", &cookie)
                .header("x-llmap-csrf", csrf)
                .body(Body::from(
                    r#"{
                        "id":"primary",
                        "label":"Primary Claude",
                        "kind":"anthropic_api_key",
                        "base_url":"https://api.anthropic.com/",
                        "enabled":true,
                        "model_map":{"claude-default":"claude-sonnet-4-5"},
                        "egress_proxies":["socks5h://fake-user:fake-pass@residential.invalid:1080"],
                        "compatible_auth_header":null,
                        "compatible_auth_prefix":null,
                        "credential":"fake-provider-token"
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);

    let rotate = app
        .clone()
        .oneshot(
            Request::put("/admin/api/v1/accounts/primary/credential")
                .header("content-type", "application/json")
                .header("cookie", &cookie)
                .header("x-llmap-csrf", csrf)
                .body(Body::from(r#"{"credential":"fake-rotated-token"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rotate.status(), StatusCode::NO_CONTENT);
    let (rotated_account, rotated_credential) = store.load_account("primary").unwrap();
    assert_eq!(rotated_credential.expose(), "fake-rotated-token");
    assert_eq!(
        rotated_account.egress_proxies,
        vec!["socks5h://fake-user:fake-pass@residential.invalid:1080"]
    );

    let list = app
        .oneshot(
            Request::get("/admin/api/v1/accounts")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let body = list.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("Primary Claude"));
    assert!(text.contains("socks5h://residential.invalid:1080"));
    assert!(!text.contains("fake-provider-token"));
    assert!(!text.contains("fake-rotated-token"));
    assert!(!text.contains("fake-pass"));

    // Use the imported timestamp to keep the contract fixed to an async runtime.
    assert!(Utc::now().timestamp() > 0);
}
