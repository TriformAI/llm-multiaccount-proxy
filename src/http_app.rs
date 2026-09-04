use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{any, delete, get, post, put};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use crate::admin::{AdminAuthError, AdminSessionManager, dashboard_page, login_page};
use crate::auth::AuthMode;
use crate::data_plane::{DataPlane, DataPlaneError, ProxyRequest};
use crate::egress::ProxyEndpoint;
use crate::providers::{ProviderAccount, ProviderKind};
use crate::secrets::SecretInput;
use crate::storage::{AuditEvent, SqliteStore, StorageError};

#[derive(Clone, Copy, Debug)]
pub struct AdminRuntimeConfig {
    pub auth_mode: AuthMode,
    pub auth_mode_locked: bool,
    pub secure_cookies: bool,
}

#[derive(Clone)]
struct AdminState {
    data_plane: Arc<DataPlane>,
    store: Arc<SqliteStore>,
    sessions: Arc<AdminSessionManager>,
    runtime: AdminRuntimeConfig,
}

pub fn router(data_plane: Arc<DataPlane>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/v1", any(proxy_root))
        .route("/v1/{*path}", any(proxy_v1))
        .route("/session/{session_id}/v1", any(proxy_session_root))
        .route("/session/{session_id}/v1/{*path}", any(proxy_session_v1))
        .with_state(data_plane)
}

pub fn application_router(
    data_plane: Arc<DataPlane>,
    store: Arc<SqliteStore>,
    sessions: Arc<AdminSessionManager>,
    runtime: AdminRuntimeConfig,
) -> Router {
    let admin_state = AdminState {
        data_plane: data_plane.clone(),
        store,
        sessions,
        runtime,
    };
    let admin = Router::new()
        .route("/admin", get(admin_redirect))
        .route("/admin/", get(admin_dashboard))
        .route("/admin/login", get(admin_login))
        .route("/admin/api/v1/login", post(admin_login_api))
        .route("/admin/api/v1/logout", post(admin_logout_api))
        .route("/admin/api/v1/session", get(admin_session_api))
        .route(
            "/admin/api/v1/accounts",
            get(admin_accounts_api).post(admin_create_account_api),
        )
        .route(
            "/admin/api/v1/accounts/{account_id}",
            delete(admin_delete_account_api),
        )
        .route(
            "/admin/api/v1/accounts/{account_id}/enabled",
            put(admin_set_account_enabled_api),
        )
        .route(
            "/admin/api/v1/accounts/{account_id}/credential",
            put(admin_rotate_account_credential_api),
        )
        .route("/admin/api/v1/audit", get(admin_audit_api))
        .with_state(admin_state);
    router(data_plane).merge(admin)
}

async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok", "service": "llmap"}))
}

async fn ready() -> impl IntoResponse {
    Json(json!({"status": "ready"}))
}

async fn metrics(State(state): State<Arc<DataPlane>>) -> Response {
    let metrics = state.metrics();
    let body = format!(
        "# TYPE llmap_requests_total counter\nllmap_requests_total {}\n\
         # TYPE llmap_authentication_failures_total counter\nllmap_authentication_failures_total {}\n\
         # TYPE llmap_upstream_failures_total counter\nllmap_upstream_failures_total {}\n\
         # TYPE llmap_responses_total counter\nllmap_responses_total {}\n",
        metrics.requests_total,
        metrics.authentication_failures_total,
        metrics.upstream_failures_total,
        metrics.responses_total,
    );
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

async fn admin_redirect() -> Redirect {
    Redirect::permanent("/admin/")
}

async fn admin_login() -> Html<&'static str> {
    Html(login_page())
}

async fn admin_dashboard(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    match authenticated_session(&state, &headers, false) {
        Ok(_) => Html(dashboard_page()).into_response(),
        Err(_) => Redirect::to("/admin/login").into_response(),
    }
}

#[derive(Deserialize)]
struct LoginInput {
    username: String,
    password: String,
}

async fn admin_login_api(
    peer: Option<ConnectInfo<std::net::SocketAddr>>,
    State(state): State<AdminState>,
    Json(input): Json<LoginInput>,
) -> Response {
    let client_key = peer
        .map(|ConnectInfo(address)| address.ip().to_string())
        .unwrap_or_else(|| "direct-router-test".into());
    let password = SecretInput::new(input.password);
    match state
        .sessions
        .login(&input.username, &password, &client_key, Utc::now())
    {
        Ok(grant) => {
            let mut response = Json(json!({"status": "ok"})).into_response();
            let cookie = match HeaderValue::from_str(&grant.cookie(state.runtime.secure_cookies)) {
                Ok(cookie) => cookie,
                Err(_) => {
                    return api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "session_creation_failed",
                        "Administrator session could not be created.",
                        "Retry the login. If this persists, restart llmap and inspect metadata-only logs.",
                    );
                }
            };
            response.headers_mut().insert(header::SET_COOKIE, cookie);
            response
        }
        Err(AdminAuthError::RateLimited) => api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "login_rate_limited",
            "Too many failed administrator login attempts.",
            "Wait for the lockout period before trying again.",
        ),
        Err(_) => api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_admin_credentials",
            "Administrator credentials were not accepted.",
            "Verify the configured administrator username and bootstrap password.",
        ),
    }
}

async fn admin_logout_api(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let session = match authenticated_session(&state, &headers, true) {
        Ok(session) => session,
        Err(response) => return response,
    };
    state.sessions.logout(&session);
    let mut response = StatusCode::NO_CONTENT.into_response();
    let secure = if state.runtime.secure_cookies {
        "; Secure"
    } else {
        ""
    };
    if let Ok(cookie) = HeaderValue::from_str(&format!(
        "llmap_admin_session=; Path=/admin; Max-Age=0; HttpOnly; SameSite=Strict{secure}"
    )) {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    response
}

async fn admin_session_api(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let session = match authenticated_session(&state, &headers, false) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let csrf = match state.sessions.issue_csrf(&session, Utc::now()) {
        Ok(csrf) => csrf,
        Err(_) => return unauthorized_admin(),
    };
    Json(json!({
        "csrf_token": csrf.expose(),
        "auth_mode": state.runtime.auth_mode,
        "auth_mode_locked": state.runtime.auth_mode_locked,
        "active_sessions": state.sessions.active_session_count(Utc::now()),
        "sticky_sessions": state.data_plane.sticky_session_count().await,
    }))
    .into_response()
}

async fn admin_accounts_api(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    if let Err(response) = authenticated_session(&state, &headers, false) {
        return response;
    }
    match state.store.list_accounts() {
        Ok(accounts) => Json(accounts).into_response(),
        Err(error) => storage_error(error),
    }
}

#[derive(Deserialize)]
struct AccountInput {
    id: String,
    label: String,
    kind: ProviderKind,
    base_url: url::Url,
    enabled: bool,
    #[serde(default)]
    model_map: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    egress_proxies: Vec<String>,
    compatible_auth_header: Option<String>,
    compatible_auth_prefix: Option<String>,
    credential: String,
}

async fn admin_create_account_api(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(input): Json<AccountInput>,
) -> Response {
    if let Err(response) = authenticated_session(&state, &headers, true) {
        return response;
    }
    if let Err(message) = validate_account_input(&input) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_account",
            &message,
            "Correct the account fields and retry. Credentials and proxy userinfo are write-only.",
        );
    }
    let account = ProviderAccount {
        id: input.id,
        label: input.label,
        kind: input.kind,
        base_url: input.base_url,
        enabled: input.enabled,
        model_map: input.model_map,
        egress_proxies: input.egress_proxies,
        compatible_auth_header: input.compatible_auth_header,
        compatible_auth_prefix: input.compatible_auth_prefix,
    };
    let credential = SecretInput::new(input.credential);
    let result = if account.kind == ProviderKind::ClaudeOauth
        && state.store.load_account(&account.id).is_ok()
    {
        state.store.rotate_account_credential(
            &account,
            &credential,
            Utc::now() + chrono::Duration::minutes(10),
        )
    } else {
        state.store.upsert_account(&account, &credential)
    };
    if let Err(error) = result {
        return storage_error(error);
    }
    let _ = state.store.append_audit(&AuditEvent {
        occurred_at: Utc::now(),
        actor: "admin".into(),
        action: "account.upsert".into(),
        account_id: Some(account.id.clone()),
        provider: Some(provider_name(&account.kind)),
        model: None,
        session_id: None,
        status: Some(StatusCode::CREATED.as_u16()),
        outcome: "success".into(),
        latency_ms: None,
    });
    if let Err(error) = refresh_routes(&state).await {
        return storage_error(error);
    }
    (StatusCode::CREATED, Json(json!({"id": account.id}))).into_response()
}

#[derive(Deserialize)]
struct EnabledInput {
    enabled: bool,
}

#[derive(Deserialize)]
struct CredentialInput {
    credential: String,
}

async fn admin_rotate_account_credential_api(
    State(state): State<AdminState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<CredentialInput>,
) -> Response {
    if let Err(response) = authenticated_session(&state, &headers, true) {
        return response;
    }
    if input.credential.is_empty() || input.credential.len() > 32 * 1024 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_credential",
            "Credential must be present and no larger than 32 KiB.",
            "Paste the complete provider credential or OAuth envelope and retry.",
        );
    }
    let (account, _) = match state.store.load_account(&account_id) {
        Ok(account) => account,
        Err(error) => return storage_error(error),
    };
    let credential = SecretInput::new(input.credential);
    let result = if account.kind == ProviderKind::ClaudeOauth {
        state.store.rotate_account_credential(
            &account,
            &credential,
            Utc::now() + chrono::Duration::minutes(10),
        )
    } else {
        state.store.upsert_account(&account, &credential)
    };
    if let Err(error) = result {
        return storage_error(error);
    }
    let _ = state.store.append_audit(&AuditEvent {
        occurred_at: Utc::now(),
        actor: "admin".into(),
        action: "account.credential.rotate".into(),
        account_id: Some(account_id),
        provider: Some(provider_name(&account.kind)),
        model: None,
        session_id: None,
        status: Some(StatusCode::NO_CONTENT.as_u16()),
        outcome: "success".into(),
        latency_ms: None,
    });
    StatusCode::NO_CONTENT.into_response()
}

async fn admin_set_account_enabled_api(
    State(state): State<AdminState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<EnabledInput>,
) -> Response {
    if let Err(response) = authenticated_session(&state, &headers, true) {
        return response;
    }
    if let Err(error) = state.store.set_account_enabled(&account_id, input.enabled) {
        return storage_error(error);
    }
    let _ = state.store.append_audit(&AuditEvent {
        occurred_at: Utc::now(),
        actor: "admin".into(),
        action: if input.enabled {
            "account.resume".into()
        } else {
            "account.pause".into()
        },
        account_id: Some(account_id),
        provider: None,
        model: None,
        session_id: None,
        status: Some(StatusCode::NO_CONTENT.as_u16()),
        outcome: "success".into(),
        latency_ms: None,
    });
    if let Err(error) = refresh_routes(&state).await {
        return storage_error(error);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn admin_delete_account_api(
    State(state): State<AdminState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authenticated_session(&state, &headers, true) {
        return response;
    }
    if let Err(error) = state.store.delete_account(&account_id) {
        return storage_error(error);
    }
    let _ = state.store.append_audit(&AuditEvent {
        occurred_at: Utc::now(),
        actor: "admin".into(),
        action: "account.delete".into(),
        account_id: Some(account_id),
        provider: None,
        model: None,
        session_id: None,
        status: Some(StatusCode::NO_CONTENT.as_u16()),
        outcome: "success".into(),
        latency_ms: None,
    });
    if let Err(error) = refresh_routes(&state).await {
        return storage_error(error);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn admin_audit_api(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    if let Err(response) = authenticated_session(&state, &headers, false) {
        return response;
    }
    match state.store.recent_audit(200) {
        Ok(events) => Json(events).into_response(),
        Err(error) => storage_error(error),
    }
}

fn authenticated_session(
    state: &AdminState,
    headers: &HeaderMap,
    require_csrf: bool,
) -> Result<String, Response> {
    let session =
        cookie_value(headers, crate::admin::ADMIN_SESSION_COOKIE).ok_or_else(unauthorized_admin)?;
    let csrf = headers
        .get("x-llmap-csrf")
        .and_then(|value| value.to_str().ok());
    state
        .sessions
        .authenticate(&session, csrf, require_csrf, Utc::now())
        .map_err(|error| match error {
            AdminAuthError::InvalidCsrf => api_error(
                StatusCode::FORBIDDEN,
                "invalid_csrf",
                "The administrator request did not include the current CSRF token.",
                "Reload the control plane and retry the operation.",
            ),
            _ => unauthorized_admin(),
        })?;
    Ok(session)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(cookie_name, value)| (cookie_name == name).then(|| value.to_owned()))
}

fn validate_account_input(input: &AccountInput) -> Result<(), String> {
    let valid_id = !input.id.is_empty()
        && input.id.len() <= 64
        && input
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if !valid_id {
        return Err("Account id must be 1-64 letters, digits, hyphens, or underscores.".into());
    }
    if input.label.trim().is_empty() || input.label.len() > 80 {
        return Err("Account display name must be 1-80 characters.".into());
    }
    if input.base_url.scheme() != "https"
        || input.base_url.host_str().is_none()
        || !input.base_url.username().is_empty()
        || input.base_url.password().is_some()
    {
        return Err("Provider base URL must be HTTPS and must not contain userinfo.".into());
    }
    if input.credential.is_empty() || input.credential.len() > 32 * 1024 {
        return Err("Credential must be present and no larger than 32 KiB.".into());
    }
    for proxy in &input.egress_proxies {
        ProxyEndpoint::parse(proxy)
            .map_err(|error| format!("Residential proxy endpoint is invalid: {error}."))?;
    }
    Ok(())
}

async fn refresh_routes(state: &AdminState) -> Result<(), StorageError> {
    let route_accounts = state.store.route_accounts()?;
    state
        .data_plane
        .replace_route_accounts(route_accounts)
        .await;
    Ok(())
}

fn provider_name(kind: &ProviderKind) -> String {
    match kind {
        ProviderKind::ClaudeOauth => "claude_oauth",
        ProviderKind::AnthropicApiKey => "anthropic_api_key",
        ProviderKind::BedrockApiKey => "bedrock_api_key",
        ProviderKind::BedrockSigV4 => "bedrock_sig_v4",
        ProviderKind::AnthropicCompatible => "anthropic_compatible",
    }
    .into()
}

fn unauthorized_admin() -> Response {
    api_error(
        StatusCode::UNAUTHORIZED,
        "admin_session_required",
        "An active administrator session is required.",
        "Sign in through /admin/login and retry.",
    )
}

fn storage_error(error: StorageError) -> Response {
    let (status, code, suggestion) = match &error {
        StorageError::NotFound => (
            StatusCode::NOT_FOUND,
            "account_not_found",
            "Refresh the account list and retry with an existing account.",
        ),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
            "Retry after the encrypted SQLite store is healthy.",
        ),
    };
    api_error(status, code, &error.to_string(), suggestion)
}

fn api_error(status: StatusCode, code: &str, message: &str, suggestion: &str) -> Response {
    (
        status,
        Json(json!({
            "type": "error",
            "error": {"type": code, "message": message},
            "_suggestion": {"message": suggestion}
        })),
    )
        .into_response()
}

async fn proxy_root(State(state): State<Arc<DataPlane>>, request: Request<Body>) -> Response {
    proxy(state, None, "/v1".into(), request).await
}

async fn proxy_v1(
    State(state): State<Arc<DataPlane>>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> Response {
    proxy(state, None, format!("/v1/{path}"), request).await
}

async fn proxy_session_root(
    State(state): State<Arc<DataPlane>>,
    Path(session_id): Path<String>,
    request: Request<Body>,
) -> Response {
    proxy(state, Some(session_id), "/v1".into(), request).await
}

async fn proxy_session_v1(
    State(state): State<Arc<DataPlane>>,
    Path((session_id, path)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    proxy(state, Some(session_id), format!("/v1/{path}"), request).await
}

async fn proxy(
    state: Arc<DataPlane>,
    session_from_path: Option<String>,
    path: String,
    request: Request<Body>,
) -> Response {
    let (parts, body) = request.into_parts();
    let path_and_query = match parts.uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };
    let body = match to_bytes(body, state.max_request_bytes.saturating_add(1)).await {
        Ok(body) => body,
        Err(_) => {
            return error_response(DataPlaneError::BadRequest(
                "request body could not be read within the configured limit".into(),
            ));
        }
    };
    match state
        .handle(ProxyRequest {
            method: parts.method,
            path_and_query,
            session_from_path,
            headers: parts.headers,
            body,
        })
        .await
    {
        Ok(proxy_response) => {
            let mut response = Response::new(proxy_response.body);
            *response.status_mut() = proxy_response.status;
            *response.headers_mut() = proxy_response.headers;
            response
        }
        Err(error) => error_response(error),
    }
}

fn error_response(error: DataPlaneError) -> Response {
    let status = error.status();
    let code = match &error {
        DataPlaneError::Unauthorized => "authentication_failed",
        DataPlaneError::CredentialStoreUnavailable => "credential_store_unavailable",
        DataPlaneError::BadRequest(_) => "invalid_request",
        DataPlaneError::NoCapacity => "no_eligible_account",
        DataPlaneError::UpstreamUnavailable => "upstream_unavailable",
    };
    let suggestion = match &error {
        DataPlaneError::Unauthorized => {
            "Send a current token from any active account configured on this proxy."
        }
        DataPlaneError::CredentialStoreUnavailable => {
            "Retry after the proxy credential store is healthy."
        }
        DataPlaneError::BadRequest(_) => "Correct the request and retry.",
        DataPlaneError::NoCapacity => {
            "Retry later or enable an account that supports the requested model."
        }
        DataPlaneError::UpstreamUnavailable => {
            "Retry only if the client can prove the request was not already accepted."
        }
    };
    (
        status,
        Json(json!({
            "type": "error",
            "error": {"type": code, "message": error.to_string()},
            "_suggestion": {"message": suggestion}
        })),
    )
        .into_response()
}
