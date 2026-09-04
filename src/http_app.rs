use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::{Path, State};
use axum::http::Request;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use serde_json::json;

use crate::data_plane::{DataPlane, DataPlaneError, ProxyRequest};

pub fn router(data_plane: Arc<DataPlane>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/v1", any(proxy_root))
        .route("/v1/{*path}", any(proxy_v1))
        .route("/session/{session_id}/v1", any(proxy_session_root))
        .route("/session/{session_id}/v1/{*path}", any(proxy_session_v1))
        .with_state(data_plane)
}

async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok", "service": "llmap"}))
}

async fn ready() -> impl IntoResponse {
    Json(json!({"status": "ready"}))
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
