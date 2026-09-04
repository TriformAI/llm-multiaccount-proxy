use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body as AxumBody;
use futures_util::{Stream, StreamExt};
use http_body_util::BodyExt;
use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::hyper::{Method, Request, Response, StatusCode};
use hudsucker::rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use hudsucker::rustls::crypto::aws_lc_rs;
use hudsucker::{Body, HttpContext, HttpHandler, Proxy, RequestOrResponse};
use parking_lot::Mutex;
use thiserror::Error;
use url::Url;

use crate::data_plane::{DataPlane, ProxyRequest};
use crate::egress::DestinationPolicy;

#[derive(Debug, Error)]
pub enum ForwardProxyError {
    #[error("certificate authority files already exist")]
    AlreadyExists,
    #[error("certificate authority operation failed: {0}")]
    Certificate(String),
    #[error("forward proxy I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("forward proxy address is invalid: {0}")]
    InvalidAddress(#[from] std::net::AddrParseError),
    #[error("forward proxy failed: {0}")]
    Proxy(#[from] hudsucker::Error),
}

#[derive(Clone)]
pub struct ForwardProxyHandler {
    data_plane: Arc<DataPlane>,
    destination_policy: DestinationPolicy,
    max_request_bytes: usize,
}

impl ForwardProxyHandler {
    pub fn new(
        data_plane: Arc<DataPlane>,
        destination_policy: DestinationPolicy,
        max_request_bytes: usize,
    ) -> Self {
        Self {
            data_plane,
            destination_policy,
            max_request_bytes,
        }
    }

    fn authorize_uri(&self, request: &Request<Body>) -> Result<(), ()> {
        let destination = if request.method() == Method::CONNECT {
            let authority = request.uri().authority().ok_or(())?;
            Url::parse(&format!("https://{authority}/")).map_err(|_| ())?
        } else {
            Url::parse(&request.uri().to_string()).map_err(|_| ())?
        };
        self.destination_policy
            .authorize(&destination)
            .map_err(|_| ())
    }

    async fn proxy(&self, request: Request<Body>) -> Response<Body> {
        let (parts, body) = request.into_parts();
        let collected = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                return forward_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_body",
                    "The forward-proxy request body could not be read.",
                );
            }
        };
        if collected.len() > self.max_request_bytes {
            return forward_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "The request exceeds the configured body limit.",
            );
        }
        let path_and_query = parts
            .uri
            .path_and_query()
            .map(ToString::to_string)
            .unwrap_or_else(|| "/".into());
        match self
            .data_plane
            .handle(ProxyRequest {
                method: parts.method,
                path_and_query,
                session_from_path: None,
                headers: parts.headers,
                body: collected,
            })
            .await
        {
            Ok(upstream) => {
                let mut response = Response::new(streaming_body(upstream.body));
                *response.status_mut() = upstream.status;
                *response.headers_mut() = upstream.headers;
                response
            }
            Err(error) => forward_error(error.status(), "proxy_request_failed", &error.to_string()),
        }
    }
}

impl HttpHandler for ForwardProxyHandler {
    fn handle_request(
        &mut self,
        _context: &HttpContext,
        request: Request<Body>,
    ) -> impl Future<Output = RequestOrResponse> + Send {
        let handler = self.clone();
        async move {
            if handler.authorize_uri(&request).is_err() {
                return forward_error(
                    StatusCode::FORBIDDEN,
                    "destination_denied",
                    "The requested forward-proxy destination is not allowed.",
                )
                .into();
            }
            if request.method() == Method::CONNECT {
                return request.into();
            }
            handler.proxy(request).await.into()
        }
    }
}

pub fn generate_ca(cert_path: &Path, key_path: &Path) -> Result<(), ForwardProxyError> {
    if cert_path.exists() || key_path.exists() {
        return Err(ForwardProxyError::AlreadyExists);
    }
    create_parent(cert_path)?;
    create_parent(key_path)?;

    let signing_key =
        KeyPair::generate().map_err(|error| ForwardProxyError::Certificate(error.to_string()))?;
    let mut params = CertificateParams::default();
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "LLM Multiaccount Proxy Local Root");
    distinguished_name.push(DnType::OrganizationName, "Triform");
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let certificate = params
        .self_signed(&signing_key)
        .map_err(|error| ForwardProxyError::Certificate(error.to_string()))?;

    write_new(key_path, signing_key.serialize_pem().as_bytes(), true)?;
    if let Err(error) = write_new(cert_path, certificate.pem().as_bytes(), false) {
        let _ = std::fs::remove_file(key_path);
        return Err(error);
    }
    Ok(())
}

pub fn load_ca(cert_path: &Path, key_path: &Path) -> Result<RcgenAuthority, ForwardProxyError> {
    let cert_pem = std::fs::read_to_string(cert_path)?;
    let key_pem = std::fs::read_to_string(key_path)?;
    let key_pair = KeyPair::from_pem(&key_pem)
        .map_err(|error| ForwardProxyError::Certificate(error.to_string()))?;
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)
        .map_err(|error| ForwardProxyError::Certificate(error.to_string()))?;
    Ok(RcgenAuthority::new(
        issuer,
        1_000,
        aws_lc_rs::default_provider(),
    ))
}

pub async fn serve_forward_proxy(
    bind: &str,
    cert_path: PathBuf,
    key_path: PathBuf,
    handler: ForwardProxyHandler,
) -> Result<(), ForwardProxyError> {
    let address: SocketAddr = bind.parse()?;
    let authority = load_ca(&cert_path, &key_path)?;
    let proxy = Proxy::builder()
        .with_addr(address)
        .with_ca(authority)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .build()?;
    proxy.start().await?;
    Ok(())
}

fn create_parent(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn write_new(path: &Path, contents: &[u8], private: bool) -> Result<(), ForwardProxyError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn forward_error(status: StatusCode, code: &str, message: &str) -> Response<Body> {
    let payload = serde_json::json!({
        "type": "error",
        "error": {"type": code, "message": message},
        "_suggestion": {"message": "Check client authentication, the destination allowlist, and account health before retrying."}
    })
    .to_string();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .expect("static forward proxy response is valid")
}

type BoxedAxumStream =
    Pin<Box<dyn Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send + 'static>>;

struct SyncBodyStream {
    stream: Arc<Mutex<BoxedAxumStream>>,
}

impl Stream for SyncBodyStream {
    type Item = Result<bytes::Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream.lock().as_mut().poll_next(context)
    }
}

fn streaming_body(body: AxumBody) -> Body {
    let stream = body
        .into_data_stream()
        .map(|item| item.map_err(|error| std::io::Error::other(error.to_string())));
    Body::from_stream(SyncBodyStream {
        stream: Arc::new(Mutex::new(Box::pin(stream))),
    })
}
