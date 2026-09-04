use std::collections::BTreeMap;
use std::fmt;

use axum::body::Body;
use axum::http::Method;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::{Bytes, BytesMut};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::secrets::SecretInput;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    ClaudeOauth,
    AnthropicApiKey,
    BedrockApiKey,
    BedrockSigV4,
    AnthropicCompatible,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderAccount {
    pub id: String,
    pub label: String,
    pub kind: ProviderKind,
    pub base_url: Url,
    pub enabled: bool,
    #[serde(default)]
    pub model_map: BTreeMap<String, String>,
    #[serde(default)]
    pub egress_proxies: Vec<String>,
    pub compatible_auth_header: Option<String>,
    pub compatible_auth_prefix: Option<String>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderError {
    #[error("upstream path must be relative to the configured provider origin")]
    InvalidPath,
    #[error("compatible provider requires a valid authentication header name")]
    InvalidAuthenticationHeader,
    #[error("Bedrock SigV4 requires AWS signing credentials")]
    AwsSigningRequired,
    #[error("Bedrock SigV4 credential envelope is invalid")]
    InvalidAwsCredential,
    #[error("Bedrock event stream frame is invalid")]
    InvalidBedrockFrame,
}

pub struct PreparedProviderRequest {
    pub url: Url,
    pub upstream_model: String,
    headers: BTreeMap<String, Zeroizing<String>>,
}

impl PreparedProviderRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(|value| value.as_str())
    }

    pub(crate) fn into_parts(self) -> (Url, String, BTreeMap<String, Zeroizing<String>>) {
        (self.url, self.upstream_model, self.headers)
    }
}

impl fmt::Debug for PreparedProviderRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedProviderRequest")
            .field("url", &self.url)
            .field("upstream_model", &self.upstream_model)
            .field("headers", &"[REDACTED]")
            .finish()
    }
}

pub fn prepare_request(
    account: &ProviderAccount,
    credential: &SecretInput,
    path_and_query: &str,
    requested_model: &str,
) -> Result<PreparedProviderRequest, ProviderError> {
    prepare_request_for_stream(account, credential, path_and_query, requested_model, false)
}

pub fn prepare_request_for_stream(
    account: &ProviderAccount,
    credential: &SecretInput,
    path_and_query: &str,
    requested_model: &str,
    stream: bool,
) -> Result<PreparedProviderRequest, ProviderError> {
    if !path_and_query.starts_with('/') || path_and_query.starts_with("//") {
        return Err(ProviderError::InvalidPath);
    }
    let upstream_model = account
        .model_map
        .get(requested_model)
        .cloned()
        .unwrap_or_else(|| requested_model.to_owned());
    let url = if matches!(
        account.kind,
        ProviderKind::BedrockApiKey | ProviderKind::BedrockSigV4
    ) && path_and_query
        .split('?')
        .next()
        .is_some_and(|path| path == "/v1/messages")
    {
        bedrock_invoke_url(&account.base_url, &upstream_model, stream)?
    } else {
        account
            .base_url
            .join(path_and_query)
            .map_err(|_| ProviderError::InvalidPath)?
    };
    if url.origin() != account.base_url.origin() {
        return Err(ProviderError::InvalidPath);
    }
    let mut headers = BTreeMap::new();
    match account.kind {
        ProviderKind::ClaudeOauth => {
            headers.insert(
                "authorization".into(),
                Zeroizing::new(format!("Bearer {}", credential.expose())),
            );
            headers.insert(
                "anthropic-beta".into(),
                Zeroizing::new("oauth-2025-04-20".into()),
            );
        }
        ProviderKind::AnthropicApiKey => {
            headers.insert(
                "x-api-key".into(),
                Zeroizing::new(credential.expose().to_owned()),
            );
        }
        ProviderKind::BedrockApiKey => {
            headers.insert(
                "authorization".into(),
                Zeroizing::new(format!("Bearer {}", credential.expose())),
            );
        }
        ProviderKind::BedrockSigV4 => {}
        ProviderKind::AnthropicCompatible => {
            let header = account
                .compatible_auth_header
                .as_deref()
                .filter(|header| valid_header_name(header))
                .ok_or(ProviderError::InvalidAuthenticationHeader)?
                .to_ascii_lowercase();
            let prefix = account
                .compatible_auth_prefix
                .as_deref()
                .unwrap_or_default();
            headers.insert(
                header,
                Zeroizing::new(format!("{prefix}{}", credential.expose())),
            );
        }
    }
    Ok(PreparedProviderRequest {
        url,
        upstream_model,
        headers,
    })
}

pub fn decode_bedrock_frame(frame: &[u8]) -> Result<Bytes, ProviderError> {
    if frame.len() < 16 {
        return Err(ProviderError::InvalidBedrockFrame);
    }
    let total_length = u32::from_be_bytes(
        frame[0..4]
            .try_into()
            .map_err(|_| ProviderError::InvalidBedrockFrame)?,
    ) as usize;
    let headers_length = u32::from_be_bytes(
        frame[4..8]
            .try_into()
            .map_err(|_| ProviderError::InvalidBedrockFrame)?,
    ) as usize;
    if total_length != frame.len()
        || total_length > 16 * 1024 * 1024
        || headers_length > total_length.saturating_sub(16)
    {
        return Err(ProviderError::InvalidBedrockFrame);
    }
    let expected_prelude = u32::from_be_bytes(
        frame[8..12]
            .try_into()
            .map_err(|_| ProviderError::InvalidBedrockFrame)?,
    );
    let expected_message = u32::from_be_bytes(
        frame[total_length - 4..]
            .try_into()
            .map_err(|_| ProviderError::InvalidBedrockFrame)?,
    );
    if crc32fast::hash(&frame[..8]) != expected_prelude
        || crc32fast::hash(&frame[..total_length - 4]) != expected_message
    {
        return Err(ProviderError::InvalidBedrockFrame);
    }
    let payload_start = 12 + headers_length;
    let payload = &frame[payload_start..total_length - 4];
    let envelope: serde_json::Value =
        serde_json::from_slice(payload).map_err(|_| ProviderError::InvalidBedrockFrame)?;
    let encoded = envelope
        .get("bytes")
        .and_then(serde_json::Value::as_str)
        .ok_or(ProviderError::InvalidBedrockFrame)?;
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| ProviderError::InvalidBedrockFrame)?;
    let event: serde_json::Value =
        serde_json::from_slice(&decoded).map_err(|_| ProviderError::InvalidBedrockFrame)?;
    let event_type = event
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or(ProviderError::InvalidBedrockFrame)?;
    Ok(Bytes::from(format!(
        "event: {event_type}\ndata: {}\n\n",
        String::from_utf8_lossy(&decoded)
    )))
}

pub fn translate_bedrock_eventstream(body: Body) -> Body {
    let output = async_stream::try_stream! {
        use futures_util::StreamExt;

        let mut input = body.into_data_stream();
        let mut buffer = BytesMut::new();
        loop {
            while buffer.len() >= 4 {
                let total_length = u32::from_be_bytes(
                    buffer[..4]
                        .try_into()
                        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid Bedrock frame"))?,
                ) as usize;
                if !(16..=16 * 1024 * 1024).contains(&total_length) {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid Bedrock event-stream frame length",
                    ))?;
                }
                if buffer.len() < total_length {
                    break;
                }
                let frame = buffer.split_to(total_length).freeze();
                let sse = decode_bedrock_frame(&frame).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid Bedrock event-stream frame",
                    )
                })?;
                yield sse;
            }
            match input.next().await {
                Some(Ok(chunk)) => buffer.extend_from_slice(&chunk),
                Some(Err(error)) => Err(std::io::Error::other(error.to_string()))?,
                None => break,
            }
        }
        if !buffer.is_empty() {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated Bedrock event stream",
            ))?;
        }
    };
    Body::from_stream(output)
}

pub fn finalize_request_auth(
    account: &ProviderAccount,
    credential: &SecretInput,
    method: &Method,
    body: &[u8],
    now: DateTime<Utc>,
    prepared: &mut PreparedProviderRequest,
) -> Result<(), ProviderError> {
    if account.kind != ProviderKind::BedrockSigV4 {
        return Ok(());
    }
    let credential: AwsCredentialEnvelope = serde_json::from_str(credential.expose())
        .map_err(|_| ProviderError::InvalidAwsCredential)?;
    credential.validate()?;

    let date = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let service = credential.service.as_deref().unwrap_or("bedrock");
    let payload_hash = hex(&Sha256::digest(body));
    let host = canonical_host(&prepared.url)?;

    prepared
        .headers
        .insert("host".into(), Zeroizing::new(host.clone()));
    prepared.headers.insert(
        "x-amz-content-sha256".into(),
        Zeroizing::new(payload_hash.clone()),
    );
    prepared
        .headers
        .insert("x-amz-date".into(), Zeroizing::new(amz_date.clone()));
    if let Some(token) = credential.session_token.as_deref() {
        prepared.headers.insert(
            "x-amz-security-token".into(),
            Zeroizing::new(token.to_owned()),
        );
    }

    let mut signed_header_names = vec!["host", "x-amz-content-sha256", "x-amz-date"];
    if credential.session_token.is_some() {
        signed_header_names.push("x-amz-security-token");
    }
    signed_header_names.sort_unstable();
    let signed_headers = signed_header_names.join(";");
    let canonical_headers = signed_header_names
        .iter()
        .map(|name| {
            let value = prepared
                .headers
                .get(*name)
                .expect("signed header was inserted");
            format!("{name}:{}\n", collapse_whitespace(value.as_str()))
        })
        .collect::<String>();
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        canonical_path(&prepared.url),
        canonical_query(&prepared.url),
        canonical_headers,
        signed_headers,
        payload_hash,
    );
    let scope = format!("{date}/{}/{service}/aws4_request", credential.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );
    let date_key = hmac_sha256(
        format!("AWS4{}", credential.secret_access_key).as_bytes(),
        date.as_bytes(),
    );
    let region_key = hmac_sha256(&date_key, credential.region.as_bytes());
    let service_key = hmac_sha256(&region_key, service.as_bytes());
    let signing_key = hmac_sha256(&service_key, b"aws4_request");
    let signature = hex(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    prepared.headers.insert(
        "authorization".into(),
        Zeroizing::new(format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            credential.access_key_id
        )),
    );
    Ok(())
}

#[derive(Deserialize)]
struct AwsCredentialEnvelope {
    access_key_id: String,
    secret_access_key: String,
    #[serde(default)]
    session_token: Option<String>,
    region: String,
    #[serde(default)]
    service: Option<String>,
}

impl Drop for AwsCredentialEnvelope {
    fn drop(&mut self) {
        self.secret_access_key.zeroize();
        self.session_token.zeroize();
    }
}

impl AwsCredentialEnvelope {
    fn validate(&self) -> Result<(), ProviderError> {
        let identifier = |value: &str| {
            !value.is_empty()
                && value.len() <= 256
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        };
        if !identifier(&self.access_key_id)
            || self.secret_access_key.is_empty()
            || self.secret_access_key.len() > 4096
            || !identifier(&self.region)
            || self
                .service
                .as_deref()
                .is_some_and(|value| !identifier(value))
        {
            return Err(ProviderError::InvalidAwsCredential);
        }
        Ok(())
    }
}

fn bedrock_invoke_url(base: &Url, model: &str, stream: bool) -> Result<Url, ProviderError> {
    if model.is_empty() {
        return Err(ProviderError::InvalidPath);
    }
    let mut url = base.clone();
    url.set_query(None);
    url.set_fragment(None);
    url.path_segments_mut()
        .map_err(|_| ProviderError::InvalidPath)?
        .clear()
        .push("model")
        .push(model)
        .push(if stream {
            "invoke-with-response-stream"
        } else {
            "invoke"
        });
    Ok(url)
}

fn canonical_host(url: &Url) -> Result<String, ProviderError> {
    let host = url.host_str().ok_or(ProviderError::InvalidPath)?;
    Ok(match url.port() {
        Some(port)
            if !((url.scheme() == "https" && port == 443)
                || (url.scheme() == "http" && port == 80)) =>
        {
            format!("{host}:{port}")
        }
        _ => host.to_owned(),
    })
}

fn canonical_path(url: &Url) -> String {
    let path = url.path();
    if path.is_empty() {
        "/".into()
    } else {
        path.to_owned()
    }
}

fn canonical_query(url: &Url) -> String {
    let mut pairs = url
        .query_pairs()
        .map(|(name, value)| (aws_encode(name.as_bytes()), aws_encode(value.as_bytes())))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn aws_encode(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(*byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn hmac_sha256(key: &[u8], value: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(value);
    mac.finalize().into_bytes().into()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn valid_header_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}
