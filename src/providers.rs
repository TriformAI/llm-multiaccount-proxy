use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
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

    pub(crate) fn into_headers(self) -> BTreeMap<String, Zeroizing<String>> {
        self.headers
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
    if !path_and_query.starts_with('/') || path_and_query.starts_with("//") {
        return Err(ProviderError::InvalidPath);
    }
    let url = account
        .base_url
        .join(path_and_query)
        .map_err(|_| ProviderError::InvalidPath)?;
    if url.origin() != account.base_url.origin() {
        return Err(ProviderError::InvalidPath);
    }

    let upstream_model = account
        .model_map
        .get(requested_model)
        .cloned()
        .unwrap_or_else(|| requested_model.to_owned());
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
        ProviderKind::BedrockSigV4 => return Err(ProviderError::AwsSigningRequired),
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
