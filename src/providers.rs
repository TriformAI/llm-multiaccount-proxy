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
    _account: &ProviderAccount,
    _credential: &SecretInput,
    _path_and_query: &str,
    _requested_model: &str,
) -> Result<PreparedProviderRequest, ProviderError> {
    unimplemented!("RED: provider adapter request preparation")
}
