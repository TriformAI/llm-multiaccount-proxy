use std::collections::{BTreeMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use zeroize::Zeroize;

use crate::providers::{ProviderAccount, ProviderKind};
use crate::secrets::SecretInput;
use crate::storage::{SqliteStore, StorageError};

const CLAUDE_TOKEN_ENDPOINT: &str = "https://platform.claude.com/v1/oauth/token";
const CLAUDE_OAUTH_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

pub struct ImportedAccount {
    pub account: ProviderAccount,
    pub credential: SecretInput,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ImportSummary {
    pub imported: usize,
    pub skipped_existing: usize,
}

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("legacy account variable {0} is defined more than once")]
    DuplicateVariable(String),
    #[error("legacy account {0} has no matching name or credential")]
    IncompleteAccount(u16),
    #[error("legacy account {0} contains invalid JSON")]
    InvalidJson(u16),
    #[error("legacy account {0} has invalid or missing provider configuration: {1}")]
    InvalidProvider(u16, String),
    #[error("legacy account file contains no CLAUDE_ACCOUNT_N entries")]
    Empty,
    #[error(transparent)]
    Storage(#[from] StorageError),
}

#[derive(Default)]
struct LegacyEntry {
    name: Option<String>,
    credential: Option<zeroize::Zeroizing<String>>,
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyCredential {
    #[serde(default)]
    paused: bool,
    #[serde(default, rename = "type")]
    provider_type: Option<String>,
    #[serde(default, alias = "api_key")]
    api_key: Option<String>,
    #[serde(default, alias = "base_url")]
    base_url: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default, alias = "model_map", alias = "models")]
    model_map: BTreeMap<String, String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default, alias = "access_key_id")]
    access_key_id: Option<String>,
    #[serde(default, alias = "secret_access_key")]
    secret_access_key: Option<String>,
    #[serde(default, alias = "session_token")]
    session_token: Option<String>,
    #[serde(default)]
    proxy_url: Option<String>,
    #[serde(default, alias = "proxy_urls", alias = "egress_proxies")]
    proxy_urls: Vec<String>,
    #[serde(default)]
    claude_ai_oauth: Option<LegacyOAuth>,
}

impl Drop for LegacyCredential {
    fn drop(&mut self) {
        self.api_key.zeroize();
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
        self.session_token.zeroize();
        self.proxy_url.zeroize();
        self.proxy_urls.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyOAuth {
    access_token: String,
    refresh_token: String,
    expires_at: i64,
    #[serde(default)]
    scopes: Vec<String>,
}

impl Drop for LegacyOAuth {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

#[derive(Serialize)]
struct OAuthEnvelope<'a> {
    access_token: &'a str,
    refresh_token: &'a str,
    expires_at: DateTime<Utc>,
    token_endpoint: &'static str,
    client_id: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

#[derive(Serialize)]
struct AwsEnvelope<'a> {
    access_key_id: &'a str,
    secret_access_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_token: Option<&'a str>,
    region: &'a str,
}

pub fn parse_claudeproxy_env(source: &str) -> Result<Vec<ImportedAccount>, MigrationError> {
    let mut entries = BTreeMap::<u16, LegacyEntry>::new();
    let mut seen = HashSet::new();
    for original_line in source.lines() {
        let line = original_line.trim();
        if line.is_empty() {
            continue;
        }
        let (enabled, line) = match line.strip_prefix('#') {
            Some(commented) => (false, commented.trim_start()),
            None => (true, line),
        };
        if !line.starts_with("CLAUDE_ACCOUNT_") {
            continue;
        }
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let Some((index, is_name)) = account_key(key) else {
            continue;
        };
        if !seen.insert(key.to_owned()) {
            return Err(MigrationError::DuplicateVariable(key.to_owned()));
        }
        let value = unquote(raw_value.trim()).to_owned();
        let entry = entries.entry(index).or_insert_with(|| LegacyEntry {
            enabled,
            ..LegacyEntry::default()
        });
        entry.enabled &= enabled;
        if is_name {
            entry.name = Some(value);
        } else {
            entry.credential = Some(zeroize::Zeroizing::new(value));
        }
    }
    if entries.is_empty() {
        return Err(MigrationError::Empty);
    }

    entries
        .into_iter()
        .map(|(index, entry)| convert_entry(index, entry))
        .collect()
}

pub fn import_claudeproxy_env(
    store: &SqliteStore,
    accounts: Vec<ImportedAccount>,
    replace: bool,
) -> Result<ImportSummary, MigrationError> {
    let existing = store
        .list_accounts()?
        .into_iter()
        .map(|account| account.id)
        .collect::<HashSet<_>>();
    let mut summary = ImportSummary::default();
    for imported in accounts {
        if existing.contains(&imported.account.id) && !replace {
            summary.skipped_existing += 1;
            continue;
        }
        store.upsert_account(&imported.account, &imported.credential)?;
        summary.imported += 1;
    }
    Ok(summary)
}

fn account_key(key: &str) -> Option<(u16, bool)> {
    let suffix = key.strip_prefix("CLAUDE_ACCOUNT_")?;
    let (digits, is_name) = match suffix.strip_suffix("_NAME") {
        Some(digits) => (digits, true),
        None => (suffix, false),
    };
    let index = digits.parse().ok()?;
    (index > 0).then_some((index, is_name))
}

fn unquote(value: &str) -> &str {
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn convert_entry(index: u16, entry: LegacyEntry) -> Result<ImportedAccount, MigrationError> {
    let name = entry
        .name
        .filter(|name| !name.trim().is_empty())
        .ok_or(MigrationError::IncompleteAccount(index))?;
    let credential_json = entry
        .credential
        .ok_or(MigrationError::IncompleteAccount(index))?;
    let credential: LegacyCredential =
        serde_json::from_str(&credential_json).map_err(|_| MigrationError::InvalidJson(index))?;
    convert_credential(index, name, entry.enabled, credential)
}

fn convert_credential(
    index: u16,
    label: String,
    line_enabled: bool,
    legacy: LegacyCredential,
) -> Result<ImportedAccount, MigrationError> {
    let enabled = line_enabled && !legacy.paused;
    let mut model_map = legacy.model_map.clone();
    if let Some(model) = legacy.model.as_deref().filter(|model| !model.is_empty()) {
        model_map
            .entry("default".into())
            .or_insert_with(|| model.into());
    }
    let mut egress_proxies = legacy.proxy_urls.clone();
    if let Some(proxy) = legacy
        .proxy_url
        .as_deref()
        .filter(|proxy| !proxy.is_empty())
    {
        egress_proxies.insert(0, proxy.to_owned());
    }
    let id = format!("claudeproxy-{index}");

    let (kind, base_url, compatible_auth_header, compatible_auth_prefix, secret) =
        if let Some(oauth) = legacy.claude_ai_oauth.as_ref() {
            if oauth.access_token.is_empty() || oauth.refresh_token.is_empty() {
                return Err(MigrationError::InvalidProvider(
                    index,
                    "OAuth access and refresh tokens are required".into(),
                ));
            }
            let expires_at =
                DateTime::from_timestamp_millis(oauth.expires_at).ok_or_else(|| {
                    MigrationError::InvalidProvider(index, "OAuth expiry is invalid".into())
                })?;
            let scope = (!oauth.scopes.is_empty()).then(|| oauth.scopes.join(" "));
            let envelope = OAuthEnvelope {
                access_token: &oauth.access_token,
                refresh_token: &oauth.refresh_token,
                expires_at,
                token_endpoint: CLAUDE_TOKEN_ENDPOINT,
                client_id: CLAUDE_OAUTH_CLIENT_ID,
                scope,
            };
            (
                ProviderKind::ClaudeOauth,
                Url::parse("https://api.anthropic.com/").expect("static URL is valid"),
                None,
                None,
                SecretInput::new(serde_json::to_string(&envelope).map_err(|_| {
                    MigrationError::InvalidProvider(index, "OAuth envelope is invalid".into())
                })?),
            )
        } else {
            convert_api_provider(index, &legacy)?
        };

    Ok(ImportedAccount {
        account: ProviderAccount {
            id,
            label,
            kind,
            base_url,
            enabled,
            model_map,
            egress_proxies,
            compatible_auth_header,
            compatible_auth_prefix,
        },
        credential: secret,
    })
}

#[allow(clippy::type_complexity)]
fn convert_api_provider(
    index: u16,
    legacy: &LegacyCredential,
) -> Result<
    (
        ProviderKind,
        Url,
        Option<String>,
        Option<String>,
        SecretInput,
    ),
    MigrationError,
> {
    let provider_type = legacy
        .provider_type
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if provider_type == "bedrock" {
        let region = legacy.region.as_deref().unwrap_or("us-east-1");
        if region.is_empty()
            || !region
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(MigrationError::InvalidProvider(
                index,
                "Bedrock region is invalid".into(),
            ));
        }
        let base_url = Url::parse(&format!("https://bedrock-runtime.{region}.amazonaws.com/"))
            .map_err(|_| MigrationError::InvalidProvider(index, "Bedrock URL is invalid".into()))?;
        if let (Some(access_key_id), Some(secret_access_key)) = (
            legacy.access_key_id.as_deref(),
            legacy.secret_access_key.as_deref(),
        ) {
            let envelope = AwsEnvelope {
                access_key_id,
                secret_access_key,
                session_token: legacy.session_token.as_deref(),
                region,
            };
            return Ok((
                ProviderKind::BedrockSigV4,
                base_url,
                None,
                None,
                SecretInput::new(serde_json::to_string(&envelope).map_err(|_| {
                    MigrationError::InvalidProvider(index, "AWS envelope is invalid".into())
                })?),
            ));
        }
        let api_key = legacy
            .api_key
            .as_deref()
            .filter(|key| !key.is_empty())
            .ok_or_else(|| {
                MigrationError::InvalidProvider(index, "Bedrock credentials are missing".into())
            })?;
        return Ok((
            ProviderKind::BedrockApiKey,
            base_url,
            None,
            None,
            SecretInput::new(api_key),
        ));
    }

    let api_key = legacy
        .api_key
        .as_deref()
        .filter(|key| !key.is_empty())
        .ok_or_else(|| MigrationError::InvalidProvider(index, "API key is missing".into()))?;
    let mut base_url = Url::parse(
        legacy
            .base_url
            .as_deref()
            .ok_or_else(|| MigrationError::InvalidProvider(index, "base URL is missing".into()))?,
    )
    .map_err(|_| MigrationError::InvalidProvider(index, "base URL is invalid".into()))?;
    if base_url.scheme() != "https" || base_url.host_str().is_none() {
        return Err(MigrationError::InvalidProvider(
            index,
            "base URL must use HTTPS".into(),
        ));
    }
    let official_anthropic = provider_type == "anthropic"
        || provider_type == "claude-api"
        || base_url.host_str() == Some("api.anthropic.com");
    if official_anthropic {
        return Ok((
            ProviderKind::AnthropicApiKey,
            base_url,
            None,
            None,
            SecretInput::new(api_key),
        ));
    }
    let path = base_url.path().trim_end_matches('/').to_owned();
    if !path.ends_with("/anthropic") {
        base_url.set_path(&format!("{path}/anthropic/"));
    }
    Ok((
        ProviderKind::AnthropicCompatible,
        base_url,
        Some("authorization".into()),
        Some("Bearer ".into()),
        SecretInput::new(api_key),
    ))
}
