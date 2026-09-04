use std::collections::BTreeMap;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::auth::AuthMode;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub forward_proxy: ForwardProxyConfig,
    pub auth: AuthConfig,
    pub storage: StorageConfig,
    pub admin: AdminConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: String,
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_allowed_hosts")]
    pub allowed_upstream_hosts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardProxyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_forward_bind")]
    pub bind: String,
    #[serde(default = "default_ca_cert_path")]
    pub ca_cert_path: String,
    #[serde(default = "default_ca_key_path")]
    pub ca_key_path: String,
    #[serde(default = "default_allowed_hosts")]
    pub allowed_hosts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub mode: AuthMode,
    #[serde(skip)]
    pub mode_locked_by_environment: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub database_path: String,
    pub master_key_env: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    pub username: String,
    pub bootstrap_password_env: String,
    #[serde(default = "default_secure_cookies")]
    pub secure_cookies: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: u16,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("configuration could not be parsed: {0}")]
    Parse(String),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl Config {
    pub fn from_toml_with_env(
        source: &str,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ConfigError> {
        let mut config: Self =
            toml::from_str(source).map_err(|error| ConfigError::Parse(error.to_string()))?;
        if let Some(mode) = environment.get("LLMAP_AUTH_MODE") {
            config.auth.mode = match mode.trim().to_ascii_lowercase().as_str() {
                "off" => AuthMode::Off,
                "observe" => AuthMode::Observe,
                "enforce" => AuthMode::Enforce,
                _ => {
                    return Err(ConfigError::Invalid(
                        "LLMAP_AUTH_MODE must be off, observe, or enforce".into(),
                    ));
                }
            };
            config.auth.mode_locked_by_environment = true;
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.server
            .bind
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::Invalid("server.bind must be an IP socket address".into()))?;
        if self.server.max_request_bytes == 0 || self.server.max_request_bytes > 256 * 1024 * 1024 {
            return Err(ConfigError::Invalid(
                "server.max_request_bytes must be between 1 and 268435456".into(),
            ));
        }
        if self.server.allowed_upstream_hosts.is_empty()
            || self
                .server
                .allowed_upstream_hosts
                .iter()
                .any(|host| host.trim().is_empty() || host.contains('/') || host.contains(':'))
        {
            return Err(ConfigError::Invalid(
                "server.allowed_upstream_hosts must contain DNS host names without ports".into(),
            ));
        }
        if self.forward_proxy.enabled {
            self.forward_proxy.bind.parse::<SocketAddr>().map_err(|_| {
                ConfigError::Invalid("forward_proxy.bind must be an IP socket address".into())
            })?;
            if self.forward_proxy.bind == self.server.bind {
                return Err(ConfigError::Invalid(
                    "server.bind and forward_proxy.bind must be different".into(),
                ));
            }
            require_value(
                "forward_proxy.ca_cert_path",
                &self.forward_proxy.ca_cert_path,
            )?;
            require_value("forward_proxy.ca_key_path", &self.forward_proxy.ca_key_path)?;
            if self.forward_proxy.allowed_hosts.is_empty()
                || self
                    .forward_proxy
                    .allowed_hosts
                    .iter()
                    .any(|host| host.trim().is_empty() || host.contains('/') || host.contains(':'))
            {
                return Err(ConfigError::Invalid(
                    "forward_proxy.allowed_hosts must contain DNS host names without ports".into(),
                ));
            }
        }
        require_value("storage.database_path", &self.storage.database_path)?;
        require_env_name("storage.master_key_env", &self.storage.master_key_env)?;
        require_value("admin.username", &self.admin.username)?;
        require_env_name(
            "admin.bootstrap_password_env",
            &self.admin.bootstrap_password_env,
        )?;
        if self.storage.master_key_env == self.admin.bootstrap_password_env {
            return Err(ConfigError::Invalid(
                "master key and admin password must use different environment variables".into(),
            ));
        }
        if self.telemetry.audit_retention_days == 0 || self.telemetry.audit_retention_days > 365 {
            return Err(ConfigError::Invalid(
                "telemetry.audit_retention_days must be between 1 and 365".into(),
            ));
        }
        Ok(())
    }
}

impl Default for ForwardProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_forward_bind(),
            ca_cert_path: default_ca_cert_path(),
            ca_key_path: default_ca_key_path(),
            allowed_hosts: default_allowed_hosts(),
        }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            audit_retention_days: default_audit_retention_days(),
        }
    }
}

fn default_max_request_bytes() -> usize {
    32 * 1024 * 1024
}

fn default_forward_bind() -> String {
    "127.0.0.1:8081".into()
}

fn default_ca_cert_path() -> String {
    "state/llmap-ca.pem".into()
}

fn default_ca_key_path() -> String {
    "state/llmap-ca-key.pem".into()
}

fn default_allowed_hosts() -> Vec<String> {
    vec![
        "api.anthropic.com".into(),
        "*.bedrock-runtime.amazonaws.com".into(),
    ]
}

fn default_secure_cookies() -> bool {
    true
}

fn default_audit_retention_days() -> u16 {
    30
}

fn require_value(field: &str, value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::Invalid(format!("{field} cannot be empty")));
    }
    Ok(())
}

fn require_env_name(field: &str, value: &str) -> Result<(), ConfigError> {
    require_value(field, value)?;
    let valid = value
        .chars()
        .enumerate()
        .all(|(index, character)| match character {
            'A'..='Z' | '_' => true,
            '0'..='9' => index > 0,
            _ => false,
        });
    if !valid {
        return Err(ConfigError::Invalid(format!(
            "{field} must name an uppercase environment variable"
        )));
    }
    Ok(())
}
