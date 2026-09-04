use std::collections::BTreeMap;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::auth::AuthMode;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub storage: StorageConfig,
    pub admin: AdminConfig,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServerConfig {
    pub bind: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthConfig {
    pub mode: AuthMode,
    #[serde(skip)]
    pub mode_locked_by_environment: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageConfig {
    pub database_path: String,
    pub master_key_env: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdminConfig {
    pub username: String,
    pub bootstrap_password_env: String,
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
        Ok(())
    }
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
