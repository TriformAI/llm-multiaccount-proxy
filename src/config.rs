use std::collections::BTreeMap;

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
        _source: &str,
        _environment: &BTreeMap<String, String>,
    ) -> Result<Self, ConfigError> {
        unimplemented!("RED: configuration loading")
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let _ = self;
        unimplemented!("RED: configuration validation")
    }
}
