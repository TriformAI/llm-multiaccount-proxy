use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    Off,
    #[default]
    Observe,
    Enforce,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialVersion {
    pub(crate) digest: [u8; 32],
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountCredential {
    pub account_id: String,
    pub active: bool,
    pub current: CredentialVersion,
    pub previous: Vec<CredentialVersion>,
}

impl AccountCredential {
    pub fn active(
        _authenticator: &Authenticator,
        _account_id: impl Into<String>,
        _token: &str,
    ) -> Self {
        unimplemented!("RED: credential construction")
    }

    pub fn with_previous(
        self,
        _authenticator: &Authenticator,
        _token: &str,
        _expires_at: DateTime<Utc>,
    ) -> Self {
        unimplemented!("RED: credential rotation")
    }

    pub fn paused(mut self) -> Self {
        self.active = false;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialSnapshot {
    Available(Vec<AccountCredential>),
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthDecision {
    pub allowed: bool,
    pub observed_failure: bool,
    pub matched_account_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthError {
    #[error("client authentication failed")]
    Unauthorized,
    #[error("credential store is unavailable")]
    CredentialStoreUnavailable,
}

#[derive(Clone)]
pub struct Authenticator {
    digest_key: [u8; 32],
}

impl Authenticator {
    pub fn new(digest_key: [u8; 32]) -> Self {
        Self { digest_key }
    }

    pub fn authorize(
        &self,
        _mode: AuthMode,
        _presented_token: Option<&str>,
        _snapshot: &CredentialSnapshot,
        _now: DateTime<Utc>,
    ) -> Result<AuthDecision, AuthError> {
        let _ = self.digest_key;
        unimplemented!("RED: configurable client authentication")
    }
}
