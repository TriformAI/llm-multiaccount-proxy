use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
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
        authenticator: &Authenticator,
        account_id: impl Into<String>,
        token: &str,
    ) -> Self {
        Self {
            account_id: account_id.into(),
            active: true,
            current: CredentialVersion {
                digest: authenticator.digest(token),
                expires_at: None,
            },
            previous: Vec::new(),
        }
    }

    pub fn with_previous(
        mut self,
        authenticator: &Authenticator,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Self {
        self.previous.push(CredentialVersion {
            digest: authenticator.digest(token),
            expires_at: Some(expires_at),
        });
        self
    }

    pub fn with_current_expiry(mut self, expires_at: Option<DateTime<Utc>>) -> Self {
        self.current.expires_at = expires_at;
        self
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
        mode: AuthMode,
        presented_token: Option<&str>,
        snapshot: &CredentialSnapshot,
        now: DateTime<Utc>,
    ) -> Result<AuthDecision, AuthError> {
        if mode == AuthMode::Off {
            return Ok(AuthDecision {
                allowed: true,
                observed_failure: false,
                matched_account_id: None,
            });
        }

        let CredentialSnapshot::Available(accounts) = snapshot else {
            return match mode {
                AuthMode::Observe => Ok(AuthDecision {
                    allowed: true,
                    observed_failure: true,
                    matched_account_id: None,
                }),
                AuthMode::Enforce => Err(AuthError::CredentialStoreUnavailable),
                AuthMode::Off => unreachable!("off mode returns before reading the store"),
            };
        };

        // Hash even a missing token and scan every configured digest. This
        // keeps the observable path for missing, unknown, and expired tokens
        // deliberately similar and never compares secret strings directly.
        let presented_digest = self.digest(presented_token.unwrap_or_default());
        let mut matched_account_id = None;
        for account in accounts {
            let current_not_expired = account.current.expires_at.is_none_or(|expiry| expiry > now);
            let current_match = presented_digest.ct_eq(&account.current.digest);
            if account.active && current_not_expired && bool::from(current_match) {
                matched_account_id = Some(account.account_id.clone());
            }
            for previous in &account.previous {
                let not_expired = previous.expires_at.is_none_or(|expiry| expiry > now);
                let previous_match = presented_digest.ct_eq(&previous.digest);
                if account.active && not_expired && bool::from(previous_match) {
                    matched_account_id = Some(account.account_id.clone());
                }
            }
        }

        if matched_account_id.is_some() {
            return Ok(AuthDecision {
                allowed: true,
                observed_failure: false,
                matched_account_id,
            });
        }

        match mode {
            AuthMode::Observe => Ok(AuthDecision {
                allowed: true,
                observed_failure: true,
                matched_account_id: None,
            }),
            AuthMode::Enforce => Err(AuthError::Unauthorized),
            AuthMode::Off => unreachable!("off mode returns before matching"),
        }
    }

    fn digest(&self, token: &str) -> [u8; 32] {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&self.digest_key)
            .expect("HMAC-SHA256 accepts a key of any length");
        mac.update(token.as_bytes());
        mac.finalize().into_bytes().into()
    }

    pub fn metadata_fingerprint(&self, value: &str) -> String {
        use std::fmt::Write as _;

        let digest = self.digest(value);
        let mut fingerprint = String::with_capacity(24);
        for byte in &digest[..12] {
            write!(&mut fingerprint, "{byte:02x}").expect("writing to a String cannot fail");
        }
        fingerprint
    }
}
