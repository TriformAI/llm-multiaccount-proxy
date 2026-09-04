use std::collections::HashMap;
use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::secrets::{AdminPasswordHash, SecretInput};

pub const ADMIN_SESSION_COOKIE: &str = "llmap_admin_session";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionPolicy {
    pub idle_timeout: Duration,
    pub absolute_timeout: Duration,
    pub max_failed_attempts: u8,
    pub lockout_duration: Duration,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::minutes(30),
            absolute_timeout: Duration::hours(12),
            max_failed_attempts: 5,
            lockout_duration: Duration::minutes(15),
        }
    }
}

pub struct SessionGrant {
    token: SecretInput,
    csrf_token: SecretInput,
    pub expires_at: DateTime<Utc>,
    max_age_seconds: i64,
}

impl SessionGrant {
    pub fn token(&self) -> &str {
        self.token.expose()
    }

    pub fn csrf_token(&self) -> &str {
        self.csrf_token.expose()
    }

    pub fn cookie(&self, secure: bool) -> String {
        let secure_attribute = if secure { "; Secure" } else { "" };
        format!(
            "{ADMIN_SESSION_COOKIE}={}; Path=/admin; Max-Age={}; HttpOnly; SameSite=Strict{secure_attribute}",
            self.token.expose(),
            self.max_age_seconds
        )
    }
}

impl fmt::Debug for SessionGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionGrant")
            .field("token", &"[REDACTED]")
            .field("csrf_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("max_age_seconds", &self.max_age_seconds)
            .finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AdminAuthError {
    #[error("invalid administrator credentials")]
    InvalidCredentials,
    #[error("too many failed login attempts")]
    RateLimited,
    #[error("administrator session is invalid or expired")]
    InvalidSession,
    #[error("CSRF token is missing or invalid")]
    InvalidCsrf,
}

struct LoginAttempt {
    failures: u8,
    locked_until: Option<DateTime<Utc>>,
}

struct Session {
    created_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    csrf_digest: [u8; 32],
}

#[derive(Default)]
struct SessionState {
    attempts: HashMap<String, LoginAttempt>,
    sessions: HashMap<[u8; 32], Session>,
}

pub struct AdminSessionManager {
    username: String,
    password_hash: AdminPasswordHash,
    digest_key: [u8; 32],
    policy: SessionPolicy,
    state: Mutex<SessionState>,
}

impl AdminSessionManager {
    pub fn new(
        username: impl Into<String>,
        password_hash: AdminPasswordHash,
        digest_key: [u8; 32],
        policy: SessionPolicy,
    ) -> Self {
        Self {
            username: username.into(),
            password_hash,
            digest_key,
            policy,
            state: Mutex::new(SessionState::default()),
        }
    }

    pub fn login(
        &self,
        username: &str,
        password: &SecretInput,
        client_key: &str,
        now: DateTime<Utc>,
    ) -> Result<SessionGrant, AdminAuthError> {
        let mut state = self.state.lock();
        state.sessions.retain(|_, session| {
            now < session.created_at + self.policy.absolute_timeout
                && now <= session.last_seen_at + self.policy.idle_timeout
        });
        let attempt = state
            .attempts
            .entry(client_key.to_owned())
            .or_insert(LoginAttempt {
                failures: 0,
                locked_until: None,
            });
        if attempt
            .locked_until
            .is_some_and(|locked_until| now < locked_until)
        {
            return Err(AdminAuthError::RateLimited);
        }
        if attempt.locked_until.is_some() {
            attempt.failures = 0;
            attempt.locked_until = None;
        }

        let username_matches = constant_time_text_eq(username, &self.username);
        let password_matches = self.password_hash.verify(password);
        if !(username_matches && password_matches) {
            attempt.failures = attempt.failures.saturating_add(1);
            if attempt.failures >= self.policy.max_failed_attempts {
                attempt.locked_until = Some(now + self.policy.lockout_duration);
            }
            return Err(AdminAuthError::InvalidCredentials);
        }
        state.attempts.remove(client_key);

        let token = random_token();
        let csrf_token = random_token();
        let token_digest = self.digest(token.expose());
        state.sessions.insert(
            token_digest,
            Session {
                created_at: now,
                last_seen_at: now,
                csrf_digest: self.digest(csrf_token.expose()),
            },
        );
        Ok(SessionGrant {
            token,
            csrf_token,
            expires_at: now + self.policy.absolute_timeout,
            max_age_seconds: self.policy.absolute_timeout.num_seconds(),
        })
    }

    pub fn authenticate(
        &self,
        session_token: &str,
        csrf_token: Option<&str>,
        require_csrf: bool,
        now: DateTime<Utc>,
    ) -> Result<(), AdminAuthError> {
        let token_digest = self.digest(session_token);
        let mut state = self.state.lock();
        let Some(session) = state.sessions.get_mut(&token_digest) else {
            return Err(AdminAuthError::InvalidSession);
        };
        let expired = now >= session.created_at + self.policy.absolute_timeout
            || now > session.last_seen_at + self.policy.idle_timeout;
        if expired {
            state.sessions.remove(&token_digest);
            return Err(AdminAuthError::InvalidSession);
        }
        if require_csrf {
            let presented = self.digest(csrf_token.unwrap_or_default());
            if !bool::from(presented.ct_eq(&session.csrf_digest)) {
                return Err(AdminAuthError::InvalidCsrf);
            }
        }
        session.last_seen_at = now;
        Ok(())
    }

    pub fn logout(&self, session_token: &str) {
        self.state
            .lock()
            .sessions
            .remove(&self.digest(session_token));
    }

    fn digest(&self, value: &str) -> [u8; 32] {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&self.digest_key)
            .expect("HMAC-SHA256 accepts a key of any length");
        mac.update(value.as_bytes());
        mac.finalize().into_bytes().into()
    }
}

pub fn login_page() -> &'static str {
    include_str!("admin_login.html")
}

pub fn dashboard_page() -> &'static str {
    unimplemented!("RED: branded account and egress control plane")
}

fn random_token() -> SecretInput {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    bytes.fill(0);
    SecretInput::new(encoded)
}

fn constant_time_text_eq(left: &str, right: &str) -> bool {
    let left_digest = Sha256::digest(left.as_bytes());
    let right_digest = Sha256::digest(right.as_bytes());
    bool::from(left_digest.ct_eq(&right_digest))
}
