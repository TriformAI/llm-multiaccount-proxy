use std::collections::HashSet;
use std::path::Path;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::Connection;
use thiserror::Error;

use crate::auth::{AccountCredential, Authenticator, CredentialSnapshot};
use crate::data_plane::{AccountRepository, ProxyAuditRecord, RepositoryError};
use crate::egress::ProxyEndpoint;
use crate::providers::ProviderAccount;
use crate::routing::RouteAccount;
use crate::secrets::{SecretBox, SecretError, SecretInput};

#[derive(Clone, Debug, serde::Serialize, Eq, PartialEq)]
pub struct PublicAccount {
    pub id: String,
    pub label: String,
    pub provider: crate::providers::ProviderKind,
    pub base_url: String,
    pub enabled: bool,
    pub models: Vec<String>,
    pub egress: Vec<String>,
    pub credential_present: bool,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
pub struct AuditEvent {
    pub occurred_at: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub account_id: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub session_id: Option<String>,
    pub status: Option<u16>,
    pub outcome: String,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database operation failed: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("secret operation failed: {0}")]
    Secret(#[from] SecretError),
    #[error("account does not exist")]
    NotFound,
    #[error("stored account data is invalid: {0}")]
    InvalidAccount(String),
}

pub struct SqliteStore {
    connection: Mutex<Connection>,
    secret_box: SecretBox,
}

impl SqliteStore {
    pub fn open(path: &Path, secret_box: SecretBox) -> Result<Self, StorageError> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "busy_timeout", 5_000)?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS provider_accounts (
                 id TEXT PRIMARY KEY,
                 account_json TEXT NOT NULL,
                 credential_ciphertext TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS audit_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 occurred_at TEXT NOT NULL,
                 actor TEXT NOT NULL,
                 action TEXT NOT NULL,
                 account_id TEXT,
                 provider TEXT,
                 model TEXT,
                 session_id TEXT,
                 status INTEGER,
                 outcome TEXT NOT NULL,
                 latency_ms INTEGER
             );
             CREATE INDEX IF NOT EXISTS audit_events_occurred_at
                 ON audit_events(occurred_at DESC);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
             VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
             VALUES (2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));",
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
            secret_box,
        })
    }

    pub fn upsert_account(
        &self,
        account: &ProviderAccount,
        credential: &SecretInput,
    ) -> Result<(), StorageError> {
        let account_json = serde_json::to_string(account)
            .map_err(|error| StorageError::InvalidAccount(error.to_string()))?;
        let associated_data = format!("account:{}", account.id);
        let encrypted = self
            .secret_box
            .encrypt(credential, associated_data.as_bytes())?;
        self.connection.lock().execute(
            "INSERT INTO provider_accounts (
                 id, account_json, credential_ciphertext, updated_at
             ) VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             ON CONFLICT(id) DO UPDATE SET
                 account_json = excluded.account_json,
                 credential_ciphertext = excluded.credential_ciphertext,
                 updated_at = excluded.updated_at",
            (&account.id, account_json, encrypted.as_storage_value()),
        )?;
        Ok(())
    }

    pub fn load_account(
        &self,
        account_id: &str,
    ) -> Result<(ProviderAccount, SecretInput), StorageError> {
        let result = self.connection.lock().query_row(
            "SELECT account_json, credential_ciphertext
             FROM provider_accounts WHERE id = ?1",
            [account_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        );
        let (account_json, ciphertext) = match result {
            Ok(values) => values,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Err(StorageError::NotFound),
            Err(error) => return Err(StorageError::Database(error)),
        };
        let account = serde_json::from_str(&account_json)
            .map_err(|error| StorageError::InvalidAccount(error.to_string()))?;
        let associated_data = format!("account:{account_id}");
        let secret = self.secret_box.decrypt(
            &crate::secrets::EncryptedSecret::from_storage_value(ciphertext),
            associated_data.as_bytes(),
        )?;
        Ok((account, SecretInput::new(secret.as_str())))
    }

    pub fn journal_mode(&self) -> Result<String, StorageError> {
        self.connection
            .lock()
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(StorageError::Database)
    }

    pub fn list_accounts(&self) -> Result<Vec<PublicAccount>, StorageError> {
        let connection = self.connection.lock();
        let mut statement = connection.prepare(
            "SELECT account_json, credential_ciphertext
             FROM provider_accounts ORDER BY id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (json, ciphertext) = row?;
            let account: ProviderAccount = serde_json::from_str(&json)
                .map_err(|error| StorageError::InvalidAccount(error.to_string()))?;
            let mut models: Vec<_> = account.model_map.keys().cloned().collect();
            models.sort();
            let egress = account
                .egress_proxies
                .iter()
                .map(|endpoint| {
                    ProxyEndpoint::parse(endpoint)
                        .map(|parsed| parsed.redacted_authority())
                        .unwrap_or_else(|_| "[invalid proxy endpoint]".into())
                })
                .collect();
            Ok(PublicAccount {
                id: account.id,
                label: account.label,
                provider: account.kind,
                base_url: account.base_url.to_string(),
                enabled: account.enabled,
                models,
                egress,
                credential_present: !ciphertext.is_empty(),
            })
        })
        .collect()
    }

    pub fn route_accounts(&self) -> Result<Vec<RouteAccount>, StorageError> {
        self.list_accounts().map(|accounts| {
            accounts
                .into_iter()
                .map(|account| RouteAccount {
                    id: account.id,
                    provider: match account.provider {
                        crate::providers::ProviderKind::ClaudeOauth => "claude_oauth",
                        crate::providers::ProviderKind::AnthropicApiKey => "anthropic_api_key",
                        crate::providers::ProviderKind::BedrockApiKey => "bedrock_api_key",
                        crate::providers::ProviderKind::BedrockSigV4 => "bedrock_sig_v4",
                        crate::providers::ProviderKind::AnthropicCompatible => {
                            "anthropic_compatible"
                        }
                    }
                    .into(),
                    enabled: account.enabled,
                    healthy: true,
                    in_flight: 0,
                    utilization_basis_points: 0,
                    models: HashSet::from_iter(account.models),
                    depleted_until: None,
                })
                .collect()
        })
    }

    pub fn set_account_enabled(&self, account_id: &str, enabled: bool) -> Result<(), StorageError> {
        let (mut account, credential) = self.load_account(account_id)?;
        account.enabled = enabled;
        self.upsert_account(&account, &credential)
    }

    pub fn delete_account(&self, account_id: &str) -> Result<(), StorageError> {
        let changed = self
            .connection
            .lock()
            .execute("DELETE FROM provider_accounts WHERE id = ?1", [account_id])?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    pub fn append_audit(&self, event: &AuditEvent) -> Result<(), StorageError> {
        self.connection.lock().execute(
            "INSERT INTO audit_events (
                 occurred_at, actor, action, account_id, provider, model,
                 session_id, status, outcome, latency_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                event.occurred_at.to_rfc3339(),
                event.actor,
                event.action,
                event.account_id,
                event.provider,
                event.model,
                event.session_id,
                event.status,
                event.outcome,
                event.latency_ms,
            ],
        )?;
        Ok(())
    }

    pub fn recent_audit(&self, limit: usize) -> Result<Vec<AuditEvent>, StorageError> {
        let connection = self.connection.lock();
        let mut statement = connection.prepare(
            "SELECT occurred_at, actor, action, account_id, provider, model,
                    session_id, status, outcome, latency_ms
             FROM audit_events ORDER BY occurred_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([limit.clamp(1, 1_000) as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<u16>>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, Option<u64>>(9)?,
            ))
        })?;
        rows.map(|row| {
            let (
                occurred_at,
                actor,
                action,
                account_id,
                provider,
                model,
                session_id,
                status,
                outcome,
                latency_ms,
            ) = row?;
            let occurred_at = DateTime::parse_from_rfc3339(&occurred_at)
                .map_err(|error| StorageError::InvalidAccount(error.to_string()))?
                .with_timezone(&Utc);
            Ok(AuditEvent {
                occurred_at,
                actor,
                action,
                account_id,
                provider,
                model,
                session_id,
                status,
                outcome,
                latency_ms,
            })
        })
        .collect()
    }

    pub fn prune_audit_before(&self, cutoff: DateTime<Utc>) -> Result<usize, StorageError> {
        self.connection
            .lock()
            .execute(
                "DELETE FROM audit_events WHERE occurred_at < ?1",
                [cutoff.to_rfc3339()],
            )
            .map_err(StorageError::Database)
    }
}

#[async_trait]
impl AccountRepository for SqliteStore {
    async fn credential_snapshot(
        &self,
        authenticator: &Authenticator,
        _now: DateTime<Utc>,
    ) -> Result<CredentialSnapshot, RepositoryError> {
        let rows = {
            let connection = self.connection.lock();
            let mut statement = connection
                .prepare(
                    "SELECT account_json, credential_ciphertext
                     FROM provider_accounts ORDER BY id",
                )
                .map_err(|_| RepositoryError::Unavailable)?;
            let mapped = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|_| RepositoryError::Unavailable)?;
            mapped
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| RepositoryError::Unavailable)?
        };

        let mut credentials = Vec::with_capacity(rows.len());
        for (account_json, ciphertext) in rows {
            let account: ProviderAccount =
                serde_json::from_str(&account_json).map_err(|_| RepositoryError::InvalidData)?;
            let associated_data = format!("account:{}", account.id);
            let secret = self
                .secret_box
                .decrypt(
                    &crate::secrets::EncryptedSecret::from_storage_value(ciphertext),
                    associated_data.as_bytes(),
                )
                .map_err(|_| RepositoryError::InvalidData)?;
            let credential = AccountCredential::active(authenticator, &account.id, secret.as_str());
            credentials.push(if account.enabled {
                credential
            } else {
                credential.paused()
            });
        }
        Ok(CredentialSnapshot::Available(credentials))
    }

    async fn load_account(
        &self,
        account_id: &str,
    ) -> Result<(ProviderAccount, SecretInput), RepositoryError> {
        SqliteStore::load_account(self, account_id).map_err(|error| match error {
            StorageError::NotFound => RepositoryError::NotFound,
            StorageError::Database(_) => RepositoryError::Unavailable,
            StorageError::Secret(_) | StorageError::InvalidAccount(_) => {
                RepositoryError::InvalidData
            }
        })
    }

    async fn append_proxy_audit(&self, record: ProxyAuditRecord) -> Result<(), RepositoryError> {
        self.append_audit(&AuditEvent {
            occurred_at: record.occurred_at,
            actor: record.actor,
            action: "proxy.request".into(),
            account_id: record.account_id,
            provider: record.provider,
            model: record.model,
            session_id: record.session_fingerprint,
            status: Some(record.status),
            outcome: record.outcome,
            latency_ms: Some(record.latency_ms),
        })
        .map_err(|error| match error {
            StorageError::Database(_) => RepositoryError::Unavailable,
            StorageError::NotFound => RepositoryError::NotFound,
            StorageError::Secret(_) | StorageError::InvalidAccount(_) => {
                RepositoryError::InvalidData
            }
        })
    }
}
