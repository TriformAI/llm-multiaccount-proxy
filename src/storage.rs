use std::collections::HashSet;
use std::fs::OpenOptions;
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::Connection;
use thiserror::Error;
use zeroize::Zeroize;

use crate::auth::{AccountCredential, Authenticator, CredentialSnapshot};
use crate::data_plane::{AccountRepository, ProxyAuditRecord, RepositoryError};
use crate::egress::ProxyEndpoint;
use crate::providers::{ProviderAccount, ProviderKind};
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct OAuthRefreshSummary {
    pub refreshed: usize,
    pub skipped: usize,
    pub failed: usize,
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
    #[error("backup destination already exists")]
    BackupDestinationExists,
    #[error("backup filesystem operation failed: {0}")]
    BackupFilesystem(#[from] std::io::Error),
    #[error("backup integrity check failed")]
    InvalidBackup,
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
        connection.pragma_update(None, "secure_delete", "ON")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS provider_accounts (
                 id TEXT PRIMARY KEY,
                 account_json TEXT NOT NULL,
                 credential_ciphertext TEXT NOT NULL,
                 egress_ciphertext TEXT,
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
             CREATE TABLE IF NOT EXISTS credential_history (
                 account_id TEXT PRIMARY KEY REFERENCES provider_accounts(id) ON DELETE CASCADE,
                 credential_ciphertext TEXT NOT NULL,
                 expires_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS audit_events_occurred_at
                 ON audit_events(occurred_at DESC);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
             VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
             VALUES (2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
             VALUES (3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));",
        )?;
        let has_egress_ciphertext = {
            let mut statement = connection.prepare("PRAGMA table_info(provider_accounts)")?;
            let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
            columns
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .any(|column| column == "egress_ciphertext")
        };
        if !has_egress_ciphertext {
            connection.execute(
                "ALTER TABLE provider_accounts ADD COLUMN egress_ciphertext TEXT",
                [],
            )?;
        }
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at)
             VALUES (4, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            [],
        )?;
        let store = Self {
            connection: Mutex::new(connection),
            secret_box,
        };
        if store.encrypt_legacy_egress_metadata()? > 0 {
            store.connection.lock().execute_batch(
                "PRAGMA wal_checkpoint(TRUNCATE);
                 VACUUM;
                 PRAGMA wal_checkpoint(TRUNCATE);",
            )?;
        }
        Ok(store)
    }

    pub fn upsert_account(
        &self,
        account: &ProviderAccount,
        credential: &SecretInput,
    ) -> Result<(), StorageError> {
        let (account_json, egress_ciphertext) = self.account_storage_values(account)?;
        let associated_data = format!("account:{}", account.id);
        let encrypted = self
            .secret_box
            .encrypt(credential, associated_data.as_bytes())?;
        let mut connection = self.connection.lock();
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO provider_accounts (
                 id, account_json, credential_ciphertext, egress_ciphertext, updated_at
             ) VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             ON CONFLICT(id) DO UPDATE SET
                 account_json = excluded.account_json,
                 credential_ciphertext = excluded.credential_ciphertext,
                 egress_ciphertext = excluded.egress_ciphertext,
                 updated_at = excluded.updated_at",
            rusqlite::params![
                account.id,
                account_json,
                encrypted.as_storage_value(),
                egress_ciphertext,
            ],
        )?;
        transaction.execute(
            "DELETE FROM credential_history WHERE account_id = ?1",
            [&account.id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn rotate_account_credential(
        &self,
        account: &ProviderAccount,
        credential: &SecretInput,
        previous_valid_until: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let (account_json, egress_ciphertext) = self.account_storage_values(account)?;
        let associated_data = format!("account:{}", account.id);
        let encrypted = self
            .secret_box
            .encrypt(credential, associated_data.as_bytes())?;
        let mut connection = self.connection.lock();
        let transaction = connection.transaction()?;
        let previous = transaction.query_row(
            "SELECT credential_ciphertext FROM provider_accounts WHERE id = ?1",
            [&account.id],
            |row| row.get::<_, String>(0),
        );
        match previous {
            Ok(previous) => {
                transaction.execute(
                    "INSERT INTO credential_history (account_id, credential_ciphertext, expires_at)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(account_id) DO UPDATE SET
                         credential_ciphertext = excluded.credential_ciphertext,
                         expires_at = excluded.expires_at",
                    rusqlite::params![account.id, previous, previous_valid_until.to_rfc3339(),],
                )?;
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {}
            Err(error) => return Err(StorageError::Database(error)),
        }
        transaction.execute(
            "INSERT INTO provider_accounts (
                 id, account_json, credential_ciphertext, egress_ciphertext, updated_at
             ) VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             ON CONFLICT(id) DO UPDATE SET
                 account_json = excluded.account_json,
                 credential_ciphertext = excluded.credential_ciphertext,
                 egress_ciphertext = excluded.egress_ciphertext,
                 updated_at = excluded.updated_at",
            rusqlite::params![
                account.id,
                account_json,
                encrypted.as_storage_value(),
                egress_ciphertext,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub async fn refresh_due_oauth(&self, now: DateTime<Utc>) -> OAuthRefreshSummary {
        let candidates = match self.oauth_refresh_candidates(now) {
            Ok(candidates) => candidates,
            Err(_) => {
                return OAuthRefreshSummary {
                    failed: 1,
                    ..OAuthRefreshSummary::default()
                };
            }
        };
        let mut summary = OAuthRefreshSummary::default();
        for candidate in candidates {
            if !candidate.due {
                summary.skipped += 1;
                continue;
            }
            match refresh_oauth_candidate(&candidate).await {
                Ok(refreshed) => {
                    let previous_valid_until = candidate
                        .envelope
                        .expires_at
                        .unwrap_or(now + chrono::Duration::minutes(10))
                        .min(now + chrono::Duration::minutes(10));
                    match self.replace_oauth_if_current(
                        &candidate,
                        &refreshed,
                        previous_valid_until,
                    ) {
                        Ok(true) => summary.refreshed += 1,
                        Ok(false) => summary.skipped += 1,
                        Err(_) => summary.failed += 1,
                    }
                }
                Err(_) => summary.failed += 1,
            }
        }
        summary
    }

    fn oauth_refresh_candidates(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<OAuthRefreshCandidate>, StorageError> {
        let rows = {
            let connection = self.connection.lock();
            let mut statement = connection.prepare(
                "SELECT account_json, credential_ciphertext, egress_ciphertext
                 FROM provider_accounts ORDER BY id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut candidates = Vec::new();
        for (account_json, ciphertext, egress_ciphertext) in rows {
            let mut account: ProviderAccount = serde_json::from_str(&account_json)
                .map_err(|error| StorageError::InvalidAccount(error.to_string()))?;
            self.hydrate_account_egress(&mut account, egress_ciphertext.as_deref())?;
            if account.kind != ProviderKind::ClaudeOauth || !account.enabled {
                continue;
            }
            let associated_data = format!("account:{}", account.id);
            let plaintext = self.secret_box.decrypt(
                &crate::secrets::EncryptedSecret::from_storage_value(ciphertext.clone()),
                associated_data.as_bytes(),
            )?;
            if !plaintext.trim_start().starts_with('{') {
                continue;
            }
            let envelope: OAuthCredentialEnvelope = serde_json::from_str(plaintext.as_str())
                .map_err(|error| StorageError::InvalidAccount(error.to_string()))?;
            let due = envelope
                .expires_at
                .is_some_and(|expiry| expiry <= now + chrono::Duration::minutes(5))
                && envelope.refresh_token.is_some()
                && envelope.token_endpoint.is_some()
                && envelope.client_id.is_some();
            candidates.push(OAuthRefreshCandidate {
                account,
                expected_ciphertext: ciphertext,
                envelope,
                due,
            });
        }
        Ok(candidates)
    }

    fn replace_oauth_if_current(
        &self,
        candidate: &OAuthRefreshCandidate,
        refreshed: &OAuthCredentialEnvelope,
        previous_valid_until: DateTime<Utc>,
    ) -> Result<bool, StorageError> {
        let plaintext = SecretInput::new(
            serde_json::to_string(refreshed)
                .map_err(|error| StorageError::InvalidAccount(error.to_string()))?,
        );
        let associated_data = format!("account:{}", candidate.account.id);
        let encrypted = self
            .secret_box
            .encrypt(&plaintext, associated_data.as_bytes())?;
        let mut connection = self.connection.lock();
        let transaction = connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE provider_accounts
             SET credential_ciphertext = ?3,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?1 AND credential_ciphertext = ?2",
            rusqlite::params![
                candidate.account.id,
                candidate.expected_ciphertext,
                encrypted.as_storage_value(),
            ],
        )?;
        if changed == 0 {
            transaction.rollback()?;
            return Ok(false);
        }
        transaction.execute(
            "INSERT INTO credential_history (account_id, credential_ciphertext, expires_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(account_id) DO UPDATE SET
                 credential_ciphertext = excluded.credential_ciphertext,
                 expires_at = excluded.expires_at",
            rusqlite::params![
                candidate.account.id,
                candidate.expected_ciphertext,
                previous_valid_until.to_rfc3339(),
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn load_account(
        &self,
        account_id: &str,
    ) -> Result<(ProviderAccount, SecretInput), StorageError> {
        let result = self.connection.lock().query_row(
            "SELECT account_json, credential_ciphertext, egress_ciphertext
             FROM provider_accounts WHERE id = ?1",
            [account_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        );
        let (account_json, ciphertext, egress_ciphertext) = match result {
            Ok(values) => values,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Err(StorageError::NotFound),
            Err(error) => return Err(StorageError::Database(error)),
        };
        let mut account: ProviderAccount = serde_json::from_str(&account_json)
            .map_err(|error| StorageError::InvalidAccount(error.to_string()))?;
        self.hydrate_account_egress(&mut account, egress_ciphertext.as_deref())?;
        let associated_data = format!("account:{account_id}");
        let secret = self.secret_box.decrypt(
            &crate::secrets::EncryptedSecret::from_storage_value(ciphertext),
            associated_data.as_bytes(),
        )?;
        let (access_token, _) = decoded_credential(&account.kind, secret.as_str())
            .map_err(StorageError::InvalidAccount)?;
        Ok((account, SecretInput::new(access_token)))
    }

    fn account_storage_values(
        &self,
        account: &ProviderAccount,
    ) -> Result<(String, String), StorageError> {
        let egress_json = SecretInput::new(
            serde_json::to_string(&account.egress_proxies)
                .map_err(|error| StorageError::InvalidAccount(error.to_string()))?,
        );
        for endpoint in &account.egress_proxies {
            ProxyEndpoint::parse(endpoint).map_err(|error| {
                StorageError::InvalidAccount(format!("invalid egress proxy: {error}"))
            })?;
        }
        let egress = self.secret_box.encrypt(
            &egress_json,
            format!("account-egress:{}", account.id).as_bytes(),
        )?;
        let mut public_account = account.clone();
        public_account.egress_proxies = account
            .egress_proxies
            .iter()
            .map(|endpoint| {
                ProxyEndpoint::parse(endpoint)
                    .expect("egress proxies were validated")
                    .redacted_authority()
            })
            .collect();
        let account_json = serde_json::to_string(&public_account)
            .map_err(|error| StorageError::InvalidAccount(error.to_string()))?;
        Ok((account_json, egress.as_storage_value().to_owned()))
    }

    fn hydrate_account_egress(
        &self,
        account: &mut ProviderAccount,
        ciphertext: Option<&str>,
    ) -> Result<(), StorageError> {
        let Some(ciphertext) = ciphertext.filter(|value| !value.is_empty()) else {
            return Ok(());
        };
        let plaintext = self.secret_box.decrypt(
            &crate::secrets::EncryptedSecret::from_storage_value(ciphertext.to_owned()),
            format!("account-egress:{}", account.id).as_bytes(),
        )?;
        account.egress_proxies = serde_json::from_str(plaintext.as_str())
            .map_err(|error| StorageError::InvalidAccount(error.to_string()))?;
        Ok(())
    }

    fn encrypt_legacy_egress_metadata(&self) -> Result<usize, StorageError> {
        let rows = {
            let connection = self.connection.lock();
            let mut statement = connection.prepare(
                "SELECT id, account_json FROM provider_accounts
                 WHERE egress_ciphertext IS NULL OR egress_ciphertext = ''",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let migrated = rows.len();
        for (id, account_json) in rows {
            let account: ProviderAccount = serde_json::from_str(&account_json)
                .map_err(|error| StorageError::InvalidAccount(error.to_string()))?;
            let (redacted_json, encrypted_egress) = self.account_storage_values(&account)?;
            self.connection.lock().execute(
                "UPDATE provider_accounts
                 SET account_json = ?2, egress_ciphertext = ?3
                 WHERE id = ?1 AND (egress_ciphertext IS NULL OR egress_ciphertext = '')",
                rusqlite::params![id, redacted_json, encrypted_egress],
            )?;
        }
        Ok(migrated)
    }

    pub fn journal_mode(&self) -> Result<String, StorageError> {
        self.connection
            .lock()
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(StorageError::Database)
    }

    /// Write a transactionally consistent SQLite snapshot without exposing
    /// the separately managed encryption key or overwriting an earlier backup.
    pub fn backup_to(&self, destination: &Path) -> Result<(), StorageError> {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
        {
            Ok(file) => drop(file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(StorageError::BackupDestinationExists);
            }
            Err(error) => return Err(StorageError::BackupFilesystem(error)),
        }

        let result = (|| {
            let source = self.connection.lock();
            let mut target = Connection::open(destination)?;
            {
                let backup = rusqlite::backup::Backup::new(&source, &mut target)?;
                backup.run_to_completion(128, Duration::from_millis(5), None)?;
            }
            let integrity: String =
                target.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
            if integrity != "ok" {
                return Err(StorageError::InvalidBackup);
            }
            Ok(())
        })();

        if result.is_err() {
            let _ = std::fs::remove_file(destination);
        }
        result
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
        let account_json = match self.connection.lock().query_row(
            "SELECT account_json FROM provider_accounts WHERE id = ?1",
            [account_id],
            |row| row.get::<_, String>(0),
        ) {
            Ok(json) => json,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Err(StorageError::NotFound),
            Err(error) => return Err(StorageError::Database(error)),
        };
        let mut account: ProviderAccount = serde_json::from_str(&account_json)
            .map_err(|error| StorageError::InvalidAccount(error.to_string()))?;
        account.enabled = enabled;
        let updated = serde_json::to_string(&account)
            .map_err(|error| StorageError::InvalidAccount(error.to_string()))?;
        self.connection.lock().execute(
            "UPDATE provider_accounts
             SET account_json = ?2, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?1",
            (account_id, updated),
        )?;
        Ok(())
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
                    "SELECT p.account_json, p.credential_ciphertext,
                            h.credential_ciphertext, h.expires_at
                     FROM provider_accounts p
                     LEFT JOIN credential_history h ON h.account_id = p.id
                     ORDER BY p.id",
                )
                .map_err(|_| RepositoryError::Unavailable)?;
            let mapped = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                })
                .map_err(|_| RepositoryError::Unavailable)?;
            mapped
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| RepositoryError::Unavailable)?
        };

        let mut credentials = Vec::with_capacity(rows.len());
        for (account_json, ciphertext, previous_ciphertext, previous_expires_at) in rows {
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
            let (current_token, current_expiry) =
                decoded_credential(&account.kind, secret.as_str())
                    .map_err(|_| RepositoryError::InvalidData)?;
            let mut credential =
                AccountCredential::active(authenticator, &account.id, &current_token)
                    .with_current_expiry(current_expiry);
            if let (Some(previous_ciphertext), Some(previous_expires_at)) =
                (previous_ciphertext, previous_expires_at)
            {
                let previous_expiry = DateTime::parse_from_rfc3339(&previous_expires_at)
                    .map_err(|_| RepositoryError::InvalidData)?
                    .with_timezone(&Utc);
                if previous_expiry > _now {
                    let previous = self
                        .secret_box
                        .decrypt(
                            &crate::secrets::EncryptedSecret::from_storage_value(
                                previous_ciphertext,
                            ),
                            associated_data.as_bytes(),
                        )
                        .map_err(|_| RepositoryError::InvalidData)?;
                    let (previous_token, _) = decoded_credential(&account.kind, previous.as_str())
                        .map_err(|_| RepositoryError::InvalidData)?;
                    credential =
                        credential.with_previous(authenticator, &previous_token, previous_expiry);
                }
            }
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

#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct OAuthCredentialEnvelope {
    access_token: String,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    token_endpoint: Option<url::Url>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

impl Drop for OAuthCredentialEnvelope {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.client_secret.zeroize();
    }
}

struct OAuthRefreshCandidate {
    account: ProviderAccount,
    expected_ciphertext: String,
    envelope: OAuthCredentialEnvelope,
    due: bool,
}

#[derive(serde::Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    expires_in: u64,
    #[serde(default)]
    refresh_token: Option<String>,
}

#[derive(serde::Serialize)]
struct OAuthRefreshRequest<'a> {
    grant_type: &'static str,
    refresh_token: &'a str,
    client_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
}

impl Drop for OAuthTokenResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

async fn refresh_oauth_candidate(
    candidate: &OAuthRefreshCandidate,
) -> Result<OAuthCredentialEnvelope, ()> {
    let endpoint = candidate.envelope.token_endpoint.as_ref().ok_or(())?;
    if endpoint.scheme() != "https" || !oauth_endpoint_allowed(endpoint) {
        return Err(());
    }
    let mut builder = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(proxy) = candidate.account.egress_proxies.first() {
        let proxy = ProxyEndpoint::parse(proxy).map_err(|_| ())?;
        builder = builder.proxy(reqwest::Proxy::all(proxy.as_url().as_str()).map_err(|_| ())?);
    }
    let client = builder.build().map_err(|_| ())?;
    let refresh_request = OAuthRefreshRequest {
        grant_type: "refresh_token",
        refresh_token: candidate.envelope.refresh_token.as_deref().ok_or(())?,
        client_id: candidate.envelope.client_id.as_deref().ok_or(())?,
        client_secret: candidate.envelope.client_secret.as_deref(),
        scope: candidate.envelope.scope.as_deref(),
    };
    let response = client
        .post(endpoint.clone())
        .json(&refresh_request)
        .send()
        .await
        .map_err(|_| ())?;
    if !response.status().is_success() {
        return Err(());
    }
    let mut response: OAuthTokenResponse = response.json().await.map_err(|_| ())?;
    if response.access_token.is_empty() || !(60..=86_400).contains(&response.expires_in) {
        return Err(());
    }
    let mut refreshed = candidate.envelope.clone();
    refreshed.access_token = std::mem::take(&mut response.access_token);
    refreshed.expires_at = Some(Utc::now() + chrono::Duration::seconds(response.expires_in as i64));
    if response.refresh_token.is_some() {
        refreshed.refresh_token = std::mem::take(&mut response.refresh_token);
    }
    Ok(refreshed)
}

fn oauth_endpoint_allowed(endpoint: &url::Url) -> bool {
    endpoint.host_str().is_some_and(|host| {
        host == "anthropic.com"
            || host.ends_with(".anthropic.com")
            || host == "claude.com"
            || host.ends_with(".claude.com")
            || host == "claude.ai"
            || host.ends_with(".claude.ai")
    })
}

fn decoded_credential(
    kind: &ProviderKind,
    stored: &str,
) -> Result<(String, Option<DateTime<Utc>>), String> {
    if *kind != ProviderKind::ClaudeOauth || !stored.trim_start().starts_with('{') {
        return Ok((stored.to_owned(), None));
    }
    let mut envelope: OAuthCredentialEnvelope =
        serde_json::from_str(stored).map_err(|error| error.to_string())?;
    if envelope.access_token.is_empty() {
        return Err("OAuth access token cannot be empty".into());
    }
    Ok((
        std::mem::take(&mut envelope.access_token),
        envelope.expires_at,
    ))
}

#[cfg(test)]
mod tests {
    use super::oauth_endpoint_allowed;

    #[test]
    fn oauth_refresh_hosts_cover_supported_claude_endpoints_only() {
        for endpoint in [
            "https://console.anthropic.com/oauth/token",
            "https://platform.claude.com/v1/oauth/token",
            "https://claude.ai/api/oauth/token",
        ] {
            assert!(oauth_endpoint_allowed(&url::Url::parse(endpoint).unwrap()));
        }
        for endpoint in [
            "http://platform.claude.com/v1/oauth/token",
            "https://claude.com.attacker.example/token",
            "https://anthropic.com.attacker.example/token",
        ] {
            let endpoint = url::Url::parse(endpoint).unwrap();
            assert!(endpoint.scheme() != "https" || !oauth_endpoint_allowed(&endpoint));
        }
    }

    #[test]
    fn oauth_refresh_request_uses_json_shape() {
        let request = super::OAuthRefreshRequest {
            grant_type: "refresh_token",
            refresh_token: "fake-refresh",
            client_id: "fake-client",
            client_secret: None,
            scope: Some("user:profile user:inference"),
        };
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["grant_type"], "refresh_token");
        assert_eq!(value["refresh_token"], "fake-refresh");
        assert!(value.get("client_secret").is_none());
    }
}
