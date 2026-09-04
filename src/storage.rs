use std::path::Path;

use rusqlite::Connection;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::providers::ProviderAccount;
use crate::secrets::{SecretBox, SecretError, SecretInput};

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
    connection: Connection,
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
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
             VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));",
        )?;
        Ok(Self {
            connection,
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
        self.connection.execute(
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
    ) -> Result<(ProviderAccount, Zeroizing<String>), StorageError> {
        let result = self.connection.query_row(
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
        Ok((account, secret))
    }

    pub fn journal_mode(&self) -> Result<String, StorageError> {
        self.connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(StorageError::Database)
    }
}
