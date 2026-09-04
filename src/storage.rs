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
    pub fn open(_path: &Path, _secret_box: SecretBox) -> Result<Self, StorageError> {
        unimplemented!("RED: SQLite WAL repository")
    }

    pub fn upsert_account(
        &self,
        _account: &ProviderAccount,
        _credential: &SecretInput,
    ) -> Result<(), StorageError> {
        unimplemented!("RED: encrypted provider credential persistence")
    }

    pub fn load_account(
        &self,
        _account_id: &str,
    ) -> Result<(ProviderAccount, Zeroizing<String>), StorageError> {
        unimplemented!("RED: encrypted provider credential loading")
    }

    pub fn journal_mode(&self) -> Result<String, StorageError> {
        let _ = (&self.connection, &self.secret_box);
        unimplemented!("RED: WAL verification")
    }
}
