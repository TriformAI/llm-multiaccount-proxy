use std::fmt;

use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SecretError {
    #[error("master key must decode to exactly 32 bytes")]
    InvalidMasterKey,
    #[error("encrypted secret has an unsupported or invalid format")]
    InvalidCiphertext,
    #[error("encrypted secret failed authentication")]
    AuthenticationFailed,
    #[error("password hashing failed")]
    PasswordHashFailed,
}

pub struct SecretInput(String);

impl SecretInput {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretInput {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretInput([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedSecret(String);

impl EncryptedSecret {
    pub fn as_storage_value(&self) -> &str {
        &self.0
    }

    pub fn from_storage_value(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl fmt::Debug for EncryptedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncryptedSecret([REDACTED])")
    }
}

#[derive(Clone)]
pub struct SecretBox {
    key: [u8; 32],
}

impl SecretBox {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn from_base64(_encoded: &str) -> Result<Self, SecretError> {
        unimplemented!("RED: master-key decoding")
    }

    pub fn encrypt(
        &self,
        _plaintext: &SecretInput,
        _associated_data: &[u8],
    ) -> Result<EncryptedSecret, SecretError> {
        let _ = self.key;
        unimplemented!("RED: XChaCha20-Poly1305 encryption")
    }

    pub fn decrypt(
        &self,
        _ciphertext: &EncryptedSecret,
        _associated_data: &[u8],
    ) -> Result<Zeroizing<String>, SecretError> {
        unimplemented!("RED: authenticated secret decryption")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AdminPasswordHash(String);

impl AdminPasswordHash {
    pub fn create(_password: &SecretInput) -> Result<Self, SecretError> {
        unimplemented!("RED: Argon2id admin password hashing")
    }

    pub fn from_storage_value(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_storage_value(&self) -> &str {
        &self.0
    }

    pub fn verify(&self, _password: &SecretInput) -> bool {
        false
    }
}

impl fmt::Debug for AdminPasswordHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdminPasswordHash([REDACTED])")
    }
}
