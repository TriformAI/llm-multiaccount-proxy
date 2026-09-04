use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use rand::rngs::OsRng;
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

    pub fn from_base64(encoded: &str) -> Result<Self, SecretError> {
        let decoded = STANDARD
            .decode(encoded.trim())
            .or_else(|_| URL_SAFE_NO_PAD.decode(encoded.trim()))
            .map_err(|_| SecretError::InvalidMasterKey)?;
        let key: [u8; 32] = decoded
            .try_into()
            .map_err(|_| SecretError::InvalidMasterKey)?;
        Ok(Self::new(key))
    }

    pub fn encrypt(
        &self,
        plaintext: &SecretInput,
        associated_data: &[u8],
    ) -> Result<EncryptedSecret, SecretError> {
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.expose().as_bytes(),
                    aad: associated_data,
                },
            )
            .map_err(|_| SecretError::AuthenticationFailed)?;
        Ok(EncryptedSecret(format!(
            "v1.{}.{}",
            URL_SAFE_NO_PAD.encode(nonce),
            URL_SAFE_NO_PAD.encode(ciphertext)
        )))
    }

    pub fn decrypt(
        &self,
        ciphertext: &EncryptedSecret,
        associated_data: &[u8],
    ) -> Result<Zeroizing<String>, SecretError> {
        let mut parts = ciphertext.as_storage_value().split('.');
        if parts.next() != Some("v1") {
            return Err(SecretError::InvalidCiphertext);
        }
        let nonce = URL_SAFE_NO_PAD
            .decode(parts.next().ok_or(SecretError::InvalidCiphertext)?)
            .map_err(|_| SecretError::InvalidCiphertext)?;
        let encrypted = URL_SAFE_NO_PAD
            .decode(parts.next().ok_or(SecretError::InvalidCiphertext)?)
            .map_err(|_| SecretError::InvalidCiphertext)?;
        if parts.next().is_some() || nonce.len() != 24 {
            return Err(SecretError::InvalidCiphertext);
        }
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &encrypted,
                    aad: associated_data,
                },
            )
            .map_err(|_| SecretError::AuthenticationFailed)?;
        let plaintext = String::from_utf8(plaintext).map_err(|error| {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            SecretError::InvalidCiphertext
        })?;
        Ok(Zeroizing::new(plaintext))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AdminPasswordHash(String);

impl AdminPasswordHash {
    pub fn create(password: &SecretInput) -> Result<Self, SecretError> {
        let salt = SaltString::generate(&mut OsRng);
        let value = Argon2::default()
            .hash_password(password.expose().as_bytes(), &salt)
            .map_err(|_| SecretError::PasswordHashFailed)?
            .to_string();
        Ok(Self(value))
    }

    pub fn from_storage_value(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_storage_value(&self) -> &str {
        &self.0
    }

    pub fn verify(&self, password: &SecretInput) -> bool {
        let Ok(parsed) = PasswordHash::new(&self.0) else {
            return false;
        };
        Argon2::default()
            .verify_password(password.expose().as_bytes(), &parsed)
            .is_ok()
    }
}

impl fmt::Debug for AdminPasswordHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdminPasswordHash([REDACTED])")
    }
}
