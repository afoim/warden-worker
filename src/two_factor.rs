use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose, Engine as _};
use js_sys::Date;
use rand::rngs::OsRng;
use rand::RngCore;
use totp_rs::{Algorithm, Secret, TOTP};
use worker::D1Database;

use crate::error::AppError;

pub const TWO_FACTOR_PROVIDER_AUTHENTICATOR: i32 = 0;

pub fn generate_totp_secret_base32_20() -> String {
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    Secret::Raw(bytes.to_vec()).to_encoded().to_string()
}

pub async fn ensure_two_factor_authenticator_table(db: &D1Database) -> Result<(), AppError> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS two_factor_authenticator (
            user_id TEXT PRIMARY KEY NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT 0,
            secret_enc TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn is_authenticator_enabled(db: &D1Database, user_id: &str) -> Result<bool, AppError> {
    ensure_two_factor_authenticator_table(db).await?;
    let enabled: Option<i64> = db
        .prepare("SELECT enabled FROM two_factor_authenticator WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .first(Some("enabled"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(matches!(enabled, Some(1)))
}

pub async fn get_authenticator_secret_enc(
    db: &D1Database,
    user_id: &str,
) -> Result<Option<String>, AppError> {
    ensure_two_factor_authenticator_table(db).await?;
    let secret_enc: Option<String> = db
        .prepare("SELECT secret_enc FROM two_factor_authenticator WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .first(Some("secret_enc"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(secret_enc)
}

pub async fn upsert_authenticator_secret(
    db: &D1Database,
    user_id: &str,
    secret_enc: String,
    enabled: bool,
    now: &str,
) -> Result<(), AppError> {
    ensure_two_factor_authenticator_table(db).await?;
    db.prepare(
        "INSERT INTO two_factor_authenticator (user_id, enabled, secret_enc, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(user_id) DO UPDATE SET enabled = excluded.enabled, secret_enc = excluded.secret_enc, updated_at = excluded.updated_at",
    )
    .bind(&[
        user_id.into(),
        (if enabled { 1 } else { 0 }).into(),
        secret_enc.into(),
        now.into(),
        now.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn disable_authenticator(db: &D1Database, user_id: &str) -> Result<(), AppError> {
    ensure_two_factor_authenticator_table(db).await?;
    db.prepare("DELETE FROM two_factor_authenticator WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(())
}

pub fn encrypt_secret_with_optional_key(
    two_factor_enc_key_b64: Option<&str>,
    user_id: &str,
    secret_encoded: &str,
) -> Result<String, AppError> {
    let Some(key_b64) = two_factor_enc_key_b64 else {
        return Ok(format!("plain:{}", secret_encoded));
    };

    let key_bytes = general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|_| AppError::BadRequest("Invalid TWO_FACTOR_ENC_KEY".to_string()))?;
    if key_bytes.len() != 32 {
        return Err(AppError::BadRequest("Invalid TWO_FACTOR_ENC_KEY".to_string()));
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: secret_encoded.as_bytes(),
                aad: user_id.as_bytes(),
            },
        )
        .map_err(|_| AppError::Internal)?;

    let mut blob = Vec::with_capacity(nonce_bytes.len() + ct.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    Ok(format!("gcm:{}", general_purpose::STANDARD.encode(blob)))
}

pub fn decrypt_secret_with_optional_key(
    two_factor_enc_key_b64: Option<&str>,
    user_id: &str,
    secret_enc: &str,
) -> Result<String, AppError> {
    if let Some(rest) = secret_enc.strip_prefix("plain:") {
        return Ok(rest.to_string());
    }
    let Some(rest) = secret_enc.strip_prefix("gcm:") else {
        return Err(AppError::Internal);
    };
    let Some(key_b64) = two_factor_enc_key_b64 else {
        return Err(AppError::BadRequest("Missing TWO_FACTOR_ENC_KEY".to_string()));
    };

    let key_bytes = general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|_| AppError::BadRequest("Invalid TWO_FACTOR_ENC_KEY".to_string()))?;
    if key_bytes.len() != 32 {
        return Err(AppError::BadRequest("Invalid TWO_FACTOR_ENC_KEY".to_string()));
    }

    let blob = general_purpose::STANDARD
        .decode(rest)
        .map_err(|_| AppError::Internal)?;
    if blob.len() < 12 {
        return Err(AppError::Internal);
    }
    let (nonce_bytes, ct) = blob.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);
    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct,
                aad: user_id.as_bytes(),
            },
        )
        .map_err(|_| {
            AppError::BadRequest(
                "Two-factor secret cannot be decrypted. Please regenerate the secret.".to_string(),
            )
        })?;

    Ok(String::from_utf8(pt).map_err(|_| AppError::Internal)?)
}

pub fn verify_totp_code(secret_encoded: &str, token: &str) -> Result<bool, AppError> {
    let token = token.trim();
    if token.len() != 6 || !token.chars().all(|c| c.is_ascii_digit()) {
        return Ok(false);
    }

    let secret = Secret::Encoded(secret_encoded.to_string());
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().map_err(|_| AppError::Internal)?,
        None,
        "".to_string(),
    )
    .map_err(|_| AppError::Internal)?;
    let unix_seconds = (Date::now() / 1000.0).floor() as u64;
    Ok(totp.check(token, unix_seconds))
}

#[cfg(test)]
mod tests {
    use super::generate_totp_secret_base32_20;
    use totp_rs::Secret;

    #[test]
    fn generated_totp_secret_is_20_bytes() {
        let secret = generate_totp_secret_base32_20();
        let bytes = Secret::Encoded(secret).to_bytes().expect("decode base32");
        assert_eq!(bytes.len(), 20);
    }
}
