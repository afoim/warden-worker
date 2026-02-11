use axum::{extract::State, Json};
use chrono::Utc;
use constant_time_eq::constant_time_eq;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use totp_rs::{Algorithm, Secret, TOTP};
use worker::Env;

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::two_factor;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableAuthenticatorRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableAuthenticatorRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOrOtpData {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}

impl PasswordOrOtpData {
    async fn validate(&self, db: &worker::D1Database, user_id: &str) -> Result<(), AppError> {
        match (&self.master_password_hash, &self.otp) {
            (Some(master_password_hash), None) => {
                let stored_hash: Option<String> = db
                    .prepare("SELECT master_password_hash FROM users WHERE id = ?1")
                    .bind(&[user_id.into()])?
                    .first(Some("master_password_hash"))
                    .await
                    .map_err(|_| AppError::Database)?;
                let Some(stored_hash) = stored_hash else {
                    return Err(AppError::NotFound("User not found".to_string()));
                };
                if !constant_time_eq(stored_hash.as_bytes(), master_password_hash.as_bytes()) {
                    return Err(AppError::Unauthorized("Invalid credentials".to_string()));
                }
                Ok(())
            }
            (None, Some(_)) => Err(AppError::BadRequest(
                "OTP validation is not supported".to_string(),
            )),
            _ => Err(AppError::BadRequest("No validation provided".to_string())),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum NumberOrString {
    Number(i64),
    String(String),
}

impl NumberOrString {
    fn into_string(self) -> String {
        match self {
            NumberOrString::Number(n) => n.to_string(),
            NumberOrString::String(s) => s,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableAuthenticatorData {
    key: String,
    token: NumberOrString,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableAuthenticatorData {
    key: String,
    master_password_hash: String,
    #[serde(rename = "type")]
    r#type: NumberOrString,
}

#[worker::send]
pub async fn two_factor_status(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    let enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?;
    let providers: Vec<i32> = if enabled {
        vec![two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR]
    } else {
        Vec::new()
    };
    Ok(Json(json!({
        "enabled": enabled,
        "providers": providers
    })))
}

#[worker::send]
pub async fn authenticator_request(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().to_rfc3339();

    let user_email: Option<String> = db
        .prepare("SELECT email FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(Some("email"))
        .await
        .map_err(|_| AppError::Database)?;
    let user_email = user_email.ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let secret_encoded = two_factor::generate_totp_secret_base32_20();
    let two_factor_key_b64 = env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
    let secret_enc = two_factor::encrypt_secret_with_optional_key(
        two_factor_key_b64.as_deref(),
        &claims.sub,
        &secret_encoded,
    )?;

    two_factor::upsert_authenticator_secret(&db, &claims.sub, secret_enc, false, &now).await?;

    let issuer = env
        .var("TWO_FACTOR_ISSUER")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_else(|| "Warden Worker".to_string());
    let issuer = issuer.replace(':', "");
    let account = user_email.replace(':', "");
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret_encoded.clone())
            .to_bytes()
            .map_err(|_| AppError::Internal)?,
        Some(issuer.clone()),
        account.clone(),
    )
    .map_err(|_| AppError::Internal)?;
    let otpauth = totp.get_url();
    let qr_base64 = totp.get_qr_base64().map_err(|_| AppError::Internal)?;

    Ok(Json(json!({
        "secret": secret_encoded,
        "otpauth": otpauth,
        "qrBase64": qr_base64
    })))
}

#[worker::send]
pub async fn get_authenticator(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    payload.validate(&db, &claims.sub).await?;

    let enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?;
    let key = if enabled {
        let secret_enc = two_factor::get_authenticator_secret_enc(&db, &claims.sub)
            .await?
            .ok_or_else(|| AppError::Internal)?;
        let two_factor_key_b64 = env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
        two_factor::decrypt_secret_with_optional_key(two_factor_key_b64.as_deref(), &claims.sub, &secret_enc)?
    } else {
        two_factor::generate_totp_secret_base32_20()
    };

    Ok(Json(json!({
        "enabled": enabled,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

#[worker::send]
pub async fn activate_authenticator(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<EnableAuthenticatorData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;

    PasswordOrOtpData {
        master_password_hash: payload.master_password_hash.clone(),
        otp: payload.otp.clone(),
    }
    .validate(&db, &claims.sub)
    .await?;

    let key = payload.key.trim().to_uppercase();
    let key_bytes = Secret::Encoded(key.clone())
        .to_bytes()
        .map_err(|_| AppError::BadRequest("Invalid totp secret".to_string()))?;
    if key_bytes.len() != 20 {
        return Err(AppError::BadRequest("Invalid key length".to_string()));
    }

    let token = payload.token.into_string();
    if !two_factor::verify_totp_code(&key, &token)? {
        return Err(AppError::BadRequest("Invalid TOTP code".to_string()));
    }

    let now = Utc::now().to_rfc3339();
    let two_factor_key_b64 = env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
    let secret_enc = two_factor::encrypt_secret_with_optional_key(two_factor_key_b64.as_deref(), &claims.sub, &key)?;
    two_factor::upsert_authenticator_secret(&db, &claims.sub, secret_enc, true, &now).await?;

    Ok(Json(json!({
        "enabled": true,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

#[worker::send]
pub async fn activate_authenticator_put(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<EnableAuthenticatorData>,
) -> Result<Json<serde_json::Value>, AppError> {
    activate_authenticator(claims, State(env), Json(payload)).await
}

#[worker::send]
pub async fn disable_authenticator_vw(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<DisableAuthenticatorData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;

    let stored_hash: Option<String> = db
        .prepare("SELECT master_password_hash FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(Some("master_password_hash"))
        .await
        .map_err(|_| AppError::Database)?;
    let Some(stored_hash) = stored_hash else {
        return Err(AppError::NotFound("User not found".to_string()));
    };
    if !constant_time_eq(stored_hash.as_bytes(), payload.master_password_hash.as_bytes()) {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    if let Some(secret_enc) = two_factor::get_authenticator_secret_enc(&db, &claims.sub).await? {
        let two_factor_key_b64 = env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
        let secret_encoded =
            two_factor::decrypt_secret_with_optional_key(two_factor_key_b64.as_deref(), &claims.sub, &secret_enc)?;
        if secret_encoded.eq_ignore_ascii_case(payload.key.trim()) {
            two_factor::disable_authenticator(&db, &claims.sub).await?;
        } else {
            return Err(AppError::BadRequest(
                "TOTP key does not match recorded value".to_string(),
            ));
        }
    }

    let type_ = match payload.r#type {
        NumberOrString::Number(n) => n as i32,
        NumberOrString::String(s) => s.parse::<i32>().unwrap_or(two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR),
    };

    Ok(Json(json!({
        "enabled": false,
        "keys": type_,
        "object": "twoFactorProvider"
    })))
}

#[worker::send]
pub async fn authenticator_enable(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<EnableAuthenticatorRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().to_rfc3339();

    let secret_enc = two_factor::get_authenticator_secret_enc(&db, &claims.sub)
        .await?
        .ok_or_else(|| AppError::BadRequest("No pending authenticator setup".to_string()))?;
    let two_factor_key_b64 = env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
    let secret_encoded = match two_factor::decrypt_secret_with_optional_key(
        two_factor_key_b64.as_deref(),
        &claims.sub,
        &secret_enc,
    ) {
        Ok(v) => v,
        Err(e) => {
            let _ = two_factor::disable_authenticator(&db, &claims.sub).await;
            return Err(e);
        }
    };
    if !two_factor::verify_totp_code(&secret_encoded, &payload.code)? {
        return Err(AppError::BadRequest("Invalid TOTP code".to_string()));
    }

    two_factor::upsert_authenticator_secret(&db, &claims.sub, secret_enc, true, &now).await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn authenticator_disable(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<DisableAuthenticatorRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    let secret_enc = two_factor::get_authenticator_secret_enc(&db, &claims.sub)
        .await?
        .ok_or_else(|| AppError::BadRequest("Authenticator not enabled".to_string()))?;
    let two_factor_key_b64 = env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
    let secret_encoded = two_factor::decrypt_secret_with_optional_key(
        two_factor_key_b64.as_deref(),
        &claims.sub,
        &secret_enc,
    )?;
    if !two_factor::verify_totp_code(&secret_encoded, &payload.code)? {
        return Err(AppError::BadRequest("Invalid TOTP code".to_string()));
    }

    two_factor::disable_authenticator(&db, &claims.sub).await?;
    Ok(Json(json!({})))
}
