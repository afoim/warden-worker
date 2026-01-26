use axum::{extract::State, Json};
use chrono::Utc;
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

    let secret = Secret::generate_secret();
    let secret_encoded = secret.to_encoded().to_string();
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
