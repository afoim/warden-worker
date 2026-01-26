use axum::{extract::State, response::IntoResponse, Form, Json};
use axum::http::StatusCode;
use axum::response::Response;
use chrono::{Duration, Utc};
use constant_time_eq::constant_time_eq;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use worker::Env;

use crate::{auth::Claims, db, error::AppError, models::user::User, two_factor};

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    username: Option<String>,
    password: Option<String>, // This is the masterPasswordHash
    refresh_token: Option<String>,
    #[serde(rename = "twoFactorToken")]
    two_factor_token: Option<String>,
    #[serde(rename = "twoFactorProvider")]
    two_factor_provider: Option<i32>,
    #[serde(rename = "twoFactorRemember")]
    two_factor_remember: Option<i32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TokenResponse {
    #[serde(rename = "access_token")]
    access_token: String,
    #[serde(rename = "expires_in")]
    expires_in: i64,
    #[serde(rename = "token_type")]
    token_type: String,
    #[serde(rename = "refresh_token")]
    refresh_token: String,
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "PrivateKey")]
    private_key: String,
    #[serde(rename = "Kdf")]
    kdf: i32,
    #[serde(rename = "ResetMasterPassword")]
    reset_master_password: bool,
    #[serde(rename = "ForcePasswordReset")]
    force_password_reset: bool,
    #[serde(rename = "UserDecryptionOptions")]
    user_decryption_options: UserDecryptionOptions,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserDecryptionOptions {
    pub has_master_password: bool,
    pub object: String,
}

fn generate_tokens_and_response(
    user: User,
    env: &Arc<Env>,
) -> Result<TokenResponse, AppError> {
    let now = Utc::now();
    let expires_in = Duration::hours(1);
    let exp = (now + expires_in).timestamp() as usize;

    let access_claims = Claims {
        sub: user.id.clone(),
        exp,
        nbf: now.timestamp() as usize,
        premium: true,
        name: user.name.clone().unwrap_or_else(|| "User".to_string()),
        email: user.email.clone(),
        email_verified: true,
        amr: vec!["Application".into()],
    };

    let jwt_secret = env.secret("JWT_SECRET")?.to_string();
    let access_token = encode(
        &Header::default(),
        &access_claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )?;

    let refresh_expires_in = Duration::days(30);
    let refresh_exp = (now + refresh_expires_in).timestamp() as usize;
    let refresh_claims = Claims {
        sub: user.id.clone(),
        exp: refresh_exp,
        nbf: now.timestamp() as usize,
        premium: true,
        name: user.name.unwrap_or_else(|| "User".to_string()),
        email: user.email.clone(),
        email_verified: true,
        amr: vec!["Application".into()],
    };
    let jwt_refresh_secret = env.secret("JWT_REFRESH_SECRET")?.to_string();
    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(jwt_refresh_secret.as_ref()),
    )?;

    Ok(TokenResponse {
        access_token,
        expires_in: expires_in.num_seconds(),
        token_type: "Bearer".to_string(),
        refresh_token,
        key: user.key,
        private_key: user.private_key,
        kdf: user.kdf_type,
        force_password_reset: false,
        reset_master_password: false,
        user_decryption_options: UserDecryptionOptions {
            has_master_password: true,
            object: "userDecryptionOptions".to_string(),
        },
    })
}

fn two_factor_required_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "TwoFactorProviders": [two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR],
            "TwoFactorProviders2": { "0": null },
            "error": "invalid_grant",
            "error_description": "Two factor required."
        })),
    )
        .into_response()
}

fn invalid_two_factor_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "invalid_grant",
            "error_description": "Invalid TOTP code."
        })),
    )
        .into_response()
}

#[worker::send]
pub async fn token(
    State(env): State<Arc<Env>>,
    Form(payload): Form<TokenRequest>,
) -> Result<Response, AppError> {
    let db = db::get_db(&env)?;
    match payload.grant_type.as_str() {
        "password" => {
            let username = payload
                .username
                .ok_or_else(|| AppError::BadRequest("Missing username".to_string()))?;
            let password_hash = payload
                .password
                .ok_or_else(|| AppError::BadRequest("Missing password".to_string()))?;

            let user: Value = db
                .prepare("SELECT * FROM users WHERE email = ?1")
                .bind(&[username.to_lowercase().into()])?
                .first(None)
                .await
                .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?
                .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;
            let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;
            // Securely compare the provided hash with the stored hash
            if !constant_time_eq(
                user.master_password_hash.as_bytes(),
                password_hash.as_bytes(),
            ) {
                return Err(AppError::Unauthorized("Invalid credentials".to_string()));
            }

            let two_factor_enabled = two_factor::is_authenticator_enabled(&db, &user.id).await?;
            if two_factor_enabled {
                let Some(provider) = payload.two_factor_provider else {
                    return Ok(two_factor_required_response());
                };
                if provider != two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR {
                    return Ok(two_factor_required_response());
                }
                let Some(token) = payload.two_factor_token else {
                    return Ok(two_factor_required_response());
                };

                let secret_enc = two_factor::get_authenticator_secret_enc(&db, &user.id)
                    .await?
                    .ok_or_else(|| AppError::Internal)?;
                let two_factor_key_b64 = env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
                let secret_encoded = two_factor::decrypt_secret_with_optional_key(
                    two_factor_key_b64.as_deref(),
                    &user.id,
                    &secret_enc,
                )?;
                if !two_factor::verify_totp_code(&secret_encoded, &token)? {
                    return Ok(invalid_two_factor_response());
                }
            }

            let response = generate_tokens_and_response(user, &env)?;
            Ok(Json(response).into_response())
        }
        "refresh_token" => {
            let refresh_token = payload
                .refresh_token
                .ok_or_else(|| AppError::BadRequest("Missing refresh_token".to_string()))?;

            let jwt_refresh_secret = env.secret("JWT_REFRESH_SECRET")?.to_string();
            let token_data = decode::<Claims>(
                &refresh_token,
                &DecodingKey::from_secret(jwt_refresh_secret.as_ref()),
                &Validation::default(),
            )
            .map_err(|_| AppError::Unauthorized("Invalid refresh token".to_string()))?;

            let user_id = token_data.claims.sub;
            let user: Value = db
                .prepare("SELECT * FROM users WHERE id = ?1")
                .bind(&[user_id.into()])?
                .first(None)
                .await
                .map_err(|_| AppError::Unauthorized("Invalid user".to_string()))?
                .ok_or_else(|| AppError::Unauthorized("Invalid user".to_string()))?;
            let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

            let response = generate_tokens_and_response(user, &env)?;
            Ok(Json(response).into_response())
        }
        _ => Err(AppError::BadRequest("Unsupported grant_type".to_string())),
    }
}
