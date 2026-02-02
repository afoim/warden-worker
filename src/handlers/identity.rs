use axum::{extract::State, http::HeaderMap, response::IntoResponse, Form, Json};
use axum::http::StatusCode;
use axum::response::Response;
use chrono::{Duration, Utc};
use constant_time_eq::constant_time_eq;
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::Deserialize;
use serde::de::{self, Deserializer};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use worker::Env;
use sha2::{Digest, Sha256};

use crate::{auth::Claims, db, error::AppError, models::user::User, two_factor};

fn deserialize_trimmed_i32_opt<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(s) => {
            let s = s.trim();
            if s.is_empty() {
                return Ok(None);
            }
            s.parse::<i32>().map(Some).map_err(de::Error::custom)
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    username: Option<String>,
    password: Option<String>, // This is the masterPasswordHash
    refresh_token: Option<String>,
    scope: Option<String>,
    client_id: Option<String>,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: Option<String>,
    #[serde(rename = "deviceName")]
    device_name: Option<String>,
    #[serde(rename = "deviceType")]
    #[serde(default, deserialize_with = "deserialize_trimmed_i32_opt")]
    device_type: Option<i32>,
    #[serde(rename = "twoFactorToken")]
    two_factor_token: Option<String>,
    #[serde(rename = "twoFactorProvider")]
    #[serde(default, deserialize_with = "deserialize_trimmed_i32_opt")]
    two_factor_provider: Option<i32>,
    #[serde(rename = "twoFactorRemember")]
    #[serde(default, deserialize_with = "deserialize_trimmed_i32_opt")]
    two_factor_remember: Option<i32>,
}

fn generate_tokens_and_response(
    user: User,
    env: &Arc<Env>,
) -> Result<Value, AppError> {
    let now = Utc::now();
    let expires_in = Duration::hours(2);
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

    Ok(json!({
        "ForcePasswordReset": false,
        "Kdf": user.kdf_type,
        "KdfIterations": user.kdf_iterations,
        "KdfMemory": null,
        "KdfParallelism": null,
        "Key": user.key,
        "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
        "PrivateKey": user.private_key,
        "ResetMasterPassword": false,
        "UserDecryptionOptions": {
            "HasMasterPassword": true,
            "MasterPasswordUnlock": {
                "Kdf": {
                    "KdfType": user.kdf_type,
                    "Iterations": user.kdf_iterations,
                    "Memory": null,
                    "Parallelism": null
                },
                "MasterKeyEncryptedUserKey": user.key,
                "MasterKeyWrappedUserKey": user.key,
                "Salt": user.email
            },
            "Object": "userDecryptionOptions"
        },
        "AccountKeys": {
            "publicKeyEncryptionKeyPair": {
                "wrappedPrivateKey": user.private_key,
                "publicKey": user.public_key,
                "Object": "publicKeyEncryptionKeyPair"
            },
            "Object": "privateKeys"
        },
        "access_token": access_token,
        "expires_in": expires_in.num_seconds(),
        "refresh_token": refresh_token,
        "scope": "api offline_access",
        "token_type": "Bearer"
    }))
}

async fn ensure_devices_table(db: &worker::D1Database) -> Result<(), AppError> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            device_identifier TEXT NOT NULL,
            device_name TEXT,
            device_type INTEGER,
            remember_token_hash TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, device_identifier),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    let _ = db
        .prepare("ALTER TABLE devices ADD COLUMN remember_token_hash TEXT")
        .run()
        .await;

    Ok(())
}

async fn ensure_login_rate_limits_table(db: &worker::D1Database) -> Result<(), AppError> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS login_rate_limits (
            key TEXT PRIMARY KEY NOT NULL,
            count INTEGER NOT NULL,
            reset_at INTEGER NOT NULL
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

async fn enforce_login_rate_limit(db: &worker::D1Database, key: &str) -> Result<(), AppError> {
    ensure_login_rate_limits_table(db).await?;
    let now = Utc::now().timestamp_millis();
    let window_ms: i64 = 5 * 60 * 1000;
    let max_attempts: i64 = 30;

    let row: Option<serde_json::Value> = db
        .prepare("SELECT count, reset_at FROM login_rate_limits WHERE key = ?1")
        .bind(&[key.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let (mut count, mut reset_at) = if let Some(row) = row {
        let count = row.get("count").and_then(|v| v.as_f64()).map(|v| v as i64).unwrap_or(0);
        let reset_at = row.get("reset_at").and_then(|v| v.as_f64()).map(|v| v as i64).unwrap_or(0);
        (count, reset_at)
    } else {
        (0, 0)
    };

    if now >= reset_at {
        count = 0;
        reset_at = now + window_ms;
    }

    count += 1;

    db.prepare(
        "INSERT INTO login_rate_limits (key, count, reset_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET count = excluded.count, reset_at = excluded.reset_at",
    )
    .bind(&[key.into(), (count as f64).into(), (reset_at as f64).into()])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    if count > max_attempts {
        return Err(AppError::TooManyRequests(
            "Too many login attempts. Please try again later.".to_string(),
        ));
    }

    Ok(())
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn generate_remember_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn two_factor_required_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "TwoFactorProviders": [two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR.to_string()],
            "TwoFactorProviders2": { "0": null },
            "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
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
            "TwoFactorProviders": [two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR.to_string()],
            "TwoFactorProviders2": { "0": null },
            "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
            "error": "invalid_grant",
            "error_description": "Invalid two factor token."
        })),
    )
        .into_response()
}

#[worker::send]
pub async fn token(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Form(payload): Form<TokenRequest>,
) -> Result<Response, AppError> {
    let db = db::get_db(&env)?;
    match payload.grant_type.as_str() {
        "password" => {
            let ip = client_ip(&headers);
            let rate_key = format!("login:{}", ip);
            enforce_login_rate_limit(&db, &rate_key).await?;

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
            let mut remember_token_to_return: Option<String> = None;
            if two_factor_enabled {
                let provider = payload.two_factor_provider;
                let token = payload.two_factor_token.clone();

                if provider == Some(5) {
                    let Some(device_identifier) = payload.device_identifier.as_deref() else {
                        return Ok(two_factor_required_response());
                    };
                    let Some(token) = token.as_deref() else {
                        return Ok(two_factor_required_response());
                    };

                    ensure_devices_table(&db).await?;
                    let row: Option<Value> = db
                        .prepare(
                            "SELECT remember_token_hash FROM devices WHERE user_id = ?1 AND device_identifier = ?2",
                        )
                        .bind(&[user.id.clone().into(), device_identifier.into()])?
                        .first(None)
                        .await
                        .map_err(|_| AppError::Database)?;
                    let stored_hash = row
                        .and_then(|v| v.get("remember_token_hash").cloned())
                        .and_then(|v| v.as_str().map(|s| s.to_string()));
                    let Some(stored_hash) = stored_hash else {
                        return Ok(two_factor_required_response());
                    };
                    let candidate_hash = sha256_hex(token);
                    if !constant_time_eq(stored_hash.as_bytes(), candidate_hash.as_bytes()) {
                        return Ok(two_factor_required_response());
                    }
                } else if provider == Some(two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR) {
                    let Some(token) = token.as_deref() else {
                        return Ok(two_factor_required_response());
                    };

                    let secret_enc = two_factor::get_authenticator_secret_enc(&db, &user.id)
                        .await?
                        .ok_or_else(|| AppError::Internal)?;
                    let two_factor_key_b64 =
                        env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
                    let secret_encoded = two_factor::decrypt_secret_with_optional_key(
                        two_factor_key_b64.as_deref(),
                        &user.id,
                        &secret_enc,
                    )?;
                    if !two_factor::verify_totp_code(&secret_encoded, token)? {
                        return Ok(invalid_two_factor_response());
                    }
                } else {
                    return Ok(two_factor_required_response());
                }

                if payload.device_identifier.is_some() {
                    remember_token_to_return = Some(generate_remember_token());
                }
            }

            let user_id = user.id.clone();
            let device_identifier = payload.device_identifier.clone();
            let device_name = payload.device_name.clone();
            let device_type = payload.device_type;

            let mut response = generate_tokens_and_response(user, &env)?;

            if let Some(device_identifier) = device_identifier.as_deref() {
                ensure_devices_table(&db).await?;

                let now = Utc::now().to_rfc3339();
                let remember_hash = remember_token_to_return
                    .as_deref()
                    .map(sha256_hex);

                if let Ok(stmt) = db
                    .prepare(
                        "INSERT INTO devices (id, user_id, device_identifier, device_name, device_type, remember_token_hash, created_at, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                         ON CONFLICT(user_id, device_identifier) DO UPDATE SET
                           updated_at = excluded.updated_at,
                           device_name = excluded.device_name,
                           device_type = excluded.device_type,
                           remember_token_hash = COALESCE(excluded.remember_token_hash, devices.remember_token_hash)",
                    )
                    .bind(&[
                        Uuid::new_v4().to_string().into(),
                        user_id.clone().into(),
                        device_identifier.into(),
                        device_name.clone().into(),
                        device_type.map(|v| v as i64).into(),
                        remember_hash.clone().into(),
                        now.clone().into(),
                        now.into(),
                    ])
                {
                    let _ = stmt.run().await;
                }
            }

            if let Some(token) = remember_token_to_return {
                if let Some(obj) = response.as_object_mut() {
                    obj.insert("TwoFactorToken".to_string(), Value::String(token));
                }
            }

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
