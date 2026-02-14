use axum::{extract::State, response::IntoResponse, Form, Json};
use axum::http::{header, HeaderMap, StatusCode};
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
use worker::{wasm_bindgen::JsValue, Env};
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

fn deserialize_truthy_i32_opt<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    let Some(s) = opt else { return Ok(None) };
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    if matches!(s, "1" | "true" | "True" | "TRUE") {
        return Ok(Some(1));
    }
    if matches!(s, "0" | "false" | "False" | "FALSE") {
        return Ok(Some(0));
    }
    s.parse::<i32>().map(Some).map_err(de::Error::custom)
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    username: Option<String>,
    password: Option<String>, // This is the masterPasswordHash
    refresh_token: Option<String>,
    scope: Option<String>,
    client_id: Option<String>,
    #[serde(rename = "deviceIdentifier", alias = "device_identifier", alias = "deviceId")]
    device_identifier: Option<String>,
    #[serde(rename = "deviceName", alias = "device_name")]
    device_name: Option<String>,
    #[serde(rename = "deviceType", alias = "device_type")]
    #[serde(default, deserialize_with = "deserialize_trimmed_i32_opt")]
    device_type: Option<i32>,
    #[serde(rename = "twoFactorToken")]
    two_factor_token: Option<String>,
    #[serde(rename = "twoFactorProvider", alias = "two_factor_provider")]
    #[serde(default, deserialize_with = "deserialize_trimmed_i32_opt")]
    two_factor_provider: Option<i32>,
    #[serde(rename = "twoFactorRemember")]
    #[serde(default, deserialize_with = "deserialize_truthy_i32_opt")]
    two_factor_remember: Option<i32>,
}

fn js_opt_string(v: Option<String>) -> JsValue {
    match v {
        Some(v) => JsValue::from_str(&v),
        None => JsValue::NULL,
    }
}

fn js_opt_i64(v: Option<i64>) -> JsValue {
    match v {
        Some(v) => JsValue::from_f64(v as f64),
        None => JsValue::NULL,
    }
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

fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn set_cookie(
    headers: &mut axum::http::HeaderMap,
    name: &str,
    value: &str,
    max_age_seconds: i64,
) -> Result<(), AppError> {
    let cookie = format!(
        "{name}={value}; Max-Age={max_age_seconds}; Path=/; HttpOnly; Secure; SameSite=Lax",
    );
    headers.append(
        header::SET_COOKIE,
        cookie.parse().map_err(|_| AppError::Internal)?,
    );
    Ok(())
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
                let wants_remember = payload.two_factor_remember.unwrap_or(0) == 1;
                let provider = payload.two_factor_provider;
                let token = payload.two_factor_token.clone();

                if provider.is_none() && token.is_none() {
                    let Some(device_identifier) = payload.device_identifier.as_deref() else {
                        return Ok(two_factor_required_response());
                    };
                    let cookie_token = get_cookie(&headers, "twoFactorRemember")
                        .or_else(|| get_cookie(&headers, "TwoFactorRemember"));
                    let Some(cookie_token) = cookie_token.as_deref() else {
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
                    let candidate_hash = sha256_hex(cookie_token.trim());
                    if !constant_time_eq(stored_hash.as_bytes(), candidate_hash.as_bytes()) {
                        return Ok(two_factor_required_response());
                    }

                    if wants_remember && payload.device_identifier.is_some() {
                        remember_token_to_return = Some(generate_remember_token());
                    }
                } else if provider == Some(5) {
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
                    let candidate_hash = sha256_hex(token.trim());
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

                    if wants_remember && payload.device_identifier.is_some() {
                        remember_token_to_return = Some(generate_remember_token());
                    }
                } else {
                    return Ok(two_factor_required_response());
                }
            }

            let user_id = user.id.clone();
            let device_identifier = payload.device_identifier.clone();
            let device_name = payload.device_name.clone();
            let device_type = payload.device_type;
            log::info!(
                "token login device id={:?} type={:?} name={:?} 2fa_provider={:?} remember={:?}",
                device_identifier,
                device_type,
                device_name,
                payload.two_factor_provider,
                payload.two_factor_remember
            );

            let mut response = generate_tokens_and_response(user, &env)?;
            let remember_token_to_set = remember_token_to_return.clone();

            if let Some(device_identifier) = device_identifier.as_deref() {
                ensure_devices_table(&db).await?;

                let now = Utc::now().to_rfc3339();
                let remember_hash = remember_token_to_return
                    .as_deref()
                    .map(sha256_hex);

                db.prepare(
                    "INSERT INTO devices (id, user_id, device_identifier, device_name, device_type, remember_token_hash, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(user_id, device_identifier) DO UPDATE SET
                       updated_at = excluded.updated_at,
                       device_name = COALESCE(excluded.device_name, devices.device_name),
                       device_type = COALESCE(excluded.device_type, devices.device_type),
                       remember_token_hash = COALESCE(excluded.remember_token_hash, devices.remember_token_hash)",
                )
                .bind(&[
                    Uuid::new_v4().to_string().into(),
                    user_id.clone().into(),
                    device_identifier.into(),
                    js_opt_string(device_name.clone()),
                    js_opt_i64(device_type.map(|v| v as i64)),
                    js_opt_string(remember_hash.clone()),
                    now.clone().into(),
                    now.into(),
                ])?
                .run()
                .await
                .map_err(|_| AppError::Database)?;
            }

            if let Some(token) = remember_token_to_return {
                if let Some(obj) = response.as_object_mut() {
                    obj.insert("TwoFactorToken".to_string(), Value::String(token));
                }
            }

            let access_token_to_set = response
                .get("access_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let refresh_token_to_set = response
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let mut resp = Json(response).into_response();
            if let Some(token) = remember_token_to_set {
                set_cookie(
                    resp.headers_mut(),
                    "twoFactorRemember",
                    &token,
                    Duration::days(30).num_seconds(),
                )?;
                set_cookie(
                    resp.headers_mut(),
                    "TwoFactorRemember",
                    &token,
                    Duration::days(30).num_seconds(),
                )?;
            }
            if let Some(v) = access_token_to_set.as_deref() {
                set_cookie(
                    resp.headers_mut(),
                    "bw_access_token",
                    v,
                    Duration::hours(2).num_seconds(),
                )?;
            }
            if let Some(v) = refresh_token_to_set.as_deref() {
                set_cookie(
                    resp.headers_mut(),
                    "bw_refresh_token",
                    v,
                    Duration::days(30).num_seconds(),
                )?;
            }
            Ok(resp)
        }
        "refresh_token" => {
            let refresh_token = payload
                .refresh_token
                .or_else(|| get_cookie(&headers, "bw_refresh_token"))
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
            let mut resp = Json(response.clone()).into_response();
            if let Some(v) = response.get("access_token").and_then(|v| v.as_str()) {
                set_cookie(
                    resp.headers_mut(),
                    "bw_access_token",
                    v,
                    Duration::hours(2).num_seconds(),
                )?;
            }
            if let Some(v) = response.get("refresh_token").and_then(|v| v.as_str()) {
                set_cookie(
                    resp.headers_mut(),
                    "bw_refresh_token",
                    v,
                    Duration::days(30).num_seconds(),
                )?;
            }
            Ok(resp)
        }
        _ => Err(AppError::BadRequest("Unsupported grant_type".to_string())),
    }
}
