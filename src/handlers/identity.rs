use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::{extract::State, response::IntoResponse, Form, Json};
use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc};
use constant_time_eq::constant_time_eq;
use rand::RngCore;
use serde::de::{self, Deserializer};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use wasm_bindgen::JsValue;
use worker::Env;

use crate::{
    auth::Claims, db, error::AppError, handlers::devices, jwt, models::user::User, notifications,
    two_factor, webauthn,
};

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
    token: Option<String>,
    #[serde(rename = "deviceResponse")]
    device_response: Option<String>,
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
    #[serde(rename = "authRequest", alias = "authrequest")]
    auth_request: Option<String>,
}

#[derive(Debug, Clone)]
struct WebAuthnPrfOptionPayload {
    encrypted_private_key: String,
    encrypted_user_key: String,
}

fn generate_tokens_and_response(
    user: User,
    env: &Arc<Env>,
    device_identifier: Option<&str>,
    webauthn_prf_option: Option<&WebAuthnPrfOptionPayload>,
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
        device: device_identifier.map(str::to_string),
    };

    let jwt_secret = env.secret("JWT_SECRET")?.to_string();
    let access_token = jwt::encode_hs256(&access_claims, &jwt_secret)?;

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
        device: device_identifier.map(str::to_string),
    };
    let jwt_refresh_secret = env.secret("JWT_REFRESH_SECRET")?.to_string();
    let refresh_token = jwt::encode_hs256(&refresh_claims, &jwt_refresh_secret)?;

    let mut user_decryption_options = json!({
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
    });

    if let Some(option) = webauthn_prf_option {
        if let Some(obj) = user_decryption_options.as_object_mut() {
            obj.insert(
                "WebAuthnPrfOption".to_string(),
                json!({
                    "EncryptedPrivateKey": option.encrypted_private_key,
                    "EncryptedUserKey": option.encrypted_user_key
                }),
            );
        }
    }

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
        "UserDecryptionOptions": user_decryption_options,
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

fn generate_remember_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn to_js_val<T: Into<JsValue>>(val: Option<T>) -> JsValue {
    val.map(Into::into).unwrap_or(JsValue::NULL)
}

async fn ensure_device_record_exists_for_login(
    db: &worker::D1Database,
    user_id: &str,
    device_identifier: Option<&str>,
    device_name: Option<&str>,
    device_type: Option<i32>,
) -> Result<(), AppError> {
    let Some(device_identifier) = device_identifier else {
        return Ok(());
    };

    devices::ensure_devices_table(db).await?;
    let now = Utc::now().to_rfc3339();
    let device_name_value = to_js_val(device_name.map(str::to_string));
    let device_type_value = to_js_val(device_type.map(f64::from));
    if let Ok(stmt) = db
        .prepare(
            "INSERT INTO devices (
                id, user_id, device_identifier, device_name, device_type,
                remember_token_hash, push_token, created_at, updated_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6, ?7)
             ON CONFLICT(user_id, device_identifier) DO NOTHING",
        )
        .bind(&[
            Uuid::new_v4().to_string().into(),
            user_id.to_string().into(),
            device_identifier.to_string().into(),
            device_name_value.into(),
            device_type_value.into(),
            now.clone().into(),
            now.into(),
        ])
    {
        let _ = stmt.run().await;
    }

    Ok(())
}

async fn validate_auth_request_login(
    db: &worker::D1Database,
    user_id: &str,
    auth_request_id: &str,
    access_code: &str,
    headers: &HeaderMap,
) -> Result<(), AppError> {
    devices::ensure_auth_requests_table(db).await?;
    devices::purge_expired_auth_requests(db).await?;

    let row: Option<Value> = db
        .prepare(
            "SELECT approved, creation_date, request_ip, access_code_hash
             FROM auth_requests
             WHERE id = ?1 AND user_id = ?2
             LIMIT 1",
        )
        .bind(&[auth_request_id.into(), user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?;
    let Some(row) = row else {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    };

    let approved = row
        .get("approved")
        .and_then(|v| {
            if v.is_null() {
                None
            } else if let Some(b) = v.as_bool() {
                Some(b)
            } else {
                v.as_i64().map(|i| i != 0)
            }
        })
        .unwrap_or(false);
    if !approved {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let creation_date = row
        .get("creation_date")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;
    let created_at = chrono::DateTime::parse_from_rfc3339(creation_date)
        .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?
        .with_timezone(&Utc);
    if Utc::now() >= created_at + Duration::minutes(5) {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let request_ip = row
        .get("request_ip")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let current_ip = devices::client_ip_from_headers(headers);
    if request_ip != current_ip {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let stored_hash = row
        .get("access_code_hash")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let candidate_hash = devices::sha256_hex(access_code);
    if !constant_time_eq(stored_hash.as_bytes(), candidate_hash.as_bytes()) {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    Ok(())
}

async fn retract_pending_auth_requests_for_device(
    db: &worker::D1Database,
    user_id: &str,
    device_identifier: Option<&str>,
) -> Result<(), AppError> {
    let Some(device_identifier) = device_identifier else {
        return Ok(());
    };

    devices::ensure_auth_requests_table(db).await?;
    devices::purge_expired_auth_requests(db).await?;
    db.prepare(
        "DELETE FROM auth_requests
         WHERE user_id = ?1
           AND request_device_identifier = ?2
           AND approved IS NULL",
    )
    .bind(&[user_id.into(), device_identifier.into()])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(())
}

async fn two_factor_metadata(
    db: &worker::D1Database,
    user_id: &str,
    headers: &HeaderMap,
) -> Result<(Vec<String>, serde_json::Map<String, Value>), AppError> {
    let mut providers: Vec<String> = Vec::new();
    let mut providers2 = serde_json::Map::new();

    if two_factor::is_authenticator_enabled(db, user_id).await? {
        providers.push(two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR.to_string());
        providers2.insert(
            two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR.to_string(),
            Value::Null,
        );
    }

    if webauthn::is_webauthn_enabled(db, user_id).await? {
        let rp_id = webauthn::rp_id_from_headers(headers);
        let origin = webauthn::origin_from_headers(headers);
        if let Some(challenge) =
            webauthn::issue_login_challenge(db, user_id, &rp_id, &origin).await?
        {
            providers.push(webauthn::TWO_FACTOR_PROVIDER_WEBAUTHN.to_string());
            providers2.insert(
                webauthn::TWO_FACTOR_PROVIDER_WEBAUTHN.to_string(),
                challenge,
            );
        }
    }

    Ok((providers, providers2))
}

async fn two_factor_required_response(
    db: &worker::D1Database,
    user_id: &str,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    let (providers, providers2) = two_factor_metadata(db, user_id, headers).await?;
    Ok((
        StatusCode::BAD_REQUEST,
        Json(json!({
            "TwoFactorProviders": providers,
            "TwoFactorProviders2": providers2,
            "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
            "error": "invalid_grant",
            "error_description": "Two factor required."
        })),
    )
        .into_response())
}

async fn invalid_two_factor_response(
    db: &worker::D1Database,
    user_id: &str,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    let (providers, providers2) = two_factor_metadata(db, user_id, headers).await?;
    Ok((
        StatusCode::BAD_REQUEST,
        Json(json!({
            "TwoFactorProviders": providers,
            "TwoFactorProviders2": providers2,
            "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
            "error": "invalid_grant",
            "error_description": "Invalid two factor token."
        })),
    )
        .into_response())
}

#[worker::send]
pub async fn webauthn_assertion_options(
    headers: HeaderMap,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let rp_id = webauthn::rp_id_from_headers(&headers);
    let origin = webauthn::origin_from_headers(&headers);
    let jwt_secret = env.secret("JWT_SECRET")?.to_string();
    let payload =
        webauthn::issue_passwordless_assertion_options(&db, &rp_id, &origin, &jwt_secret).await?;
    Ok(Json(payload))
}

#[worker::send]
pub async fn token(
    headers: HeaderMap,
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
            let auth_request_id = payload.auth_request.clone();
            if let Some(auth_request_id) = auth_request_id.as_deref() {
                validate_auth_request_login(
                    &db,
                    &user.id,
                    auth_request_id,
                    &password_hash,
                    &headers,
                )
                .await?;
            } else if !constant_time_eq(
                user.master_password_hash.as_bytes(),
                password_hash.as_bytes(),
            ) {
                return Err(AppError::Unauthorized("Invalid credentials".to_string()));
            }

            ensure_device_record_exists_for_login(
                &db,
                &user.id,
                payload.device_identifier.as_deref(),
                payload.device_name.as_deref(),
                payload.device_type,
            )
            .await?;

            let authenticator_enabled = two_factor::is_authenticator_enabled(&db, &user.id).await?;
            let webauthn_enabled = webauthn::is_webauthn_enabled(&db, &user.id).await?;
            let two_factor_enabled = authenticator_enabled || webauthn_enabled;
            let remember_device_requested = payload.two_factor_remember == Some(1);
            let mut remember_token_to_return: Option<String> = None;
            if two_factor_enabled {
                let provider = payload.two_factor_provider;
                let token = payload.two_factor_token.clone();

                if provider == Some(5) {
                    let Some(device_identifier) = payload.device_identifier.as_deref() else {
                        return two_factor_required_response(&db, &user.id, &headers).await;
                    };
                    let Some(token) = token.as_deref() else {
                        return two_factor_required_response(&db, &user.id, &headers).await;
                    };

                    devices::ensure_devices_table(&db).await?;
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
                        return two_factor_required_response(&db, &user.id, &headers).await;
                    };
                    let candidate_hash = devices::sha256_hex(token);
                    if !constant_time_eq(stored_hash.as_bytes(), candidate_hash.as_bytes()) {
                        return two_factor_required_response(&db, &user.id, &headers).await;
                    }
                } else if provider == Some(two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR) {
                    if !authenticator_enabled {
                        return two_factor_required_response(&db, &user.id, &headers).await;
                    }
                    let Some(token) = token.as_deref() else {
                        return two_factor_required_response(&db, &user.id, &headers).await;
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
                        return invalid_two_factor_response(&db, &user.id, &headers).await;
                    }
                } else if provider == Some(webauthn::TWO_FACTOR_PROVIDER_WEBAUTHN) {
                    if !webauthn_enabled {
                        return two_factor_required_response(&db, &user.id, &headers).await;
                    }
                    let Some(token) = token.as_deref() else {
                        return two_factor_required_response(&db, &user.id, &headers).await;
                    };

                    if webauthn::verify_login_assertion(&db, &user.id, token)
                        .await
                        .is_err()
                    {
                        return invalid_two_factor_response(&db, &user.id, &headers).await;
                    }
                } else {
                    return two_factor_required_response(&db, &user.id, &headers).await;
                }

                if remember_device_requested && payload.device_identifier.is_some() {
                    remember_token_to_return = Some(generate_remember_token());
                }
            }

            let user_id = user.id.clone();
            let device_identifier = payload.device_identifier.clone();
            let device_name = payload.device_name.clone();
            let device_type = payload.device_type;

            let mut response =
                generate_tokens_and_response(user, &env, device_identifier.as_deref(), None)?;

            if let Some(device_identifier) = device_identifier.as_deref() {
                devices::ensure_devices_table(&db).await?;

                let now = Utc::now().to_rfc3339();
                let remember_hash = remember_token_to_return.as_deref().map(devices::sha256_hex);
                let device_name_value = to_js_val(device_name.clone());
                let device_type_value = to_js_val(device_type.map(f64::from));
                let remember_hash_value = to_js_val(remember_hash.clone());

                if let Ok(stmt) = db
                    .prepare(
                        "INSERT INTO devices (id, user_id, device_identifier, device_name, device_type, remember_token_hash, push_token, created_at, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8)
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
                        device_name_value.into(),
                        device_type_value.into(),
                        remember_hash_value.into(),
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

            if let Some(auth_request_id) = auth_request_id {
                if let Ok(stmt) = db
                    .prepare(
                        "UPDATE auth_requests SET authentication_date = ?1 WHERE id = ?2 AND user_id = ?3",
                    )
                    .bind(&[
                        Utc::now().to_rfc3339().into(),
                        auth_request_id.clone().into(),
                        user_id.clone().into(),
                    ])
                {
                    let _ = stmt.run().await;
                }

                if let Err(err) =
                    notifications::close_anonymous_subscription(env.as_ref(), &auth_request_id)
                        .await
                {
                    log::warn!("close anonymous auth websocket failed: {err}");
                }
            }

            let _ = retract_pending_auth_requests_for_device(
                &db,
                &user_id,
                device_identifier.as_deref(),
            )
            .await;

            Ok(Json(response).into_response())
        }
        "webauthn" => {
            let challenge_token = payload
                .token
                .ok_or_else(|| AppError::BadRequest("Missing token".to_string()))?;
            let device_response = payload
                .device_response
                .ok_or_else(|| AppError::BadRequest("Missing deviceResponse".to_string()))?;
            let jwt_secret = env.secret("JWT_SECRET")?.to_string();
            let login_result = webauthn::verify_passwordless_login_assertion(
                &db,
                &challenge_token,
                &device_response,
                &jwt_secret,
            )
            .await
            .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?;
            let user_id = login_result.user_id.clone();

            let user: Value = db
                .prepare("SELECT * FROM users WHERE id = ?1")
                .bind(&[user_id.clone().into()])?
                .first(None)
                .await
                .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?
                .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;
            let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

            let device_identifier = payload.device_identifier.clone();
            let device_name = payload.device_name.clone();
            let device_type = payload.device_type;

            let webauthn_prf_option = match (
                login_result.encrypted_private_key.as_deref(),
                login_result.encrypted_user_key.as_deref(),
            ) {
                (Some(encrypted_private_key), Some(encrypted_user_key))
                    if !encrypted_private_key.trim().is_empty()
                        && !encrypted_user_key.trim().is_empty() =>
                {
                    Some(WebAuthnPrfOptionPayload {
                        encrypted_private_key: encrypted_private_key.to_string(),
                        encrypted_user_key: encrypted_user_key.to_string(),
                    })
                }
                _ => None,
            };

            let response = generate_tokens_and_response(
                user,
                &env,
                device_identifier.as_deref(),
                webauthn_prf_option.as_ref(),
            )?;

            if let Some(device_identifier) = device_identifier.as_deref() {
                devices::ensure_devices_table(&db).await?;

                let now = Utc::now().to_rfc3339();
                let device_name_value = to_js_val(device_name.clone());
                let device_type_value = to_js_val(device_type.map(f64::from));
                if let Ok(stmt) = db
                    .prepare(
                        "INSERT INTO devices (id, user_id, device_identifier, device_name, device_type, remember_token_hash, push_token, created_at, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8)
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
                        device_name_value.into(),
                        device_type_value.into(),
                        JsValue::NULL.into(),
                        now.clone().into(),
                        now.into(),
                    ])
                {
                    let _ = stmt.run().await;
                }
            }

            let _ = retract_pending_auth_requests_for_device(
                &db,
                &user_id,
                device_identifier.as_deref(),
            )
            .await;

            Ok(Json(response).into_response())
        }
        "refresh_token" => {
            let refresh_token = payload
                .refresh_token
                .ok_or_else(|| AppError::BadRequest("Missing refresh_token".to_string()))?;

            let jwt_refresh_secret = env.secret("JWT_REFRESH_SECRET")?.to_string();
            let token_data: Claims = jwt::decode_hs256(&refresh_token, &jwt_refresh_secret)
                .map_err(|_| AppError::Unauthorized("Invalid refresh token".to_string()))?;

            let user_id = token_data.sub;
            let user: Value = db
                .prepare("SELECT * FROM users WHERE id = ?1")
                .bind(&[user_id.into()])?
                .first(None)
                .await
                .map_err(|_| AppError::Unauthorized("Invalid user".to_string()))?
                .ok_or_else(|| AppError::Unauthorized("Invalid user".to_string()))?;
            let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

            let response =
                generate_tokens_and_response(user, &env, token_data.device.as_deref(), None)?;
            Ok(Json(response).into_response())
        }
        _ => Err(AppError::BadRequest("Unsupported grant_type".to_string())),
    }
}
