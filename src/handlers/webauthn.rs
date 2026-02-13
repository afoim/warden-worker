use axum::{
    extract::{Path, State},
    http::{header, HeaderMap},
    Json,
};
use constant_time_eq::constant_time_eq;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use worker::Env;

use crate::{auth::Claims, db, error::AppError, jwt, webauthn};

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SecretVerificationData {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
}

impl SecretVerificationData {
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
#[serde(rename_all = "camelCase")]
pub struct UpdateTwoFactorWebAuthnRequest {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
    id: i32,
    name: Option<String>,
    #[serde(rename = "deviceResponse")]
    device_response: WebAuthnDeviceResponse,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTwoFactorWebAuthnDeleteRequest {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
    id: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnDeviceResponse {
    response: WebAuthnDeviceResponseInner,
}

#[derive(Debug, Deserialize)]
struct WebAuthnDeviceResponseInner {
    #[serde(rename = "AttestationObject", alias = "attestationObject")]
    attestation_object: String,
    #[serde(rename = "clientDataJson", alias = "clientDataJSON")]
    client_data_json: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveWebAuthnCredentialRequest {
    #[serde(rename = "token")]
    _token: Option<String>,
    name: Option<String>,
    #[serde(rename = "deviceResponse")]
    device_response: WebAuthnDeviceResponse,
    #[serde(rename = "supportsPrf")]
    supports_prf: Option<bool>,
    #[serde(rename = "encryptedUserKey")]
    encrypted_user_key: Option<String>,
    #[serde(rename = "encryptedPublicKey")]
    encrypted_public_key: Option<String>,
    #[serde(rename = "encryptedPrivateKey")]
    encrypted_private_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateWebAuthnCredentialRequest {
    #[serde(rename = "token")]
    _token: Option<String>,
    #[serde(rename = "deviceResponse")]
    device_response: Value,
    #[serde(rename = "encryptedUserKey")]
    encrypted_user_key: Option<String>,
    #[serde(rename = "encryptedPublicKey")]
    encrypted_public_key: Option<String>,
    #[serde(rename = "encryptedPrivateKey")]
    encrypted_private_key: Option<String>,
}

async fn webauthn_response(
    db: &worker::D1Database,
    user_id: &str,
) -> Result<serde_json::Value, AppError> {
    let keys = webauthn::list_webauthn_keys(db, user_id).await?;
    let key_items: Vec<Value> = keys
        .into_iter()
        .map(|k| {
            json!({
                "Name": k.name,
                "Id": k.id,
                "Migrated": k.migrated
            })
        })
        .collect();
    Ok(json!({
        "Enabled": !key_items.is_empty(),
        "Keys": key_items
    }))
}

async fn webauthn_credentials_response(
    db: &worker::D1Database,
    user_id: &str,
) -> Result<serde_json::Value, AppError> {
    let keys = webauthn::list_webauthn_api_items(db, user_id).await?;
    let data: Vec<Value> = keys
        .into_iter()
        .map(|k| {
            json!({
                "Id": k.id,
                "Name": k.name,
                "PrfStatus": k.prf_status,
                "EncryptedPublicKey": k.encrypted_public_key,
                "EncryptedUserKey": k.encrypted_user_key,
                "EncryptedPrivateKey": k.encrypted_private_key
            })
        })
        .collect();

    Ok(json!({
        "Object": "list",
        "Data": data,
        "ContinuationToken": Value::Null
    }))
}

async fn next_available_webauthn_slot_id(
    db: &worker::D1Database,
    user_id: &str,
) -> Result<i32, AppError> {
    let keys = webauthn::list_webauthn_keys(db, user_id).await?;
    for slot_id in 1..=5 {
        if !keys.iter().any(|k| k.id == slot_id) {
            return Ok(slot_id);
        }
    }
    Err(AppError::BadRequest(
        "WebAuthn key slots are full".to_string(),
    ))
}

fn bearer_token_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
}

async fn claims_from_bearer(
    headers: &HeaderMap,
    env: &Arc<Env>,
) -> Result<Option<Claims>, AppError> {
    let Some(token) = bearer_token_from_headers(headers) else {
        return Ok(None);
    };
    let jwt_secret = env.secret("JWT_SECRET")?.to_string();
    let claims = jwt::decode_hs256(&token, &jwt_secret)?;
    Ok(Some(claims))
}

#[worker::send]
pub async fn api_webauthn_get(
    headers: HeaderMap,
    State(env): State<Arc<Env>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    if let Some(claims) = claims_from_bearer(&headers, &env).await? {
        return Ok(Json(webauthn_credentials_response(&db, &claims.sub).await?));
    }
    Ok(Json(json!({
        "object": "list",
        "data": [],
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn webauthn_attestation_options(
    claims: Claims,
    headers: HeaderMap,
    State(env): State<Arc<Env>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    payload.validate(&db, &claims.sub).await?;

    let user_row: Value = db
        .prepare("SELECT name, email FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let user_name = user_row.get("name").and_then(|v| v.as_str());
    let user_email = user_row
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Database)?;

    let rp_id = webauthn::rp_id_from_headers(&headers);
    let origin = webauthn::origin_from_headers(&headers);
    let options = webauthn::issue_registration_challenge(
        &db,
        &claims.sub,
        user_name,
        user_email,
        &rp_id,
        &origin,
    )
    .await?;

    let token = options
        .get("challenge")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    Ok(Json(json!({
        "options": options,
        "token": token
    })))
}

#[worker::send]
pub async fn webauthn_assertion_options(
    claims: Claims,
    headers: HeaderMap,
    State(env): State<Arc<Env>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    payload.validate(&db, &claims.sub).await?;

    let rp_id = webauthn::rp_id_from_headers(&headers);
    let origin = webauthn::origin_from_headers(&headers);
    let options = webauthn::issue_login_challenge(&db, &claims.sub, &rp_id, &origin)
        .await?
        .ok_or_else(|| AppError::BadRequest("No WebAuthn credentials registered".to_string()))?;

    let token = options
        .get("challenge")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    Ok(Json(json!({
        "options": options,
        "token": token
    })))
}

#[worker::send]
pub async fn webauthn_save_credential(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<SaveWebAuthnCredentialRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    let slot_id = next_available_webauthn_slot_id(&db, &claims.sub).await?;
    let name = payload.name.unwrap_or_default();

    webauthn::register_webauthn_credential(
        &db,
        &claims.sub,
        slot_id,
        &name,
        &payload.device_response.response.attestation_object,
        &payload.device_response.response.client_data_json,
    )
    .await?;

    let encrypted_public_key = payload
        .encrypted_public_key
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let encrypted_user_key = payload
        .encrypted_user_key
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let encrypted_private_key = payload
        .encrypted_private_key
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let prf_status = if payload.supports_prf.unwrap_or(false) {
        if encrypted_public_key.is_some() && encrypted_user_key.is_some() {
            webauthn::WEBAUTHN_PRF_STATUS_ENABLED
        } else {
            webauthn::WEBAUTHN_PRF_STATUS_SUPPORTED
        }
    } else {
        webauthn::WEBAUTHN_PRF_STATUS_UNSUPPORTED
    };
    webauthn::update_webauthn_prf_by_slot(
        &db,
        &claims.sub,
        slot_id,
        prf_status,
        encrypted_public_key,
        encrypted_user_key,
        encrypted_private_key,
    )
    .await?;

    Ok(Json(json!({ "success": true })))
}

#[worker::send]
pub async fn webauthn_update_credential(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<UpdateWebAuthnCredentialRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    let assertion_token_json = serde_json::to_string(&payload.device_response)
        .map_err(|_| AppError::BadRequest("Invalid WebAuthn assertion".to_string()))?;

    webauthn::verify_login_assertion(&db, &claims.sub, &assertion_token_json).await?;
    let credential_id_b64url =
        webauthn::extract_assertion_credential_id_b64url(&assertion_token_json)?;
    let encrypted_public_key = payload
        .encrypted_public_key
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let encrypted_user_key = payload
        .encrypted_user_key
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let encrypted_private_key = payload
        .encrypted_private_key
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    if encrypted_public_key.is_none() || encrypted_user_key.is_none() {
        return Err(AppError::BadRequest(
            "Missing encrypted keyset for passkey encryption".to_string(),
        ));
    }
    webauthn::update_webauthn_prf_by_credential_id(
        &db,
        &claims.sub,
        &credential_id_b64url,
        webauthn::WEBAUTHN_PRF_STATUS_ENABLED,
        encrypted_public_key,
        encrypted_user_key,
        encrypted_private_key,
    )
    .await?;

    Ok(Json(json!({ "success": true })))
}

#[worker::send]
pub async fn webauthn_delete_credential(
    claims: Claims,
    Path(id): Path<i32>,
    State(env): State<Arc<Env>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    payload.validate(&db, &claims.sub).await?;
    webauthn::delete_webauthn_key(&db, &claims.sub, id).await?;
    Ok(Json(json!({ "success": true })))
}

#[worker::send]
pub async fn get_webauthn(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    payload.validate(&db, &claims.sub).await?;
    Ok(Json(webauthn_response(&db, &claims.sub).await?))
}

#[worker::send]
pub async fn get_webauthn_challenge(
    claims: Claims,
    headers: HeaderMap,
    State(env): State<Arc<Env>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    payload.validate(&db, &claims.sub).await?;

    let user_row: Value = db
        .prepare("SELECT name, email FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let user_name = user_row.get("name").and_then(|v| v.as_str());
    let user_email = user_row
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Database)?;

    let rp_id = webauthn::rp_id_from_headers(&headers);
    let origin = webauthn::origin_from_headers(&headers);
    let challenge = webauthn::issue_registration_challenge(
        &db,
        &claims.sub,
        user_name,
        user_email,
        &rp_id,
        &origin,
    )
    .await?;

    Ok(Json(challenge))
}

#[worker::send]
pub async fn put_webauthn(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<UpdateTwoFactorWebAuthnRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    SecretVerificationData {
        master_password_hash: payload.master_password_hash.clone(),
        otp: payload.otp.clone(),
    }
    .validate(&db, &claims.sub)
    .await?;

    webauthn::register_webauthn_credential(
        &db,
        &claims.sub,
        payload.id,
        payload.name.as_deref().unwrap_or(""),
        &payload.device_response.response.attestation_object,
        &payload.device_response.response.client_data_json,
    )
    .await?;

    Ok(Json(webauthn_response(&db, &claims.sub).await?))
}

#[worker::send]
pub async fn delete_webauthn(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<UpdateTwoFactorWebAuthnDeleteRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    SecretVerificationData {
        master_password_hash: payload.master_password_hash.clone(),
        otp: payload.otp.clone(),
    }
    .validate(&db, &claims.sub)
    .await?;

    webauthn::delete_webauthn_key(&db, &claims.sub, payload.id).await?;
    Ok(Json(webauthn_response(&db, &claims.sub).await?))
}
