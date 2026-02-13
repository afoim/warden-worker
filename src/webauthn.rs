use axum::http::HeaderMap;
use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc};
use ciborium::value::Value as CborValue;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use uuid::Uuid;
use worker::wasm_bindgen::JsValue;
use worker::D1Database;

use crate::{error::AppError, jwt};

pub const TWO_FACTOR_PROVIDER_WEBAUTHN: i32 = 7;
pub const WEBAUTHN_PRF_STATUS_ENABLED: i32 = 0;
pub const WEBAUTHN_PRF_STATUS_SUPPORTED: i32 = 1;
pub const WEBAUTHN_PRF_STATUS_UNSUPPORTED: i32 = 2;
const CHALLENGE_KIND_REGISTER: &str = "register";
const CHALLENGE_KIND_LOGIN: &str = "login";
const CHALLENGE_TTL_SECONDS: i64 = 300;

fn opt_str_to_js_value(value: Option<&str>) -> JsValue {
    match value {
        Some(v) => JsValue::from_str(v),
        None => JsValue::NULL,
    }
}

#[derive(Debug, Clone)]
pub struct WebAuthnCredentialSummary {
    pub id: i32,
    pub name: String,
    pub migrated: bool,
}

#[derive(Debug, Clone)]
pub struct WebAuthnCredentialApiItem {
    pub id: i32,
    pub name: String,
    pub prf_status: i32,
    pub encrypted_public_key: Option<String>,
    pub encrypted_user_key: Option<String>,
    pub encrypted_private_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PendingChallengeRow {
    challenge_b64url: String,
    challenge_type: String,
    rp_id: String,
    origin: String,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
struct StoredCredentialRow {
    slot_id: i32,
    credential_id_b64url: String,
    public_key_cose_b64: String,
    sign_count: i64,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StoredCredentialLookupRow {
    user_id: String,
    slot_id: i32,
    public_key_cose_b64: String,
    sign_count: i64,
    encrypted_user_key: Option<String>,
    encrypted_private_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PasswordlessLoginResult {
    pub user_id: String,
    pub encrypted_user_key: Option<String>,
    pub encrypted_private_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WebAuthnLoginTokenClaims {
    exp: usize,
    nbf: usize,
    challenge: String,
    rp_id: String,
    origin: String,
}

#[derive(Debug)]
struct ParsedAuthData {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    credential_id: Option<Vec<u8>>,
    credential_public_key_cose: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
struct ClientDataJson {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
}

#[derive(Debug, Deserialize)]
pub struct WebAuthnAssertionToken {
    pub id: Option<String>,
    #[serde(rename = "rawId")]
    pub raw_id: Option<String>,
    pub response: WebAuthnAssertionResponse,
}

#[derive(Debug, Deserialize)]
pub struct WebAuthnAssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "clientDataJson", alias = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
}

pub async fn ensure_webauthn_tables(db: &D1Database) -> Result<(), AppError> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS two_factor_webauthn (
            user_id TEXT NOT NULL,
            slot_id INTEGER NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            credential_id_b64url TEXT NOT NULL,
            public_key_cose_b64 TEXT NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            prf_status INTEGER NOT NULL DEFAULT 2,
            encrypted_public_key TEXT,
            encrypted_user_key TEXT,
            encrypted_private_key TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (user_id, slot_id),
            UNIQUE (user_id, credential_id_b64url),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    db.prepare(
        "CREATE TABLE IF NOT EXISTS webauthn_challenges (
            user_id TEXT PRIMARY KEY NOT NULL,
            challenge_b64url TEXT NOT NULL,
            challenge_type TEXT NOT NULL,
            rp_id TEXT NOT NULL,
            origin TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    // Production schema self-healing: old deployments may already have these tables
    // with missing columns. SQLite/D1 has no IF NOT EXISTS for ADD COLUMN, so ignore
    // duplicate-column errors and only fail on unexpected issues.
    let alter_statements = [
        "ALTER TABLE two_factor_webauthn ADD COLUMN name TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE two_factor_webauthn ADD COLUMN sign_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE two_factor_webauthn ADD COLUMN prf_status INTEGER NOT NULL DEFAULT 2",
        "ALTER TABLE two_factor_webauthn ADD COLUMN encrypted_public_key TEXT",
        "ALTER TABLE two_factor_webauthn ADD COLUMN encrypted_user_key TEXT",
        "ALTER TABLE two_factor_webauthn ADD COLUMN encrypted_private_key TEXT",
        "ALTER TABLE two_factor_webauthn ADD COLUMN created_at TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE two_factor_webauthn ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE webauthn_challenges ADD COLUMN challenge_b64url TEXT",
        "ALTER TABLE webauthn_challenges ADD COLUMN challenge_type TEXT",
        "ALTER TABLE webauthn_challenges ADD COLUMN rp_id TEXT",
        "ALTER TABLE webauthn_challenges ADD COLUMN origin TEXT",
        "ALTER TABLE webauthn_challenges ADD COLUMN expires_at TEXT",
        "ALTER TABLE webauthn_challenges ADD COLUMN created_at TEXT",
        "ALTER TABLE webauthn_challenges ADD COLUMN updated_at TEXT",
    ];
    for stmt in alter_statements {
        if let Err(e) = db.prepare(stmt).run().await {
            let msg = e.to_string().to_ascii_lowercase();
            let ignorable = msg.contains("duplicate column")
                || msg.contains("already exists")
                || msg.contains("no such table");
            if !ignorable {
                return Err(AppError::Database);
            }
        }
    }

    let now = Utc::now().to_rfc3339();
    let _ = db
        .prepare(
            "UPDATE two_factor_webauthn
             SET name = COALESCE(name, ''),
                 sign_count = COALESCE(sign_count, 0),
                 prf_status = COALESCE(prf_status, 2),
                 created_at = COALESCE(NULLIF(created_at, ''), ?1),
                 updated_at = COALESCE(NULLIF(updated_at, ''), ?1)
             WHERE name IS NULL
                OR sign_count IS NULL
                OR prf_status IS NULL
                OR created_at IS NULL OR created_at = ''
                OR updated_at IS NULL OR updated_at = ''",
        )
        .bind(&[now.clone().into()])?
        .run()
        .await;

    let _ = db
        .prepare(
            "UPDATE webauthn_challenges
             SET challenge_b64url = COALESCE(challenge_b64url, ''),
                 challenge_type = COALESCE(challenge_type, ''),
                 rp_id = COALESCE(rp_id, ''),
                 origin = COALESCE(origin, ''),
                 expires_at = COALESCE(NULLIF(expires_at, ''), ?1),
                 created_at = COALESCE(NULLIF(created_at, ''), ?1),
                 updated_at = COALESCE(NULLIF(updated_at, ''), ?1)
             WHERE challenge_b64url IS NULL
                OR challenge_type IS NULL
                OR rp_id IS NULL
                OR origin IS NULL
                OR expires_at IS NULL OR expires_at = ''
                OR created_at IS NULL OR created_at = ''
                OR updated_at IS NULL OR updated_at = ''",
        )
        .bind(&[now.into()])?
        .run()
        .await;

    Ok(())
}

pub async fn is_webauthn_enabled(db: &D1Database, user_id: &str) -> Result<bool, AppError> {
    ensure_webauthn_tables(db).await?;
    let count: Option<i64> = db
        .prepare("SELECT COUNT(1) AS total FROM two_factor_webauthn WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .first(Some("total"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(count.unwrap_or(0) > 0)
}

pub async fn list_webauthn_keys(
    db: &D1Database,
    user_id: &str,
) -> Result<Vec<WebAuthnCredentialSummary>, AppError> {
    ensure_webauthn_tables(db).await?;
    let rows: Vec<Value> = db
        .prepare(
            "SELECT slot_id, name
             FROM two_factor_webauthn
             WHERE user_id = ?1
             ORDER BY slot_id ASC",
        )
        .bind(&[user_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let slot_id = row
            .get("slot_id")
            .and_then(|v| v.as_i64())
            .ok_or(AppError::Database)? as i32;
        let name = row
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        out.push(WebAuthnCredentialSummary {
            id: slot_id,
            name,
            migrated: false,
        });
    }
    Ok(out)
}

pub async fn list_webauthn_api_items(
    db: &D1Database,
    user_id: &str,
) -> Result<Vec<WebAuthnCredentialApiItem>, AppError> {
    ensure_webauthn_tables(db).await?;
    let rows: Vec<Value> = db
        .prepare(
            "SELECT slot_id, name, prf_status, encrypted_public_key, encrypted_user_key, encrypted_private_key
             FROM two_factor_webauthn
             WHERE user_id = ?1
             ORDER BY slot_id ASC",
        )
        .bind(&[user_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let id = row
            .get("slot_id")
            .and_then(|v| v.as_i64())
            .ok_or(AppError::Database)? as i32;
        let name = row
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let prf_status_raw =
            row.get("prf_status")
                .and_then(|v| v.as_i64())
                .unwrap_or(i64::from(WEBAUTHN_PRF_STATUS_UNSUPPORTED)) as i32;
        let encrypted_public_key = row
            .get("encrypted_public_key")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .map(|v| v.to_string());
        let encrypted_user_key = row
            .get("encrypted_user_key")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .map(|v| v.to_string());
        let encrypted_private_key = row
            .get("encrypted_private_key")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .map(|v| v.to_string());

        let has_keyset = encrypted_public_key.is_some() && encrypted_user_key.is_some();
        let prf_status = if has_keyset {
            WEBAUTHN_PRF_STATUS_ENABLED
        } else if prf_status_raw == WEBAUTHN_PRF_STATUS_SUPPORTED {
            WEBAUTHN_PRF_STATUS_SUPPORTED
        } else {
            WEBAUTHN_PRF_STATUS_UNSUPPORTED
        };

        out.push(WebAuthnCredentialApiItem {
            id,
            name,
            prf_status,
            encrypted_public_key,
            encrypted_user_key,
            encrypted_private_key,
        });
    }

    Ok(out)
}

pub async fn update_webauthn_prf_by_slot(
    db: &D1Database,
    user_id: &str,
    slot_id: i32,
    prf_status: i32,
    encrypted_public_key: Option<&str>,
    encrypted_user_key: Option<&str>,
    encrypted_private_key: Option<&str>,
) -> Result<(), AppError> {
    ensure_webauthn_tables(db).await?;
    let exists: Option<i64> = db
        .prepare(
            "SELECT COUNT(1) AS total
             FROM two_factor_webauthn
             WHERE user_id = ?1 AND slot_id = ?2",
        )
        .bind(&[user_id.into(), f64::from(slot_id).into()])?
        .first(Some("total"))
        .await
        .map_err(|_| AppError::Database)?;
    if exists.unwrap_or(0) == 0 {
        return Err(AppError::NotFound("WebAuthn key not found".to_string()));
    }

    db.prepare(
        "UPDATE two_factor_webauthn
         SET prf_status = ?1,
             encrypted_public_key = ?2,
             encrypted_user_key = ?3,
             encrypted_private_key = ?4,
             updated_at = ?5
         WHERE user_id = ?6 AND slot_id = ?7",
    )
    .bind(&[
        f64::from(prf_status).into(),
        opt_str_to_js_value(encrypted_public_key).into(),
        opt_str_to_js_value(encrypted_user_key).into(),
        opt_str_to_js_value(encrypted_private_key).into(),
        Utc::now().to_rfc3339().into(),
        user_id.into(),
        f64::from(slot_id).into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(())
}

pub async fn update_webauthn_prf_by_credential_id(
    db: &D1Database,
    user_id: &str,
    credential_id_b64url: &str,
    prf_status: i32,
    encrypted_public_key: Option<&str>,
    encrypted_user_key: Option<&str>,
    encrypted_private_key: Option<&str>,
) -> Result<(), AppError> {
    ensure_webauthn_tables(db).await?;
    let exists: Option<i64> = db
        .prepare(
            "SELECT COUNT(1) AS total
             FROM two_factor_webauthn
             WHERE user_id = ?1 AND credential_id_b64url = ?2",
        )
        .bind(&[user_id.into(), credential_id_b64url.into()])?
        .first(Some("total"))
        .await
        .map_err(|_| AppError::Database)?;
    if exists.unwrap_or(0) == 0 {
        return Err(AppError::NotFound("WebAuthn key not found".to_string()));
    }

    db.prepare(
        "UPDATE two_factor_webauthn
         SET prf_status = ?1,
             encrypted_public_key = ?2,
             encrypted_user_key = ?3,
             encrypted_private_key = ?4,
             updated_at = ?5
         WHERE user_id = ?6 AND credential_id_b64url = ?7",
    )
    .bind(&[
        f64::from(prf_status).into(),
        opt_str_to_js_value(encrypted_public_key).into(),
        opt_str_to_js_value(encrypted_user_key).into(),
        opt_str_to_js_value(encrypted_private_key).into(),
        Utc::now().to_rfc3339().into(),
        user_id.into(),
        credential_id_b64url.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(())
}

pub async fn delete_webauthn_key(
    db: &D1Database,
    user_id: &str,
    slot_id: i32,
) -> Result<(), AppError> {
    ensure_webauthn_tables(db).await?;
    db.prepare("DELETE FROM two_factor_webauthn WHERE user_id = ?1 AND slot_id = ?2")
        .bind(&[user_id.into(), f64::from(slot_id).into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn disable_webauthn(db: &D1Database, user_id: &str) -> Result<(), AppError> {
    ensure_webauthn_tables(db).await?;
    db.prepare("DELETE FROM two_factor_webauthn WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    db.prepare("DELETE FROM webauthn_challenges WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(())
}

pub fn rp_id_from_headers(headers: &HeaderMap) -> String {
    let host = header_first_token(headers, "x-forwarded-host")
        .or_else(|| header_first_token(headers, "host"))
        .unwrap_or_else(|| "localhost".to_string());
    normalize_rp_id(&host)
}

pub fn origin_from_headers(headers: &HeaderMap) -> String {
    let proto = header_first_token(headers, "x-forwarded-proto")
        .or_else(|| header_first_token(headers, "x-forwarded-scheme"))
        .unwrap_or_else(|| "https".to_string())
        .to_ascii_lowercase();
    let mut host = header_first_token(headers, "x-forwarded-host")
        .or_else(|| header_first_token(headers, "host"))
        .unwrap_or_else(|| "localhost".to_string());
    if !host.contains(':') && !host.ends_with(']') {
        if let Some(port) = header_first_token(headers, "x-forwarded-port") {
            host = format!("{host}:{port}");
        }
    }
    let origin = format!("{proto}://{host}");
    normalize_origin(&origin).unwrap_or(origin)
}

pub async fn issue_registration_challenge(
    db: &D1Database,
    user_id: &str,
    user_name: Option<&str>,
    user_email: &str,
    rp_id: &str,
    origin: &str,
) -> Result<Value, AppError> {
    ensure_webauthn_tables(db).await?;
    let challenge = random_challenge_b64url();
    upsert_pending_challenge(
        db,
        user_id,
        CHALLENGE_KIND_REGISTER,
        &challenge,
        rp_id,
        origin,
    )
    .await?;

    let existing = list_stored_credentials(db, user_id).await?;
    let exclude_credentials = existing
        .iter()
        .map(|row| {
            json!({
                "type": "public-key",
                "id": row.credential_id_b64url,
            })
        })
        .collect::<Vec<_>>();

    let mut user_id_bytes = Uuid::parse_str(user_id)
        .map(|u| u.as_bytes().to_vec())
        .unwrap_or_else(|_| user_id.as_bytes().to_vec());
    if user_id_bytes.len() > 64 {
        user_id_bytes.truncate(64);
    }
    let user_display_name = user_name
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(user_email);

    Ok(json!({
        "attestation": "none",
        "authenticatorSelection": {
            "userVerification": "preferred"
        },
        "challenge": challenge,
        "excludeCredentials": exclude_credentials,
        "extensions": {},
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 }
        ],
        "rp": {
            "name": "Warden Worker",
            "id": rp_id
        },
        "timeout": 60000,
        "user": {
            "id": encode_b64url(&user_id_bytes),
            "name": user_email,
            "displayName": user_display_name
        }
    }))
}

pub async fn issue_login_challenge(
    db: &D1Database,
    user_id: &str,
    rp_id: &str,
    origin: &str,
) -> Result<Option<Value>, AppError> {
    ensure_webauthn_tables(db).await?;
    let existing = list_stored_credentials(db, user_id).await?;
    if existing.is_empty() {
        return Ok(None);
    }

    let challenge = random_challenge_b64url();
    upsert_pending_challenge(db, user_id, CHALLENGE_KIND_LOGIN, &challenge, rp_id, origin).await?;

    let allow_credentials = existing
        .iter()
        .map(|row| {
            json!({
                "type": "public-key",
                "id": row.credential_id_b64url,
            })
        })
        .collect::<Vec<_>>();

    Ok(Some(json!({
        "challenge": challenge,
        "timeout": 60000,
        "rpId": rp_id,
        "allowCredentials": allow_credentials,
        "userVerification": "preferred"
    })))
}

pub async fn issue_passwordless_assertion_options(
    db: &D1Database,
    rp_id: &str,
    origin: &str,
    jwt_secret: &str,
) -> Result<Value, AppError> {
    ensure_webauthn_tables(db).await?;
    let allow_credentials: Vec<Value> = Vec::new();

    let challenge = random_challenge_b64url();
    let now = Utc::now().timestamp() as usize;
    let claims = WebAuthnLoginTokenClaims {
        exp: now + CHALLENGE_TTL_SECONDS as usize,
        nbf: now.saturating_sub(5),
        challenge: challenge.clone(),
        rp_id: rp_id.to_string(),
        origin: origin.to_string(),
    };
    let token = jwt::encode_hs256(&claims, jwt_secret)?;

    Ok(json!({
        "options": {
            "challenge": challenge,
            "timeout": 60000,
            "rpId": rp_id,
            "allowCredentials": allow_credentials,
            "userVerification": "preferred"
        },
        "token": token
    }))
}

pub async fn register_webauthn_credential(
    db: &D1Database,
    user_id: &str,
    slot_id: i32,
    name: &str,
    attestation_object_b64: &str,
    client_data_json_b64: &str,
) -> Result<(), AppError> {
    ensure_webauthn_tables(db).await?;

    if !(1..=5).contains(&slot_id) {
        return Err(AppError::BadRequest(
            "Invalid WebAuthn key slot".to_string(),
        ));
    }

    let pending = pop_pending_challenge(db, user_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("Missing WebAuthn challenge".to_string()))?;
    if pending.challenge_type != CHALLENGE_KIND_REGISTER {
        return Err(AppError::BadRequest(
            "WebAuthn challenge type mismatch".to_string(),
        ));
    }
    if is_expired(&pending.expires_at)? {
        return Err(AppError::BadRequest(
            "WebAuthn challenge expired".to_string(),
        ));
    }

    let client_data_json = decode_b64_any(client_data_json_b64)?;
    let client_data: ClientDataJson = serde_json::from_slice(&client_data_json)
        .map_err(|_| AppError::BadRequest("Invalid WebAuthn clientData".to_string()))?;
    if client_data.typ != "webauthn.create" {
        return Err(AppError::BadRequest(
            "Invalid WebAuthn clientData type".to_string(),
        ));
    }
    verify_challenge(&pending.challenge_b64url, &client_data.challenge)?;
    verify_origin(&pending.origin, &client_data.origin)?;

    let attestation_object = decode_b64_any(attestation_object_b64)?;
    let (rp_id_hash, sign_count, credential_id, credential_public_key_cose) =
        parse_attestation_object(&attestation_object)?;

    verify_rp_id_hash(&pending.rp_id, &rp_id_hash)?;
    parse_p256_verifying_key(&credential_public_key_cose)?;

    upsert_credential(
        db,
        user_id,
        slot_id,
        name,
        &credential_id,
        &credential_public_key_cose,
        sign_count as i64,
    )
    .await
}

pub async fn verify_login_assertion(
    db: &D1Database,
    user_id: &str,
    assertion_token_json: &str,
) -> Result<(), AppError> {
    ensure_webauthn_tables(db).await?;
    let pending = pop_pending_challenge(db, user_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid two factor token".to_string()))?;
    if pending.challenge_type != CHALLENGE_KIND_LOGIN {
        return Err(AppError::Unauthorized(
            "Invalid two factor token".to_string(),
        ));
    }
    if is_expired(&pending.expires_at)? {
        return Err(AppError::Unauthorized(
            "Invalid two factor token".to_string(),
        ));
    }

    let assertion: WebAuthnAssertionToken = serde_json::from_str(assertion_token_json)
        .map_err(|_| AppError::Unauthorized("Invalid two factor token".to_string()))?;
    let client_data_json = decode_b64_any(&assertion.response.client_data_json)?;
    let client_data: ClientDataJson = serde_json::from_slice(&client_data_json)
        .map_err(|_| AppError::Unauthorized("Invalid two factor token".to_string()))?;

    if client_data.typ != "webauthn.get" {
        return Err(AppError::Unauthorized(
            "Invalid two factor token".to_string(),
        ));
    }
    verify_challenge(&pending.challenge_b64url, &client_data.challenge)
        .map_err(|_| AppError::Unauthorized("Invalid two factor token".to_string()))?;
    verify_origin(&pending.origin, &client_data.origin)
        .map_err(|_| AppError::Unauthorized("Invalid two factor token".to_string()))?;

    let authenticator_data = decode_b64_any(&assertion.response.authenticator_data)?;
    let parsed = parse_auth_data(&authenticator_data, false)?;
    verify_rp_id_hash(&pending.rp_id, &parsed.rp_id_hash)
        .map_err(|_| AppError::Unauthorized("Invalid two factor token".to_string()))?;
    if (parsed.flags & 0x01) == 0 {
        return Err(AppError::Unauthorized(
            "Invalid two factor token".to_string(),
        ));
    }

    let credential_id_raw = match assertion.raw_id.or(assertion.id) {
        Some(v) => decode_b64_any(&v)?,
        None => {
            return Err(AppError::Unauthorized(
                "Invalid two factor token".to_string(),
            ))
        }
    };
    let credential_id_b64url = encode_b64url(&credential_id_raw);
    let stored = get_stored_credential(db, user_id, &credential_id_b64url)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid two factor token".to_string()))?;

    let public_key_cose = decode_b64_any(&stored.public_key_cose_b64)?;
    let verifying_key = parse_p256_verifying_key(&public_key_cose)
        .map_err(|_| AppError::Unauthorized("Invalid two factor token".to_string()))?;

    let signature = decode_b64_any(&assertion.response.signature)?;
    let signature = Signature::from_der(&signature)
        .map_err(|_| AppError::Unauthorized("Invalid two factor token".to_string()))?;

    let mut signed_data = Vec::with_capacity(authenticator_data.len() + 32);
    signed_data.extend_from_slice(&authenticator_data);
    signed_data.extend_from_slice(&Sha256::digest(&client_data_json));
    verifying_key
        .verify(&signed_data, &signature)
        .map_err(|_| AppError::Unauthorized("Invalid two factor token".to_string()))?;

    let new_sign_count = parsed.sign_count as i64;
    let old_sign_count = stored.sign_count;
    if old_sign_count > 0 && new_sign_count > 0 && new_sign_count <= old_sign_count {
        return Err(AppError::Unauthorized(
            "Invalid two factor token".to_string(),
        ));
    }
    if new_sign_count > old_sign_count {
        db.prepare(
            "UPDATE two_factor_webauthn
             SET sign_count = ?1, updated_at = ?2
             WHERE user_id = ?3 AND slot_id = ?4",
        )
        .bind(&[
            (new_sign_count as f64).into(),
            Utc::now().to_rfc3339().into(),
            user_id.into(),
            f64::from(stored.slot_id).into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }

    Ok(())
}

pub async fn verify_passwordless_login_assertion(
    db: &D1Database,
    challenge_token: &str,
    assertion_token_json: &str,
    jwt_secret: &str,
) -> Result<PasswordlessLoginResult, AppError> {
    ensure_webauthn_tables(db).await?;
    let claims: WebAuthnLoginTokenClaims = jwt::decode_hs256(challenge_token, jwt_secret)?;

    let assertion: WebAuthnAssertionToken = serde_json::from_str(assertion_token_json)
        .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?;
    let client_data_json = decode_b64_any(&assertion.response.client_data_json)?;
    let client_data: ClientDataJson = serde_json::from_slice(&client_data_json)
        .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?;
    if client_data.typ != "webauthn.get" {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }
    verify_challenge(&claims.challenge, &client_data.challenge)
        .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?;
    verify_origin(&claims.origin, &client_data.origin)
        .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?;

    let authenticator_data = decode_b64_any(&assertion.response.authenticator_data)?;
    let parsed = parse_auth_data(&authenticator_data, false)
        .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?;
    verify_rp_id_hash(&claims.rp_id, &parsed.rp_id_hash)
        .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?;

    let credential_id_raw = match assertion.raw_id.or(assertion.id) {
        Some(raw) => decode_b64_any(&raw)?,
        None => {
            return Err(AppError::Unauthorized("Invalid credentials".to_string()));
        }
    };
    let credential_id_b64url = encode_b64url(&credential_id_raw);
    let stored = get_stored_credential_by_credential_id(db, &credential_id_b64url)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;

    let public_key_cose = decode_b64_any(&stored.public_key_cose_b64)?;
    let verifying_key = parse_p256_verifying_key(&public_key_cose)
        .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?;

    let signature = decode_b64_any(&assertion.response.signature)?;
    let signature = Signature::from_der(&signature)
        .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?;

    let mut signed_data = Vec::with_capacity(authenticator_data.len() + 32);
    signed_data.extend_from_slice(&authenticator_data);
    signed_data.extend_from_slice(&Sha256::digest(&client_data_json));
    verifying_key
        .verify(&signed_data, &signature)
        .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?;

    let new_sign_count = parsed.sign_count as i64;
    let old_sign_count = stored.sign_count;
    if old_sign_count > 0 && new_sign_count > 0 && new_sign_count <= old_sign_count {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }
    if new_sign_count > old_sign_count {
        db.prepare(
            "UPDATE two_factor_webauthn
             SET sign_count = ?1, updated_at = ?2
             WHERE user_id = ?3 AND slot_id = ?4",
        )
        .bind(&[
            (new_sign_count as f64).into(),
            Utc::now().to_rfc3339().into(),
            stored.user_id.clone().into(),
            f64::from(stored.slot_id).into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }

    Ok(PasswordlessLoginResult {
        user_id: stored.user_id,
        encrypted_user_key: stored.encrypted_user_key,
        encrypted_private_key: stored.encrypted_private_key,
    })
}

pub fn extract_assertion_credential_id_b64url(
    assertion_token_json: &str,
) -> Result<String, AppError> {
    let assertion: WebAuthnAssertionToken = serde_json::from_str(assertion_token_json)
        .map_err(|_| AppError::BadRequest("Invalid WebAuthn assertion".to_string()))?;
    let credential_id_raw = match assertion.raw_id.or(assertion.id) {
        Some(v) => decode_b64_any(&v)?,
        None => {
            return Err(AppError::BadRequest(
                "Missing WebAuthn credential id".to_string(),
            ))
        }
    };
    Ok(encode_b64url(&credential_id_raw))
}

fn random_challenge_b64url() -> String {
    let mut challenge = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    encode_b64url(&challenge)
}

fn normalize_rp_id(host: &str) -> String {
    let host = host.trim().to_lowercase();
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            return host[1..end].to_string();
        }
    }
    host.split(':').next().unwrap_or("localhost").to_string()
}

fn verify_challenge(expected_b64url: &str, actual_b64url: &str) -> Result<(), AppError> {
    let expected = decode_b64_any(expected_b64url)?;
    let actual = decode_b64_any(actual_b64url)?;
    if expected != actual {
        return Err(AppError::BadRequest(
            "WebAuthn challenge mismatch".to_string(),
        ));
    }
    Ok(())
}

fn verify_origin(expected: &str, actual: &str) -> Result<(), AppError> {
    let normalized_expected = normalize_origin(expected)
        .unwrap_or_else(|| expected.trim().trim_end_matches('/').to_ascii_lowercase());
    let normalized_actual = normalize_origin(actual)
        .unwrap_or_else(|| actual.trim().trim_end_matches('/').to_ascii_lowercase());
    if normalized_expected == normalized_actual {
        Ok(())
    } else {
        Err(AppError::BadRequest("WebAuthn origin mismatch".to_string()))
    }
}

fn header_first_token(headers: &HeaderMap, key: &str) -> Option<String> {
    headers
        .get(key)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
}

fn normalize_origin(origin: &str) -> Option<String> {
    let origin = origin.trim().trim_end_matches('/');
    let (scheme, remainder) = origin.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let authority = remainder.split('/').next()?.trim();
    if authority.is_empty() {
        return None;
    }
    let authority = strip_default_port(authority, &scheme);
    Some(format!("{scheme}://{authority}"))
}

fn strip_default_port(authority: &str, scheme: &str) -> String {
    let authority = authority.trim().to_ascii_lowercase();
    let default_port = match scheme {
        "http" => Some("80"),
        "https" => Some("443"),
        _ => None,
    };

    if authority.starts_with('[') {
        if let Some(end) = authority.find(']') {
            let host = &authority[..=end];
            let suffix = &authority[end + 1..];
            if let Some(default_port) = default_port {
                if suffix == format!(":{default_port}") {
                    return host.to_string();
                }
            }
        }
        return authority;
    }

    if let (Some(default_port), Some((host, port))) = (default_port, authority.rsplit_once(':')) {
        if !host.contains(':') && port == default_port {
            return host.to_string();
        }
    }

    authority
}

#[cfg(test)]
mod tests {
    use super::{normalize_origin, normalize_rp_id, verify_origin};

    #[test]
    fn normalize_origin_strips_default_https_port() {
        let normalized = normalize_origin("https://example.com:443").expect("normalized");
        assert_eq!(normalized, "https://example.com");
    }

    #[test]
    fn verify_origin_accepts_default_port_equivalence() {
        assert!(verify_origin("https://example.com:443", "https://example.com").is_ok());
        assert!(verify_origin("http://example.com:80", "http://example.com/").is_ok());
    }

    #[test]
    fn normalize_rp_id_strips_port() {
        assert_eq!(normalize_rp_id("example.com:443"), "example.com");
        assert_eq!(normalize_rp_id("[::1]:8443"), "::1");
    }
}

fn verify_rp_id_hash(rp_id: &str, rp_id_hash: &[u8; 32]) -> Result<(), AppError> {
    let expected = Sha256::digest(rp_id.as_bytes());
    if expected.as_slice() == rp_id_hash {
        Ok(())
    } else {
        Err(AppError::BadRequest("WebAuthn rpId mismatch".to_string()))
    }
}

fn decode_b64_any(input: &str) -> Result<Vec<u8>, AppError> {
    let s = input.trim();
    if let Ok(v) = general_purpose::URL_SAFE_NO_PAD.decode(s) {
        return Ok(v);
    }
    if let Ok(v) = general_purpose::URL_SAFE.decode(s) {
        return Ok(v);
    }
    if let Ok(v) = general_purpose::STANDARD.decode(s) {
        return Ok(v);
    }
    let mut padded = s.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    if let Ok(v) = general_purpose::URL_SAFE.decode(&padded) {
        return Ok(v);
    }
    general_purpose::STANDARD
        .decode(&padded)
        .map_err(|_| AppError::BadRequest("Invalid base64 payload".to_string()))
}

fn encode_b64url(bytes: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn parse_attestation_object(bytes: &[u8]) -> Result<([u8; 32], u32, Vec<u8>, Vec<u8>), AppError> {
    let value: CborValue = ciborium::de::from_reader(Cursor::new(bytes))
        .map_err(|_| AppError::BadRequest("Invalid WebAuthn attestation".to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| AppError::BadRequest("Invalid WebAuthn attestation".to_string()))?;
    let auth_data = map_get_text(map, "authData")
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| AppError::BadRequest("Invalid WebAuthn attestation".to_string()))?;

    let parsed = parse_auth_data(auth_data, true)?;
    let cred_id = parsed
        .credential_id
        .ok_or_else(|| AppError::BadRequest("Missing WebAuthn credential id".to_string()))?;
    let cred_key = parsed
        .credential_public_key_cose
        .ok_or_else(|| AppError::BadRequest("Missing WebAuthn credential key".to_string()))?;
    Ok((parsed.rp_id_hash, parsed.sign_count, cred_id, cred_key))
}

fn parse_auth_data(data: &[u8], expect_attested_data: bool) -> Result<ParsedAuthData, AppError> {
    if data.len() < 37 {
        return Err(AppError::BadRequest(
            "Invalid WebAuthn authData".to_string(),
        ));
    }

    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&data[..32]);
    let flags = data[32];
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);

    if (flags & 0x01) == 0 {
        return Err(AppError::BadRequest(
            "WebAuthn user presence is required".to_string(),
        ));
    }

    let mut credential_id = None;
    let mut credential_public_key_cose = None;
    if expect_attested_data || (flags & 0x40) != 0 {
        if (flags & 0x40) == 0 {
            return Err(AppError::BadRequest(
                "WebAuthn attested credential data missing".to_string(),
            ));
        }
        let mut offset = 37usize;
        if data.len() < offset + 18 {
            return Err(AppError::BadRequest(
                "Invalid WebAuthn attested credential data".to_string(),
            ));
        }

        offset += 16; // aaguid
        let cred_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + cred_len {
            return Err(AppError::BadRequest(
                "Invalid WebAuthn credential id".to_string(),
            ));
        }
        credential_id = Some(data[offset..offset + cred_len].to_vec());
        offset += cred_len;

        let mut cursor = Cursor::new(&data[offset..]);
        let _parsed_key: CborValue = ciborium::de::from_reader(&mut cursor)
            .map_err(|_| AppError::BadRequest("Invalid WebAuthn credential key".to_string()))?;
        let used = cursor.position() as usize;
        if used == 0 || offset + used > data.len() {
            return Err(AppError::BadRequest(
                "Invalid WebAuthn credential key".to_string(),
            ));
        }
        credential_public_key_cose = Some(data[offset..offset + used].to_vec());
    }

    Ok(ParsedAuthData {
        rp_id_hash,
        flags,
        sign_count,
        credential_id,
        credential_public_key_cose,
    })
}

fn parse_p256_verifying_key(cose_key_bytes: &[u8]) -> Result<VerifyingKey, AppError> {
    let value: CborValue = ciborium::de::from_reader(Cursor::new(cose_key_bytes))
        .map_err(|_| AppError::BadRequest("Invalid WebAuthn public key".to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| AppError::BadRequest("Invalid WebAuthn public key".to_string()))?;

    let kty = map_get_i128(map, 1)
        .ok_or_else(|| AppError::BadRequest("Invalid WebAuthn public key".to_string()))?;
    let alg = map_get_i128(map, 3)
        .ok_or_else(|| AppError::BadRequest("Invalid WebAuthn public key".to_string()))?;
    let crv = map_get_i128(map, -1)
        .ok_or_else(|| AppError::BadRequest("Invalid WebAuthn public key".to_string()))?;
    if kty != 2 || alg != -7 || crv != 1 {
        return Err(AppError::BadRequest(
            "Unsupported WebAuthn public key type".to_string(),
        ));
    }

    let x = map_get_bytes(map, -2)
        .ok_or_else(|| AppError::BadRequest("Invalid WebAuthn public key".to_string()))?;
    let y = map_get_bytes(map, -3)
        .ok_or_else(|| AppError::BadRequest("Invalid WebAuthn public key".to_string()))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(AppError::BadRequest(
            "Invalid WebAuthn public key length".to_string(),
        ));
    }

    let mut encoded = Vec::with_capacity(65);
    encoded.push(0x04);
    encoded.extend_from_slice(x);
    encoded.extend_from_slice(y);

    VerifyingKey::from_sec1_bytes(&encoded)
        .map_err(|_| AppError::BadRequest("Invalid WebAuthn public key".to_string()))
}

fn map_get_text<'a>(map: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
    map.iter().find_map(|(k, v)| match k {
        CborValue::Text(t) if t == key => Some(v),
        _ => None,
    })
}

fn map_get_i128(map: &[(CborValue, CborValue)], key: i128) -> Option<i128> {
    map.iter().find_map(|(k, v)| {
        let k = match k {
            CborValue::Integer(i) => i128::try_from(*i).ok(),
            _ => None,
        }?;
        if k == key {
            match v {
                CborValue::Integer(i) => i128::try_from(*i).ok(),
                _ => None,
            }
        } else {
            None
        }
    })
}

fn map_get_bytes<'a>(map: &'a [(CborValue, CborValue)], key: i128) -> Option<&'a [u8]> {
    map.iter().find_map(|(k, v)| {
        let k = match k {
            CborValue::Integer(i) => i128::try_from(*i).ok(),
            _ => None,
        }?;
        if k == key {
            v.as_bytes().map(|bytes| bytes.as_slice())
        } else {
            None
        }
    })
}

async fn list_stored_credentials(
    db: &D1Database,
    user_id: &str,
) -> Result<Vec<StoredCredentialRow>, AppError> {
    let rows: Vec<Value> = db
        .prepare(
            "SELECT slot_id, credential_id_b64url, public_key_cose_b64, sign_count, name
             FROM two_factor_webauthn
             WHERE user_id = ?1
             ORDER BY slot_id ASC",
        )
        .bind(&[user_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let slot_id = row
            .get("slot_id")
            .and_then(|v| v.as_i64())
            .ok_or(AppError::Database)? as i32;
        let credential_id_b64url = row
            .get("credential_id_b64url")
            .and_then(|v| v.as_str())
            .ok_or(AppError::Database)?
            .to_string();
        let public_key_cose_b64 = row
            .get("public_key_cose_b64")
            .and_then(|v| v.as_str())
            .ok_or(AppError::Database)?
            .to_string();
        let sign_count = row.get("sign_count").and_then(|v| v.as_i64()).unwrap_or(0);
        let name = row
            .get("name")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());
        out.push(StoredCredentialRow {
            slot_id,
            credential_id_b64url,
            public_key_cose_b64,
            sign_count,
            name,
        });
    }
    Ok(out)
}

async fn get_stored_credential(
    db: &D1Database,
    user_id: &str,
    credential_id_b64url: &str,
) -> Result<Option<StoredCredentialRow>, AppError> {
    let row: Option<Value> = db
        .prepare(
            "SELECT slot_id, credential_id_b64url, public_key_cose_b64, sign_count, name
             FROM two_factor_webauthn
             WHERE user_id = ?1 AND credential_id_b64url = ?2
             LIMIT 1",
        )
        .bind(&[user_id.into(), credential_id_b64url.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let Some(row) = row else {
        return Ok(None);
    };

    let slot_id = row
        .get("slot_id")
        .and_then(|v| v.as_i64())
        .ok_or(AppError::Database)? as i32;
    let credential_id_b64url = row
        .get("credential_id_b64url")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Database)?
        .to_string();
    let public_key_cose_b64 = row
        .get("public_key_cose_b64")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Database)?
        .to_string();
    let sign_count = row.get("sign_count").and_then(|v| v.as_i64()).unwrap_or(0);
    let name = row
        .get("name")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());

    Ok(Some(StoredCredentialRow {
        slot_id,
        credential_id_b64url,
        public_key_cose_b64,
        sign_count,
        name,
    }))
}

async fn get_stored_credential_by_credential_id(
    db: &D1Database,
    credential_id_b64url: &str,
) -> Result<Option<StoredCredentialLookupRow>, AppError> {
    let row: Option<Value> = db
        .prepare(
            "SELECT user_id, slot_id, public_key_cose_b64, sign_count, encrypted_user_key, encrypted_private_key
             FROM two_factor_webauthn
             WHERE credential_id_b64url = ?1
             LIMIT 1",
        )
        .bind(&[credential_id_b64url.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let Some(row) = row else {
        return Ok(None);
    };

    let user_id = row
        .get("user_id")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Database)?
        .to_string();
    let slot_id = row
        .get("slot_id")
        .and_then(|v| v.as_i64())
        .ok_or(AppError::Database)? as i32;
    let public_key_cose_b64 = row
        .get("public_key_cose_b64")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Database)?
        .to_string();
    let sign_count = row.get("sign_count").and_then(|v| v.as_i64()).unwrap_or(0);
    let encrypted_user_key = row
        .get("encrypted_user_key")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    let encrypted_private_key = row
        .get("encrypted_private_key")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());

    Ok(Some(StoredCredentialLookupRow {
        user_id,
        slot_id,
        public_key_cose_b64,
        sign_count,
        encrypted_user_key,
        encrypted_private_key,
    }))
}

async fn upsert_credential(
    db: &D1Database,
    user_id: &str,
    slot_id: i32,
    name: &str,
    credential_id_raw: &[u8],
    credential_public_key_cose: &[u8],
    sign_count: i64,
) -> Result<(), AppError> {
    let now = Utc::now().to_rfc3339();
    let credential_id_b64url = encode_b64url(credential_id_raw);
    let public_key_cose_b64 = general_purpose::STANDARD.encode(credential_public_key_cose);
    db.prepare(
        "INSERT INTO two_factor_webauthn (
            user_id, slot_id, name, credential_id_b64url, public_key_cose_b64, sign_count,
            prf_status, encrypted_public_key, encrypted_user_key, encrypted_private_key,
            created_at, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(user_id, slot_id) DO UPDATE SET
            name = excluded.name,
            credential_id_b64url = excluded.credential_id_b64url,
            public_key_cose_b64 = excluded.public_key_cose_b64,
            sign_count = excluded.sign_count,
            prf_status = excluded.prf_status,
            encrypted_public_key = excluded.encrypted_public_key,
            encrypted_user_key = excluded.encrypted_user_key,
            encrypted_private_key = excluded.encrypted_private_key,
            updated_at = excluded.updated_at",
    )
    .bind(&[
        user_id.into(),
        f64::from(slot_id).into(),
        name.into(),
        credential_id_b64url.into(),
        public_key_cose_b64.into(),
        (sign_count as f64).into(),
        f64::from(WEBAUTHN_PRF_STATUS_UNSUPPORTED).into(),
        JsValue::NULL.into(),
        JsValue::NULL.into(),
        JsValue::NULL.into(),
        now.clone().into(),
        now.into(),
    ])?
    .run()
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::BadRequest("WebAuthn key already exists".to_string())
        } else {
            AppError::Database
        }
    })?;
    Ok(())
}

async fn upsert_pending_challenge(
    db: &D1Database,
    user_id: &str,
    challenge_type: &str,
    challenge_b64url: &str,
    rp_id: &str,
    origin: &str,
) -> Result<(), AppError> {
    let now = Utc::now();
    let expires_at = (now + Duration::seconds(CHALLENGE_TTL_SECONDS)).to_rfc3339();
    let now = now.to_rfc3339();
    db.prepare(
        "INSERT INTO webauthn_challenges (
            user_id, challenge_b64url, challenge_type, rp_id, origin, expires_at, created_at, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(user_id) DO UPDATE SET
            challenge_b64url = excluded.challenge_b64url,
            challenge_type = excluded.challenge_type,
            rp_id = excluded.rp_id,
            origin = excluded.origin,
            expires_at = excluded.expires_at,
            updated_at = excluded.updated_at",
    )
    .bind(&[
        user_id.into(),
        challenge_b64url.into(),
        challenge_type.into(),
        rp_id.into(),
        origin.into(),
        expires_at.into(),
        now.clone().into(),
        now.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

async fn pop_pending_challenge(
    db: &D1Database,
    user_id: &str,
) -> Result<Option<PendingChallengeRow>, AppError> {
    let row: Option<Value> = db
        .prepare(
            "SELECT challenge_b64url, challenge_type, rp_id, origin, expires_at
             FROM webauthn_challenges
             WHERE user_id = ?1
             LIMIT 1",
        )
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    db.prepare("DELETE FROM webauthn_challenges WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    let Some(row) = row else {
        return Ok(None);
    };

    let challenge_b64url = row
        .get("challenge_b64url")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Database)?
        .to_string();
    let challenge_type = row
        .get("challenge_type")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Database)?
        .to_string();
    let rp_id = row
        .get("rp_id")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Database)?
        .to_string();
    let origin = row
        .get("origin")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Database)?
        .to_string();
    let expires_at = row
        .get("expires_at")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Database)?
        .to_string();

    Ok(Some(PendingChallengeRow {
        challenge_b64url,
        challenge_type,
        rp_id,
        origin,
        expires_at,
    }))
}

fn is_expired(expires_at: &str) -> Result<bool, AppError> {
    let expires = chrono::DateTime::parse_from_rfc3339(expires_at)
        .map_err(|_| AppError::Database)?
        .with_timezone(&Utc);
    Ok(Utc::now() >= expires)
}
