use axum::{extract::State, Json};
use chrono::Utc;
use constant_time_eq::constant_time_eq;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use wasm_bindgen::JsValue;
use worker::{query, Env};

use crate::{
    auth::Claims,
    db,
    error::AppError,
    models::user::{KeyData, PreloginResponse, RegisterRequest, User},
    two_factor,
};

const KDF_TYPE_PBKDF2: i32 = 0;
const KDF_TYPE_ARGON2ID: i32 = 1;
const ARGON2ID_MEMORY_DEFAULT_MB: i32 = 64;
const ARGON2ID_PARALLELISM_DEFAULT: i32 = 4;

fn validate_kdf(
    kdf_type: i32,
    kdf_iterations: i32,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
) -> Result<(Option<i32>, Option<i32>), AppError> {
    match kdf_type {
        KDF_TYPE_PBKDF2 => {
            if kdf_iterations < 100_000 {
                return Err(AppError::BadRequest("Invalid kdfIterations".to_string()));
            }
            Ok((None, None))
        }
        KDF_TYPE_ARGON2ID => {
            if kdf_iterations < 1 {
                return Err(AppError::BadRequest("Invalid kdfIterations".to_string()));
            }
            let kdf_memory = kdf_memory.ok_or_else(|| {
                AppError::BadRequest("Missing kdfMemory for Argon2id".to_string())
            })?;
            let kdf_parallelism = kdf_parallelism.ok_or_else(|| {
                AppError::BadRequest("Missing kdfParallelism for Argon2id".to_string())
            })?;

            if !(15..=1024).contains(&kdf_memory) {
                return Err(AppError::BadRequest("Invalid kdfMemory".to_string()));
            }
            if !(1..=16).contains(&kdf_parallelism) {
                return Err(AppError::BadRequest("Invalid kdfParallelism".to_string()));
            }
            Ok((Some(kdf_memory), Some(kdf_parallelism)))
        }
        _ => Err(AppError::BadRequest("Invalid kdfType".to_string())),
    }
}

fn normalize_kdf_for_response(
    kdf_type: i32,
    kdf_iterations: i32,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
) -> (Option<i32>, Option<i32>) {
    match kdf_type {
        KDF_TYPE_PBKDF2 => (None, None),
        KDF_TYPE_ARGON2ID => {
            if kdf_iterations < 1 {
                return (Some(ARGON2ID_MEMORY_DEFAULT_MB), Some(ARGON2ID_PARALLELISM_DEFAULT));
            }
            let mem = kdf_memory.unwrap_or(ARGON2ID_MEMORY_DEFAULT_MB);
            let par = kdf_parallelism.unwrap_or(ARGON2ID_PARALLELISM_DEFAULT);
            let mem = if (15..=1024).contains(&mem) {
                mem
            } else {
                ARGON2ID_MEMORY_DEFAULT_MB
            };
            let par = if (1..=16).contains(&par) {
                par
            } else {
                ARGON2ID_PARALLELISM_DEFAULT
            };
            (Some(mem), Some(par))
        }
        _ => (None, None),
    }
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KdfData {
    #[serde(rename = "kdfType", alias = "kdf")]
    pub kdf: i32,
    #[serde(rename = "iterations", alias = "kdfIterations")]
    pub kdf_iterations: i32,
    #[serde(rename = "memory", alias = "kdfMemory")]
    pub kdf_memory: Option<i32>,
    #[serde(rename = "parallelism", alias = "kdfParallelism")]
    pub kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationData {
    #[serde(alias = "Salt", alias = "salt")]
    pub salt: String,
    #[serde(alias = "Kdf")]
    pub kdf: KdfData,
    #[serde(alias = "masterPasswordAuthenticationHash", alias = "MasterPasswordAuthenticationHash")]
    #[allow(dead_code)]
    pub master_password_authentication_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockData {
    #[serde(alias = "Salt", alias = "salt")]
    pub salt: String,
    #[serde(alias = "Kdf")]
    pub kdf: KdfData,
    #[serde(alias = "masterKeyWrappedUserKey", alias = "MasterKeyWrappedUserKey")]
    #[allow(dead_code)]
    pub master_key_wrapped_user_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfRequest {
    #[serde(alias = "newMasterPasswordHash", alias = "NewMasterPasswordHash")]
    pub new_master_password_hash: String,
    #[serde(alias = "Key")]
    pub key: String,
    #[serde(alias = "authenticationData", alias = "authentication_data", alias = "AuthenticationData")]
    pub authentication_data: AuthenticationData,
    #[serde(alias = "unlockData", alias = "unlock_data", alias = "UnlockData")]
    pub unlock_data: UnlockData,
    #[serde(alias = "masterPasswordHash", alias = "MasterPasswordHash")]
    pub master_password_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfFlatRequest {
    #[serde(alias = "kdfType")]
    pub kdf: i32,
    #[serde(alias = "kdfIterations", alias = "iterations")]
    pub kdf_iterations: i32,
    #[serde(alias = "kdfMemory", alias = "memory")]
    #[allow(dead_code)]
    pub kdf_memory: Option<i32>,
    #[serde(alias = "kdfParallelism", alias = "parallelism")]
    #[allow(dead_code)]
    pub kdf_parallelism: Option<i32>,
    #[serde(alias = "masterPasswordHash", alias = "MasterPasswordHash")]
    pub master_password_hash: String,
    #[serde(alias = "newMasterPasswordHash", alias = "NewMasterPasswordHash")]
    pub new_master_password_hash: String,
    #[serde(alias = "Key")]
    pub key: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ChangeKdfPayload {
    Vw(ChangeKdfRequest),
    Flat(ChangeKdfFlatRequest),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeMasterPasswordRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    pub master_password_hint: Option<String>,
    pub user_symmetric_key: String,
    #[serde(default)]
    pub user_asymmetric_keys: Option<KeyData>,
    #[serde(default)]
    pub kdf: Option<i32>,
    #[serde(default)]
    pub kdf_iterations: Option<i32>,
    #[serde(default)]
    pub kdf_memory: Option<i32>,
    #[serde(default)]
    pub kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeEmailRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    pub new_email: String,
    pub user_symmetric_key: String,
    #[serde(default)]
    pub kdf: Option<i32>,
    #[serde(default)]
    pub kdf_iterations: Option<i32>,
    #[serde(default)]
    pub kdf_memory: Option<i32>,
    #[serde(default)]
    pub kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileData {
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarData {
    pub avatar_color: Option<String>,
}

#[worker::send]
pub async fn profile(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let two_factor_enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?;
    let user: User = query!(
        &db,
        "SELECT * FROM users WHERE id = ?1",
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("User not found".to_string()))?;

    Ok(Json(json!({
        "id": user.id,
        "name": user.name.unwrap_or_default(),
        "email": user.email,
        "emailVerified": user.email_verified,
        "avatarColor": user.avatar_color,
        "premium": true,
        "premiumFromOrganization": false,
        "masterPasswordHint": user.master_password_hint,
        "culture": "en-US",
        "twoFactorEnabled": two_factor_enabled,
        "key": user.key,
        "privateKey": user.private_key,
        "securityStamp": user.security_stamp,
        "organizations": [],
        "object": "profile"
    })))
}

#[worker::send]
pub async fn post_profile(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<ProfileData>,
) -> Result<Json<Value>, AppError> {
    let name = payload.name.unwrap_or_default();

    if name.len() > 50 {
        return Err(AppError::BadRequest(
            "The field Name must be a string with a maximum length of 50.".to_string(),
        ));
    }

    let db = db::get_db(&env)?;
    let now = Utc::now().to_rfc3339();

    db.prepare("UPDATE users SET name = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[
            name.into(),
            now.into(),
            claims.sub.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    profile(claims, State(env)).await
}

#[worker::send]
pub async fn put_avatar(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<AvatarData>,
) -> Result<Json<Value>, AppError> {
    if let Some(color) = payload.avatar_color.as_deref() {
        if color.len() != 7 {
            return Err(AppError::BadRequest(
                "The field AvatarColor must be a HTML/Hex color code with a length of 7 characters"
                    .to_string(),
            ));
        }
    }

    let db = db::get_db(&env)?;
    let now = Utc::now().to_rfc3339();

    db.prepare("UPDATE users SET avatar_color = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[
            to_js_val(payload.avatar_color),
            now.into(),
            claims.sub.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    profile(claims, State(env)).await
}

#[worker::send]
pub async fn post_security_stamp(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().to_rfc3339();
    let security_stamp = Uuid::new_v4().to_string();

    db.prepare("UPDATE users SET security_stamp = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[
            security_stamp.clone().into(),
            now.into(),
            claims.sub.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    let two_factor_enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?;
    let user: User = query!(
        &db,
        "SELECT * FROM users WHERE id = ?1",
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("User not found".to_string()))?;

    Ok(Json(json!({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "emailVerified": user.email_verified,
        "avatarColor": user.avatar_color,
        "premium": true,
        "premiumFromOrganization": false,
        "masterPasswordHint": user.master_password_hint,
        "culture": "en-US",
        "twoFactorEnabled": two_factor_enabled,
        "key": user.key,
        "privateKey": user.private_key,
        "securityStamp": user.security_stamp,
        "organizations": [],
        "object": "profile"
    })))
}

#[worker::send]
pub async fn revision_date(
    _claims: Claims,
) -> Result<Json<i64>, AppError> {
    Ok(Json(chrono::Utc::now().timestamp_millis()))
}

#[worker::send]
pub async fn prelogin(
    State(env): State<Arc<Env>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<PreloginResponse>, AppError> {
    let email = payload["email"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("Missing email".to_string()))?;
    let db = db::get_db(&env)?;

    let stmt = db.prepare(
        "SELECT kdf_type, kdf_iterations, kdf_memory, kdf_parallelism FROM users WHERE email = ?1",
    );
    let query = stmt.bind(&[email.into()])?;
    let row: Option<Value> = query
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let (kdf_type, kdf_iterations, kdf_memory, kdf_parallelism) = match row {
        Some(v) => {
            let kdf_type = v
                .get("kdf_type")
                .and_then(|x| x.as_i64())
                .unwrap_or(0) as i32;
            let kdf_iterations = v
                .get("kdf_iterations")
                .and_then(|x| x.as_i64())
                .unwrap_or(600_000) as i32;
            let kdf_memory = v.get("kdf_memory").and_then(|x| x.as_i64()).map(|v| v as i32);
            let kdf_parallelism = v
                .get("kdf_parallelism")
                .and_then(|x| x.as_i64())
                .map(|v| v as i32);
            (kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)
        }
        None => (KDF_TYPE_PBKDF2, 600_000, None, None),
    };

    let (kdf_memory, kdf_parallelism) =
        normalize_kdf_for_response(kdf_type, kdf_iterations, kdf_memory, kdf_parallelism);

    Ok(Json(PreloginResponse {
        kdf: kdf_type,
        kdf_iterations,
        kdf_memory,
        kdf_parallelism,
    }))
}

#[worker::send]
pub async fn register(
    State(env): State<Arc<Env>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user_count: Option<i64> = db
        .prepare("SELECT COUNT(1) AS user_count FROM users")
        .first(Some("user_count"))
        .await
        .map_err(|_| AppError::Database)?;
    let user_count = user_count.unwrap_or(0);
    if user_count == 0 {
        let allowed_emails = env
            .secret("ALLOWED_EMAILS")
            .map_err(|_| AppError::Internal)?;
        let allowed_emails = allowed_emails
            .as_ref()
            .as_string()
            .ok_or_else(|| AppError::Internal)?;
        if allowed_emails
            .split(",")
            .all(|email| email.trim() != payload.email)
        {
            return Err(AppError::Unauthorized("Not allowed to signup".to_string()));
        }
    }
    let now = Utc::now().to_rfc3339();
    let name = payload.name.unwrap_or_default();
    let (kdf_memory, kdf_parallelism) = validate_kdf(
        payload.kdf,
        payload.kdf_iterations,
        payload.kdf_memory,
        payload.kdf_parallelism,
    )?;
    let user = User {
        id: Uuid::new_v4().to_string(),
        name: Some(name),
        email: payload.email.to_lowercase(),
        email_verified: false,
        avatar_color: None,
        master_password_hash: payload.master_password_hash,
        master_password_hint: payload.master_password_hint,
        key: payload.user_symmetric_key,
        private_key: payload.user_asymmetric_keys.encrypted_private_key,
        public_key: payload.user_asymmetric_keys.public_key,
        kdf_type: payload.kdf,
        kdf_iterations: payload.kdf_iterations,
        kdf_memory,
        kdf_parallelism,
        security_stamp: Uuid::new_v4().to_string(),
        created_at: now.clone(),
        updated_at: now,
    };

    query!(
        &db,
        "INSERT INTO users (id, name, email, email_verified, avatar_color, master_password_hash, master_password_hint, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
         user.id,
         user.name,
         user.email,
         user.email_verified,
         user.avatar_color,
         user.master_password_hash,
         user.master_password_hint,
         user.key,
         user.private_key,
         user.public_key,
         user.kdf_type,
         user.kdf_iterations,
         user.kdf_memory,
         user.kdf_parallelism,
         user.security_stamp,
         user.created_at,
         user.updated_at
    ).map_err(|_|{
        AppError::Database
    })?
    .run()
    .await
    .map_err(|_|{
        AppError::Database
    })?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn change_master_password(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<ChangeMasterPasswordRequest>,
) -> Result<Json<Value>, AppError> {
    if payload.master_password_hash.is_empty() || payload.new_master_password_hash.is_empty() {
        return Err(AppError::BadRequest("Missing masterPasswordHash".to_string()));
    }
    if payload.user_symmetric_key.is_empty() {
        return Err(AppError::BadRequest("Missing userSymmetricKey".to_string()));
    }

    let db = db::get_db(&env)?;
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    if !constant_time_eq(
        user.master_password_hash.as_bytes(),
        payload.master_password_hash.as_bytes(),
    ) {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let now = Utc::now().to_rfc3339();
    let security_stamp = Uuid::new_v4().to_string();
    let master_password_hint = payload.master_password_hint.clone();
    let private_key = payload
        .user_asymmetric_keys
        .as_ref()
        .map(|k| k.encrypted_private_key.clone())
        .unwrap_or_else(|| user.private_key.clone());
    let public_key = payload
        .user_asymmetric_keys
        .as_ref()
        .map(|k| k.public_key.clone())
        .unwrap_or_else(|| user.public_key.clone());
    let kdf_type = payload.kdf.unwrap_or(user.kdf_type);
    let kdf_iterations = payload.kdf_iterations.unwrap_or(user.kdf_iterations);
    let kdf_memory_in = payload.kdf_memory.or(user.kdf_memory);
    let kdf_parallelism_in = payload.kdf_parallelism.or(user.kdf_parallelism);
    let (kdf_memory, kdf_parallelism) =
        validate_kdf(kdf_type, kdf_iterations, kdf_memory_in, kdf_parallelism_in)?;

    db.prepare(
        "UPDATE users SET master_password_hash = ?1, master_password_hint = ?2, key = ?3, private_key = ?4, public_key = ?5, kdf_type = ?6, kdf_iterations = ?7, kdf_memory = ?8, kdf_parallelism = ?9, security_stamp = ?10, updated_at = ?11 WHERE id = ?12",
    )
    .bind(&[
        payload.new_master_password_hash.into(),
        to_js_val(master_password_hint),
        payload.user_symmetric_key.into(),
        private_key.into(),
        public_key.into(),
        kdf_type.into(),
        kdf_iterations.into(),
        to_js_val(kdf_memory),
        to_js_val(kdf_parallelism),
        security_stamp.into(),
        now.into(),
        claims.sub.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn change_email(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<ChangeEmailRequest>,
) -> Result<Json<Value>, AppError> {
    if payload.master_password_hash.is_empty() || payload.new_master_password_hash.is_empty() {
        return Err(AppError::BadRequest("Missing masterPasswordHash".to_string()));
    }
    if payload.new_email.trim().is_empty() {
        return Err(AppError::BadRequest("Missing newEmail".to_string()));
    }
    if payload.user_symmetric_key.is_empty() {
        return Err(AppError::BadRequest("Missing userSymmetricKey".to_string()));
    }

    let new_email = payload.new_email.to_lowercase();

    let db = db::get_db(&env)?;
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    if !constant_time_eq(
        user.master_password_hash.as_bytes(),
        payload.master_password_hash.as_bytes(),
    ) {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let now = Utc::now().to_rfc3339();
    let security_stamp = Uuid::new_v4().to_string();
    let kdf_type = payload.kdf.unwrap_or(user.kdf_type);
    let kdf_iterations = payload.kdf_iterations.unwrap_or(user.kdf_iterations);
    let kdf_memory_in = payload.kdf_memory.or(user.kdf_memory);
    let kdf_parallelism_in = payload.kdf_parallelism.or(user.kdf_parallelism);
    let (kdf_memory, kdf_parallelism) =
        validate_kdf(kdf_type, kdf_iterations, kdf_memory_in, kdf_parallelism_in)?;

    db.prepare(
        "UPDATE users SET email = ?1, email_verified = ?2, master_password_hash = ?3, key = ?4, kdf_type = ?5, kdf_iterations = ?6, kdf_memory = ?7, kdf_parallelism = ?8, security_stamp = ?9, updated_at = ?10 WHERE id = ?11",
    )
    .bind(&[
        new_email.into(),
        false.into(),
        payload.new_master_password_hash.into(),
        payload.user_symmetric_key.into(),
        kdf_type.into(),
        kdf_iterations.into(),
        to_js_val(kdf_memory),
        to_js_val(kdf_parallelism),
        security_stamp.into(),
        now.into(),
        claims.sub.into(),
    ])?
    .run()
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::BadRequest("Email already in use".to_string())
        } else {
            AppError::Database
        }
    })?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn post_kdf(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<ChangeKdfPayload>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    if !constant_time_eq(
        user.master_password_hash.as_bytes(),
        match &payload {
            ChangeKdfPayload::Vw(p) => p.master_password_hash.as_bytes(),
            ChangeKdfPayload::Flat(p) => p.master_password_hash.as_bytes(),
        },
    ) {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let (new_master_password_hash, key, kdf_type, kdf_iterations, kdf_memory_in, kdf_parallelism_in) =
        match &payload {
        ChangeKdfPayload::Vw(p) => {
            if p.authentication_data.kdf != p.unlock_data.kdf {
                return Err(AppError::BadRequest(
                    "KDF settings must be equal for authentication and unlock".to_string(),
                ));
            }

            if !user.email.eq_ignore_ascii_case(&p.authentication_data.salt)
                || !user.email.eq_ignore_ascii_case(&p.unlock_data.salt)
            {
                return Err(AppError::BadRequest("Invalid master password salt".to_string()));
            }

            (
                &p.new_master_password_hash,
                &p.key,
                p.unlock_data.kdf.kdf,
                p.unlock_data.kdf.kdf_iterations,
                p.unlock_data.kdf.kdf_memory,
                p.unlock_data.kdf.kdf_parallelism,
            )
        }
        ChangeKdfPayload::Flat(p) => {
            (
                &p.new_master_password_hash,
                &p.key,
                p.kdf,
                p.kdf_iterations,
                p.kdf_memory,
                p.kdf_parallelism,
            )
        }
    };

    let (kdf_memory, kdf_parallelism) =
        validate_kdf(kdf_type, kdf_iterations, kdf_memory_in, kdf_parallelism_in)?;

    let now = Utc::now().to_rfc3339();
    let security_stamp = Uuid::new_v4().to_string();

    db.prepare(
        "UPDATE users SET master_password_hash = ?1, key = ?2, kdf_type = ?3, kdf_iterations = ?4, kdf_memory = ?5, kdf_parallelism = ?6, security_stamp = ?7, updated_at = ?8 WHERE id = ?9",
    )
    .bind(&[
        new_master_password_hash.to_string().into(),
        key.to_string().into(),
        kdf_type.into(),
        kdf_iterations.into(),
        to_js_val(kdf_memory),
        to_js_val(kdf_parallelism),
        security_stamp.into(),
        now.into(),
        claims.sub.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(Json(json!({})))
}

fn to_js_val<T: Into<JsValue>>(val: Option<T>) -> JsValue {
    val.map(Into::into).unwrap_or(JsValue::NULL)
}

#[worker::send]
pub async fn send_verification_email() -> String {
    "fixed-token-to-mock".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_kdf_pbkdf2_ok() {
        let (m, p) = validate_kdf(KDF_TYPE_PBKDF2, 600_000, Some(64), Some(4)).unwrap();
        assert_eq!(m, None);
        assert_eq!(p, None);
    }

    #[test]
    fn validate_kdf_pbkdf2_iterations_too_low() {
        assert!(validate_kdf(KDF_TYPE_PBKDF2, 99_999, None, None).is_err());
    }

    #[test]
    fn validate_kdf_argon2id_requires_params() {
        assert!(validate_kdf(KDF_TYPE_ARGON2ID, 3, None, Some(4)).is_err());
        assert!(validate_kdf(KDF_TYPE_ARGON2ID, 3, Some(64), None).is_err());
    }

    #[test]
    fn validate_kdf_argon2id_range_checks() {
        assert!(validate_kdf(KDF_TYPE_ARGON2ID, 3, Some(14), Some(4)).is_err());
        assert!(validate_kdf(KDF_TYPE_ARGON2ID, 3, Some(1025), Some(4)).is_err());
        assert!(validate_kdf(KDF_TYPE_ARGON2ID, 3, Some(64), Some(0)).is_err());
        assert!(validate_kdf(KDF_TYPE_ARGON2ID, 3, Some(64), Some(17)).is_err());
    }

    #[test]
    fn validate_kdf_argon2id_ok() {
        let (m, p) = validate_kdf(KDF_TYPE_ARGON2ID, 3, Some(64), Some(4)).unwrap();
        assert_eq!(m, Some(64));
        assert_eq!(p, Some(4));
    }

    #[test]
    fn normalize_kdf_for_response_defaults_argon2id() {
        let (m, p) = normalize_kdf_for_response(KDF_TYPE_ARGON2ID, 3, None, None);
        assert_eq!(m, Some(ARGON2ID_MEMORY_DEFAULT_MB));
        assert_eq!(p, Some(ARGON2ID_PARALLELISM_DEFAULT));
    }
}
