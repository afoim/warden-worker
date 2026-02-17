use axum::{extract::{Query, State}, Json};
use serde_json::Value;
use serde::Deserialize;
use std::sync::Arc;
use worker::Env;

use crate::{
    auth::Claims,
    db,
    domains,
    error::AppError,
    models::{
        cipher::{Cipher, CipherDBModel},
        folder::{Folder, FolderResponse},
        send::{send_to_json, SendDBModel},
        sync::{Profile, SyncResponse, UserDecryption},
        user::User,
    },
    two_factor,
};

const KDF_TYPE_PBKDF2: i32 = 0;
const KDF_TYPE_ARGON2ID: i32 = 1;
const ARGON2ID_MEMORY_DEFAULT_MB: i32 = 64;
const ARGON2ID_PARALLELISM_DEFAULT: i32 = 4;

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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncQuery {
    exclude_domains: Option<bool>,
}

#[worker::send]
pub async fn get_sync_data(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Query(q): Query<SyncQuery>,
) -> Result<Json<SyncResponse>, AppError> {
    let user_id = claims.sub;
    let db = db::get_db(&env)?;

    // Fetch profile
    let user: User = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Fetch folders
    let folders_db: Vec<Folder> = db
        .prepare("SELECT * FROM folders WHERE user_id = ?1")
        .bind(&[user_id.clone().into()])?
        .all()
        .await?
        .results()?;

    let folders: Vec<FolderResponse> = folders_db.into_iter().map(|f| f.into()).collect();

    // Fetch ciphers
    let ciphers: Vec<Value> = db
        .prepare("SELECT * FROM ciphers WHERE user_id = ?1")
        .bind(&[user_id.clone().into()])?
        .all()
        .await?
        .results()?;

    let ciphers = ciphers
        .into_iter()
        .filter_map(
            |cipher| match serde_json::from_value::<CipherDBModel>(cipher.clone()) {
                Ok(cipher) => Some(cipher),
                Err(err) => {
                    log::warn!("Cannot parse {err:?} {cipher:?}");
                    None
                }
            },
        )
        .map(|cipher| cipher.into())
        .collect::<Vec<Cipher>>();

    let send_rows: Vec<Value> = db
        .prepare("SELECT * FROM sends WHERE user_id = ?1 ORDER BY updated_at DESC")
        .bind(&[user_id.clone().into()])?
        .all()
        .await?
        .results()?;
    let sends = send_rows
        .into_iter()
        .filter_map(|v| serde_json::from_value::<SendDBModel>(v).ok())
        .map(|s| send_to_json(&s))
        .collect::<Vec<_>>();

    let time = chrono::DateTime::parse_from_rfc3339(&user.created_at)
        .map_err(|_| AppError::Internal)?
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let user_key = user.key.clone();
    let user_email = user.email.clone();
    let (kdf_memory, kdf_parallelism) = normalize_kdf_for_response(
        user.kdf_type,
        user.kdf_iterations,
        user.kdf_memory,
        user.kdf_parallelism,
    );
    let profile = Profile {
        id: user.id,
        name: user.name.unwrap_or_default(),
        email: user_email.clone(),
        avatar_color: user.avatar_color,
        master_password_hint: user.master_password_hint,
        security_stamp: user.security_stamp,
        object: "profile".to_string(),
        premium: true,
        premium_from_organization: false,
        email_verified: user.email_verified,
        force_password_reset: false,
        two_factor_enabled: two_factor::is_authenticator_enabled(&db, &user_id).await?,
        uses_key_connector: false,
        creation_date: time,
        key: user_key.clone(),
        private_key: user.private_key,
        culture: "en-US".to_string(),
        organizations: Vec::new(),
        providers: Vec::new(),
        provider_organizations: Vec::new(),
    };

    let user_decryption = UserDecryption {
        master_password_unlock: serde_json::json!({
            "kdf": {
                "kdfType": user.kdf_type,
                "iterations": user.kdf_iterations,
                "memory": kdf_memory,
                "parallelism": kdf_parallelism
            },
            "masterKeyEncryptedUserKey": user_key,
            "masterKeyWrappedUserKey": user_key,
            "salt": user_email
        }),
    };

    let domains = if q.exclude_domains.unwrap_or(false) {
        Value::Null
    } else {
        domains::build_domains_object(&db, &user_id, false).await?
    };

    let response = SyncResponse {
        profile,
        folders,
        collections: Vec::new(),
        policies: Vec::new(),
        ciphers,
        sends,
        domains,
        user_decryption,
        object: "sync".to_string(),
    };

    Ok(Json(response))
}
