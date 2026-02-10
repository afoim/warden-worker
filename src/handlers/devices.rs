use axum::{extract::State, http::HeaderMap, Json};
use axum::extract::Path;
use base64::{engine::general_purpose, Engine as _};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use worker::Env;

use crate::{db, error::AppError};

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

#[worker::send]
pub async fn knowndevice(
    headers: HeaderMap,
    State(env): State<Arc<Env>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_devices_table(&db).await?;

    let email_b64 = headers
        .get("x-request-email")
        .or_else(|| headers.get("X-Request-Email"))
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("X-Request-Email value is required".to_string()))?;
    let device_identifier = headers
        .get("x-device-identifier")
        .or_else(|| headers.get("X-Device-Identifier"))
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("X-Device-Identifier value is required".to_string()))?;

    let email_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(email_b64.as_bytes())
        .map_err(|_| AppError::BadRequest("X-Request-Email value failed to decode as base64url".to_string()))?;
    let email = String::from_utf8(email_bytes)
        .map_err(|_| AppError::BadRequest("X-Request-Email value failed to decode as UTF-8".to_string()))?
        .to_lowercase();

    let user_id: Option<String> = db
        .prepare("SELECT id FROM users WHERE email = ?1")
        .bind(&[email.into()])?
        .first(Some("id"))
        .await
        .map_err(|_| AppError::Database)?;

    let Some(user_id) = user_id else {
        return Ok(Json(json!(false)));
    };

    let exists: Option<i64> = db
        .prepare("SELECT 1 AS ok FROM devices WHERE user_id = ?1 AND device_identifier = ?2 LIMIT 1")
        .bind(&[user_id.into(), device_identifier.into()])?
        .first(Some("ok"))
        .await
        .map_err(|_| AppError::Database)?;

    Ok(Json(json!(exists.is_some())))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushTokenRequest {
    push_token: String,
}

#[worker::send]
pub async fn device_token(
    State(_env): State<Arc<Env>>,
    Path(_device_id): Path<String>,
    Json(_payload): Json<PushTokenRequest>,
) -> Result<Json<()>, AppError> {
    Ok(Json(()))
}
