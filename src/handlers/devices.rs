use axum::{extract::State, http::HeaderMap, Json};
use axum::extract::Path;
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use worker::{wasm_bindgen::JsValue, Env};

use crate::{auth::Claims, db, error::AppError};

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

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(|s| s.to_string())
}

fn header_i64(headers: &HeaderMap, name: &str) -> Option<i64> {
    header_str(headers, name)?.trim().parse::<i64>().ok()
}

fn infer_device_name(headers: &HeaderMap) -> Option<String> {
    let client = header_str(headers, "bitwarden-client-name")
        .or_else(|| header_str(headers, "Bitwarden-Client-Name"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let ver = header_str(headers, "bitwarden-client-version")
        .or_else(|| header_str(headers, "Bitwarden-Client-Version"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    match (client, ver) {
        (Some(c), Some(v)) => Some(format!("{c} {v}")),
        (Some(c), None) => Some(c),
        _ => None,
    }
}

fn infer_device_type(headers: &HeaderMap) -> Option<i64> {
    header_i64(headers, "device-type").or_else(|| header_i64(headers, "Device-Type"))
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
    claims: Claims,
    headers: HeaderMap,
    State(env): State<Arc<Env>>,
    Path(device_identifier): Path<String>,
    Json(_payload): Json<PushTokenRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    ensure_devices_table(&db).await?;

    let inferred_name = infer_device_name(&headers);
    let inferred_type = infer_device_type(&headers);
    let now = Utc::now().to_rfc3339();

    db.prepare(
        "INSERT INTO devices (id, user_id, device_identifier, device_name, device_type, remember_token_hash, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)
         ON CONFLICT(user_id, device_identifier) DO UPDATE SET
           updated_at = excluded.updated_at,
           device_name = COALESCE(excluded.device_name, devices.device_name),
           device_type = COALESCE(excluded.device_type, devices.device_type)",
    )
    .bind(&[
        Uuid::new_v4().to_string().into(),
        claims.sub.into(),
        device_identifier.into(),
        js_opt_string(inferred_name),
        js_opt_i64(inferred_type),
        now.clone().into(),
        now.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(Json(()))
}

#[worker::send]
pub async fn get_devices(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_devices_table(&db).await?;

    let rows: Vec<Value> = db
        .prepare(
            "SELECT id, device_identifier, device_name, device_type, remember_token_hash, created_at, updated_at
             FROM devices
             WHERE user_id = ?1
             ORDER BY updated_at DESC",
        )
        .bind(&[claims.sub.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;

    let data = rows
        .into_iter()
        .map(|row| {
            let id = row.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let identifier = row
                .get("device_identifier")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name = row
                .get("device_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let device_type = row.get("device_type").and_then(|v| v.as_i64()).unwrap_or(0);
            let created_at = row
                .get("created_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let updated_at = row
                .get("updated_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let trusted = row
                .get("remember_token_hash")
                .and_then(|v| v.as_str())
                .is_some();

            json!({
                "id": id,
                "name": name,
                "identifier": identifier,
                "type": device_type,
                "creationDate": created_at,
                "revisionDate": updated_at,
                "lastSeenDate": updated_at,
                "isTrusted": trusted,
                "object": "device"
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "data": data,
        "object": "list",
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn get_device_by_identifier(
    claims: Claims,
    headers: HeaderMap,
    State(env): State<Arc<Env>>,
    Path(device_identifier): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_devices_table(&db).await?;

    let inferred_name = infer_device_name(&headers);
    let inferred_type = infer_device_type(&headers);
    let row: Option<Value> = db
        .prepare(
            "SELECT id, device_identifier, device_name, device_type, remember_token_hash, created_at, updated_at
             FROM devices
             WHERE user_id = ?1 AND device_identifier = ?2
             LIMIT 1",
        )
        .bind(&[claims.sub.clone().into(), device_identifier.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let now = Utc::now().to_rfc3339();
    let row = match row {
        Some(row) => row,
        None => {
            let device_id = Uuid::new_v4().to_string();
            db.prepare(
                "INSERT INTO devices (id, user_id, device_identifier, device_name, device_type, remember_token_hash, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)",
            )
            .bind(&[
                device_id.clone().into(),
                claims.sub.clone().into(),
                device_identifier.clone().into(),
                js_opt_string(inferred_name.clone()),
                js_opt_i64(inferred_type),
                now.clone().into(),
                now.clone().into(),
            ])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;

            db.prepare(
                "SELECT id, device_identifier, device_name, device_type, remember_token_hash, created_at, updated_at
                 FROM devices
                 WHERE id = ?1
                 LIMIT 1",
            )
            .bind(&[device_id.into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?
            .ok_or(AppError::Internal)?
        }
    };

    let row_device_type = row.get("device_type").and_then(|v| v.as_i64());
    let row_device_name = row
        .get("device_name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let row_id = row.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let row_created_at = row
        .get("created_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let row_updated_at = row
        .get("updated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let should_update_type = row_device_type.is_none() && inferred_type.is_some();
    let should_update_name = row_device_name
        .as_deref()
        .map(|s| s.trim().is_empty())
        .unwrap_or(true)
        && inferred_name.is_some();
    let updated = should_update_type || should_update_name;
    if updated {
        let update_name = inferred_name.clone().or(row_device_name.clone());
        let update_type = inferred_type.or(row_device_type);
        let _ = db
            .prepare("UPDATE devices SET device_name = ?1, device_type = ?2, updated_at = ?3 WHERE id = ?4")
            .bind(&[
                js_opt_string(update_name),
                js_opt_i64(update_type),
                now.clone().into(),
                row_id.clone().into(),
            ])
            .map_err(|_| AppError::Database)?
            .run()
            .await;
    }

    let identifier = row
        .get("device_identifier")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let name = inferred_name.or(row_device_name).unwrap_or_default();
    let device_type = inferred_type.or(row_device_type).unwrap_or(0);
    let created_at = row_created_at;
    let updated_at = if updated { now.clone() } else { row_updated_at };
    let trusted = row
        .get("remember_token_hash")
        .and_then(|v| v.as_str())
        .is_some();

    Ok(Json(json!({
        "id": row_id,
        "name": name,
        "identifier": identifier,
        "type": device_type,
        "creationDate": created_at,
        "revisionDate": updated_at,
        "lastSeenDate": updated_at,
        "isTrusted": trusted,
        "object": "device"
    })))
}
