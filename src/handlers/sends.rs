use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    response::Response,
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use constant_time_eq::constant_time_eq;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;
use worker::{query, Env};

use crate::{
    auth::Claims,
    db,
    error::AppError,
    models::send::{
        send_to_json, send_to_json_access, uuid_from_access_id, SendAccessData, SendDBModel,
        SendData, SendFileDBModel, SEND_TYPE_FILE, SEND_TYPE_TEXT,
    },
};

const SEND_FILE_B64_CHUNK_LEN: usize = 1_500_000;

fn now_rfc3339_millis() -> String {
    Utc::now()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn parse_rfc3339(s: &str) -> Result<DateTime<Utc>, AppError> {
    let dt = DateTime::parse_from_rfc3339(s).map_err(|_| AppError::BadRequest("Invalid date".to_string()))?;
    Ok(dt.with_timezone(&Utc))
}

fn display_size(bytes: i64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let kb = bytes as f64 / 1024.0;
    if kb < 1024.0 {
        return format!("{:.1} KB", kb);
    }
    let mb = kb / 1024.0;
    if mb < 1024.0 {
        return format!("{:.1} MB", mb);
    }
    let gb = mb / 1024.0;
    format!("{:.1} GB", gb)
}

fn hash_password(password: &str, salt_b64: &str) -> Result<String, AppError> {
    let salt = general_purpose::STANDARD
        .decode(salt_b64)
        .map_err(|_| AppError::Internal)?;
    let mut hasher = Sha256::new();
    hasher.update(&salt);
    hasher.update(password.as_bytes());
    let out = hasher.finalize();
    Ok(general_purpose::STANDARD.encode(out))
}

fn new_salt_b64() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    general_purpose::STANDARD.encode(bytes)
}

fn extract_send_payload_data(mut data: SendData) -> Result<(i32, String, Value), AppError> {
    let send_type = data.r#type;
    let mut payload = match send_type {
        SEND_TYPE_TEXT => data.text.take().ok_or_else(|| AppError::BadRequest("Missing text".to_string()))?,
        SEND_TYPE_FILE => data.file.take().ok_or_else(|| AppError::BadRequest("Missing file".to_string()))?,
        _ => return Err(AppError::BadRequest("Invalid send type".to_string())),
    };

    if let Some(obj) = payload.as_object_mut() {
        obj.remove("response");
    }

    Ok((send_type, data.key, payload))
}

async fn get_send_by_id(db: &worker::D1Database, send_id: &str) -> Result<Option<SendDBModel>, AppError> {
    let value: Option<Value> = db
        .prepare("SELECT * FROM sends WHERE id = ?1")
        .bind(&[send_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    Ok(value.and_then(|v| serde_json::from_value::<SendDBModel>(v).ok()))
}

async fn get_send_by_id_and_user(
    db: &worker::D1Database,
    send_id: &str,
    user_id: &str,
) -> Result<Option<SendDBModel>, AppError> {
    let value: Option<Value> = db
        .prepare("SELECT * FROM sends WHERE id = ?1 AND user_id = ?2")
        .bind(&[send_id.into(), user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    Ok(value.and_then(|v| serde_json::from_value::<SendDBModel>(v).ok()))
}

async fn update_send_access_count(db: &worker::D1Database, send_id: &str, delta: i32) -> Result<(), AppError> {
    db.prepare("UPDATE sends SET access_count = access_count + ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[
            delta.into(),
            now_rfc3339_millis().into(),
            send_id.into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(())
}

async fn get_creator_identifier(
    db: &worker::D1Database,
    send: &SendDBModel,
) -> Result<Option<String>, AppError> {
    if send.hide_email.unwrap_or(false) {
        return Ok(None);
    }
    let email: Option<String> = db
        .prepare("SELECT email FROM users WHERE id = ?1")
        .bind(&[send.user_id.clone().into()])?
        .first(Some("email"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(email)
}

fn validate_send_access(send: &SendDBModel) -> Result<(), AppError> {
    if send.disabled {
        return Err(AppError::NotFound("Send not found".to_string()));
    }

    if let Some(max_access_count) = send.max_access_count {
        if send.access_count >= max_access_count {
            return Err(AppError::NotFound("Send not found".to_string()));
        }
    }

    let now = Utc::now();
    if let Some(exp) = send.expiration_date.as_deref() {
        let exp = parse_rfc3339(exp)?;
        if now >= exp {
            return Err(AppError::NotFound("Send not found".to_string()));
        }
    }

    let del = parse_rfc3339(&send.deletion_date)?;
    if now >= del {
        return Err(AppError::NotFound("Send not found".to_string()));
    }

    Ok(())
}

fn validate_send_password(send: &SendDBModel, password: Option<String>) -> Result<(), AppError> {
    let Some(stored_hash_b64) = send.password_hash.as_deref() else {
        return Ok(());
    };
    let Some(stored_salt_b64) = send.password_salt.as_deref() else {
        return Err(AppError::Internal);
    };

    let Some(password) = password else {
        return Err(AppError::Unauthorized("Password not provided".to_string()));
    };
    let candidate = hash_password(&password, stored_salt_b64)?;
    if !constant_time_eq(stored_hash_b64.as_bytes(), candidate.as_bytes()) {
        return Err(AppError::BadRequest("Invalid password".to_string()));
    }
    Ok(())
}

#[worker::send]
pub async fn get_sends(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let rows: Vec<Value> = db
        .prepare("SELECT * FROM sends WHERE user_id = ?1 ORDER BY updated_at DESC")
        .bind(&[claims.sub.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;

    let data = rows
        .into_iter()
        .filter_map(|v| serde_json::from_value::<SendDBModel>(v).ok())
        .map(|s| send_to_json(&s))
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "data": data,
        "object": "list",
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn get_send(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(send_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let send = get_send_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;
    Ok(Json(send_to_json(&send)))
}

#[worker::send]
pub async fn delete_send(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(send_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let owned = get_send_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;

    if owned.r#type == SEND_TYPE_FILE {
        query!(
            &db,
            "DELETE FROM send_file_chunks WHERE send_file_id IN (SELECT id FROM send_files WHERE send_id = ?1 AND user_id = ?2)",
            send_id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

        query!(
            &db,
            "DELETE FROM send_files WHERE send_id = ?1 AND user_id = ?2",
            send_id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
    }

    query!(
        &db,
        "DELETE FROM sends WHERE id = ?1 AND user_id = ?2",
        send_id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn post_send(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<SendData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    if payload.r#type == SEND_TYPE_FILE {
        return Err(AppError::BadRequest("File sends should use /api/sends/file/v2".to_string()));
    }

    let payload = payload;
    let name = payload.name.clone();
    let notes = payload.notes.clone();
    let password = payload.password.clone();
    let max_access_count = payload.max_access_count;
    let expiration_date = payload.expiration_date.clone();
    let deletion_date = payload.deletion_date.clone();
    let disabled = payload.disabled;
    let hide_email = payload.hide_email;

    let (send_type, key, data_value) = extract_send_payload_data(payload)?;
    let send_id = Uuid::new_v4().to_string();
    let now = now_rfc3339_millis();

    let password_salt = password
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(|_| new_salt_b64());
    let password_hash = match (password.as_deref(), password_salt.as_deref()) {
        (Some(p), Some(salt)) if !p.trim().is_empty() => Some(hash_password(p, salt)?),
        _ => None,
    };

    let data_str = serde_json::to_string(&data_value).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "INSERT INTO sends (id, user_id, organization_id, type, name, notes, data, key, password_hash, password_salt, password_iter, max_access_count, access_count, created_at, updated_at, expiration_date, deletion_date, disabled, hide_email)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, 0, ?11, ?12, ?13, ?14, ?15, ?16)",
        send_id,
        claims.sub,
        send_type,
        name,
        notes,
        data_str,
        key,
        password_hash,
        password_salt,
        max_access_count,
        now,
        now,
        expiration_date,
        deletion_date,
        if disabled { 1 } else { 0 },
        hide_email.map(|b| if b { 1 } else { 0 })
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let send = get_send_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::Internal)?;
    Ok(Json(send_to_json(&send)))
}

#[worker::send]
pub async fn post_send_file_v2(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<SendData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    if payload.r#type != SEND_TYPE_FILE {
        return Err(AppError::BadRequest("Send content is not a file".to_string()));
    }

    let payload = payload;
    let file_length = payload
        .file_length
        .ok_or_else(|| AppError::BadRequest("Invalid send length".to_string()))?;
    if file_length < 0 {
        return Err(AppError::BadRequest("Send size can't be negative".to_string()));
    }

    let name = payload.name.clone();
    let notes = payload.notes.clone();
    let max_access_count = payload.max_access_count;
    let expiration_date = payload.expiration_date.clone();
    let deletion_date = payload.deletion_date.clone();
    let disabled = payload.disabled;
    let hide_email = payload.hide_email;

    let (send_type, key, mut data_value) = extract_send_payload_data(payload)?;

    let file_id = Uuid::new_v4().to_string();
    if let Some(obj) = data_value.as_object_mut() {
        obj.insert("id".to_string(), Value::String(file_id.clone()));
        obj.insert("size".to_string(), Value::Number(file_length.into()));
        obj.insert("sizeName".to_string(), Value::String(display_size(file_length)));
    }

    let send_id = Uuid::new_v4().to_string();
    let now = now_rfc3339_millis();
    let data_str = serde_json::to_string(&data_value).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "INSERT INTO sends (id, user_id, organization_id, type, name, notes, data, key, password_hash, password_salt, password_iter, max_access_count, access_count, created_at, updated_at, expiration_date, deletion_date, disabled, hide_email)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, NULL, NULL, NULL, ?8, 0, ?9, ?10, ?11, ?12, ?13, ?14)",
        send_id,
        claims.sub,
        send_type,
        name,
        notes,
        data_str,
        key,
        max_access_count,
        now,
        now,
        expiration_date,
        deletion_date,
        if disabled { 1 } else { 0 },
        hide_email.map(|b| if b { 1 } else { 0 })
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    query!(
        &db,
        "INSERT INTO send_files (id, send_id, user_id, file_name, size, mime, data_base64, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6, ?7)",
        file_id,
        send_id,
        claims.sub,
        data_value
            .get("fileName")
            .and_then(|v| v.as_str())
            .unwrap_or("file")
            .to_string(),
        file_length,
        now,
        now
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let send = get_send_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::Internal)?;

    Ok(Json(json!({
        "fileUploadType": 0,
        "object": "send-fileUpload",
        "url": format!("/sends/{}/file/{}", send_id, file_id),
        "sendResponse": send_to_json(&send)
    })))
}

#[worker::send]
pub async fn post_send_file_v2_data(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((send_id, file_id)): Path<(String, String)>,
    mut multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let send = get_send_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("Send not found. Unable to save the file.".to_string()))?;
    if send.r#type != SEND_TYPE_FILE {
        return Err(AppError::BadRequest("Send content is not a file".to_string()));
    }

    let size: Option<i64> = db
        .prepare("SELECT size FROM send_files WHERE id = ?1 AND send_id = ?2 AND user_id = ?3 LIMIT 1")
        .bind(&[file_id.clone().into(), send_id.clone().into(), claims.sub.clone().into()])?
        .first(Some("size"))
        .await
        .map_err(|_| AppError::Database)?;
    let size = size.ok_or_else(|| AppError::NotFound("Send not found. Unable to save the file.".to_string()))?;
    if size < 0 {
        return Err(AppError::BadRequest("Send size can't be negative".to_string()));
    }

    let now = now_rfc3339_millis();

    let estimated_b64_len: usize = ((size as usize + 2) / 3) * 4;
    let should_inline = estimated_b64_len <= SEND_FILE_B64_CHUNK_LEN;

    let mut uploaded = false;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::BadRequest("Invalid multipart".to_string()))?
    {
        let name = field.name().unwrap_or("").to_string();
        if name != "data" {
            continue;
        }

        uploaded = true;

        if should_inline {
            let mut carry: Vec<u8> = Vec::with_capacity(2);
            let mut data_b64 = String::new();
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid multipart data: {e}")))?
            {
                let mut combined = Vec::with_capacity(carry.len() + chunk.len());
                combined.extend_from_slice(&carry);
                combined.extend_from_slice(&chunk);

                let full_len = (combined.len() / 3) * 3;
                if full_len > 0 {
                    data_b64.push_str(&general_purpose::STANDARD.encode(&combined[..full_len]));
                }
                carry.clear();
                carry.extend_from_slice(&combined[full_len..]);
            }
            if !carry.is_empty() {
                data_b64.push_str(&general_purpose::STANDARD.encode(&carry));
            }

            query!(
                &db,
                "UPDATE send_files SET data_base64 = ?1, updated_at = ?2 WHERE id = ?3 AND send_id = ?4 AND user_id = ?5",
                data_b64,
                now,
                file_id,
                send_id,
                claims.sub
            )
            .map_err(|_| AppError::Database)?
            .run()
            .await?;

            query!(
                &db,
                "DELETE FROM send_file_chunks WHERE send_file_id = ?1",
                file_id
            )
            .map_err(|_| AppError::Database)?
            .run()
            .await?;
        } else {
            query!(
                &db,
                "UPDATE send_files SET data_base64 = NULL, updated_at = ?1 WHERE id = ?2 AND send_id = ?3 AND user_id = ?4",
                now,
                file_id,
                send_id,
                claims.sub
            )
            .map_err(|_| AppError::Database)?
            .run()
            .await?;

            query!(
                &db,
                "DELETE FROM send_file_chunks WHERE send_file_id = ?1",
                file_id
            )
            .map_err(|_| AppError::Database)?
            .run()
            .await?;

            let mut carry: Vec<u8> = Vec::with_capacity(2);
            let mut b64_buf = String::new();
            let mut chunk_index: i32 = 0;

            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid multipart data: {e}")))?
            {
                let mut combined = Vec::with_capacity(carry.len() + chunk.len());
                combined.extend_from_slice(&carry);
                combined.extend_from_slice(&chunk);

                let full_len = (combined.len() / 3) * 3;
                if full_len > 0 {
                    b64_buf.push_str(&general_purpose::STANDARD.encode(&combined[..full_len]));
                }
                carry.clear();
                carry.extend_from_slice(&combined[full_len..]);

                while b64_buf.len() >= SEND_FILE_B64_CHUNK_LEN {
                    let tail = b64_buf.split_off(SEND_FILE_B64_CHUNK_LEN);
                    let part = std::mem::replace(&mut b64_buf, tail);
                    query!(
                        &db,
                        "INSERT INTO send_file_chunks (send_file_id, chunk_index, data_base64, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                        file_id,
                        chunk_index,
                        part,
                        now,
                        now
                    )
                    .map_err(|_| AppError::Database)?
                    .run()
                    .await?;
                    chunk_index += 1;
                }
            }

            if !carry.is_empty() {
                b64_buf.push_str(&general_purpose::STANDARD.encode(&carry));
            }
            if !b64_buf.is_empty() {
                query!(
                    &db,
                    "INSERT INTO send_file_chunks (send_file_id, chunk_index, data_base64, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    file_id,
                    chunk_index,
                    b64_buf,
                    now,
                    now
                )
                .map_err(|_| AppError::Database)?
                .run()
                .await?;
            }
        }

        break;
    }

    if !uploaded {
        return Err(AppError::BadRequest("Missing file data".to_string()));
    }

    query!(
        &db,
        "UPDATE sends SET updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
        now,
        send_id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn post_access(
    State(env): State<Arc<Env>>,
    Path(access_id): Path<String>,
    Json(payload): Json<SendAccessData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let send_id = uuid_from_access_id(&access_id).ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;
    let send = get_send_by_id(&db, &send_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;

    validate_send_access(&send)?;
    validate_send_password(&send, payload.password)?;

    if send.r#type == SEND_TYPE_TEXT {
        update_send_access_count(&db, &send.id, 1).await?;
    }

    let creator_identifier = get_creator_identifier(&db, &send).await?;
    Ok(Json(send_to_json_access(&send, creator_identifier)))
}

#[worker::send]
pub async fn post_access_file(
    State(env): State<Arc<Env>>,
    Path((send_id, file_id)): Path<(String, String)>,
    Json(payload): Json<SendAccessData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let send = get_send_by_id(&db, &send_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;

    validate_send_access(&send)?;
    validate_send_password(&send, payload.password)?;

    let file_exists: Option<i64> = db
        .prepare("SELECT 1 AS ok FROM send_files WHERE id = ?1 AND send_id = ?2 LIMIT 1")
        .bind(&[file_id.clone().into(), send_id.clone().into()])?
        .first(Some("ok"))
        .await
        .map_err(|_| AppError::Database)?;
    if file_exists.is_none() {
        return Err(AppError::NotFound("Send not found".to_string()));
    }

    update_send_access_count(&db, &send.id, 1).await?;

    let token = generate_download_token(&env, &send_id, &file_id)?;
    let url = format!("/api/sends/{send_id}/{file_id}?t={token}");

    Ok(Json(json!({
        "object": "send-fileDownload",
        "id": file_id,
        "url": url
    })))
}

#[derive(Debug, Deserialize)]
pub struct DownloadQuery {
    t: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SendDownloadClaims {
    sub: String,
    exp: usize,
}

fn generate_download_token(env: &Arc<Env>, send_id: &str, file_id: &str) -> Result<String, AppError> {
    let secret = env.secret("JWT_SECRET")?.to_string();
    let exp = (Utc::now() + chrono::Duration::minutes(5)).timestamp() as usize;
    let claims = SendDownloadClaims {
        sub: format!("{send_id}/{file_id}"),
        exp,
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok(token)
}

fn validate_download_token(env: &Arc<Env>, token: &str, send_id: &str, file_id: &str) -> Result<(), AppError> {
    let secret = env.secret("JWT_SECRET")?.to_string();
    let data = jsonwebtoken::decode::<SendDownloadClaims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
        &jsonwebtoken::Validation::default(),
    )
    .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

    if data.claims.sub != format!("{send_id}/{file_id}") {
        return Err(AppError::Unauthorized("Invalid token".to_string()));
    }
    Ok(())
}

#[worker::send]
pub async fn download_send(
    State(env): State<Arc<Env>>,
    Path((send_id, file_id)): Path<(String, String)>,
    Query(q): Query<DownloadQuery>,
) -> Result<Response, AppError> {
    validate_download_token(&env, &q.t, &send_id, &file_id)?;
    let db = db::get_db(&env)?;

    let row: Option<Value> = db
        .prepare("SELECT * FROM send_files WHERE id = ?1 AND send_id = ?2 LIMIT 1")
        .bind(&[file_id.clone().into(), send_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let Some(row) = row else {
        return Err(AppError::NotFound("File not found".to_string()));
    };
    let file = serde_json::from_value::<SendFileDBModel>(row).map_err(|_| AppError::Internal)?;
    let data_b64 = match file.data_base64 {
        Some(v) => v,
        None => {
            let rows: Vec<Value> = db
                .prepare("SELECT data_base64 FROM send_file_chunks WHERE send_file_id = ?1 ORDER BY chunk_index ASC")
                .bind(&[file_id.clone().into()])?
                .all()
                .await
                .map_err(|_| AppError::Database)?
                .results()?;

            if rows.is_empty() {
                return Err(AppError::NotFound("File not found".to_string()));
            }

            let mut out = String::new();
            for row in rows {
                let part = row
                    .get("data_base64")
                    .and_then(|v| v.as_str())
                    .ok_or(AppError::Internal)?;
                out.push_str(part);
            }
            out
        }
    };
    let bytes = general_purpose::STANDARD.decode(data_b64).map_err(|_| AppError::Internal)?;

    let mut response = Response::new(axum::body::Body::from(bytes));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{}\"", file.file_name))
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("attachment")),
    );
    Ok(response)
}
