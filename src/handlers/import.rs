use axum::{extract::State, Json};
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;
use worker::{D1Database, D1PreparedStatement, Env};
use wasm_bindgen::JsValue;

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::models::cipher::CipherData;
use crate::models::folder::Folder;
use crate::models::import::ImportRequest;

const IMPORT_BATCH_SIZE: usize = 200;

#[worker::send]
pub async fn import_data(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(mut payload): Json<ImportRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let folder_query = "INSERT OR IGNORE INTO folders (id, user_id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)";

    let mut folder_stmts: Vec<D1PreparedStatement> = Vec::new();
    for import_folder in &payload.folders {
        let folder = Folder {
            id: import_folder.id.clone(),
            user_id: claims.sub.clone(),
            name: import_folder.name.clone(),
            created_at: now.clone(),
            updated_at: now.clone(),
        };

        folder_stmts.push(db.prepare(folder_query).bind(&[
            folder.id.into(),
            folder.user_id.into(),
            folder.name.into(),
            folder.created_at.into(),
            folder.updated_at.into(),
        ])?);

        if folder_stmts.len() >= IMPORT_BATCH_SIZE {
            run_batch(&db, &mut folder_stmts).await?;
        }
    }
    run_batch(&db, &mut folder_stmts).await?;

    for relationship in payload.folder_relationships {
        if let Some(cipher) = payload.ciphers.get_mut(relationship.key) {
            if let Some(folder) = payload.folders.get(relationship.value) {
                cipher.folder_id = Some(folder.id.clone());
            }
        }
    }

    let cipher_query = "INSERT OR IGNORE INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";

    let mut cipher_stmts: Vec<D1PreparedStatement> = Vec::new();
    for import_cipher in payload.ciphers {
        if import_cipher.encrypted_for != claims.sub {
            return Err(AppError::BadRequest("Cipher encrypted for wrong user".to_string()));
        }

        let cipher_data = CipherData {
            name: import_cipher.name,
            notes: import_cipher.notes,
            login: import_cipher.login,
            card: import_cipher.card,
            identity: import_cipher.identity,
            secure_note: import_cipher.secure_note,
            fields: import_cipher.fields,
            password_history: import_cipher.password_history,
            reprompt: import_cipher.reprompt,
        };

        let id = Uuid::new_v4().to_string();
        let user_id = claims.sub.clone();
        let data = serde_json::to_string(&cipher_data).map_err(|_| AppError::Internal)?;

        cipher_stmts.push(db.prepare(cipher_query).bind(&[
            id.into(),
            user_id.into(),
            to_js_val(import_cipher.organization_id),
            import_cipher.r#type.into(),
            data.into(),
            import_cipher.favorite.into(),
            to_js_val(import_cipher.folder_id),
            now.clone().into(),
            now.clone().into(),
        ])?);

        if cipher_stmts.len() >= IMPORT_BATCH_SIZE {
            run_batch(&db, &mut cipher_stmts).await?;
        }
    }
    run_batch(&db, &mut cipher_stmts).await?;

    Ok(Json(()))
}

fn to_js_val<T: Into<JsValue>>(val: Option<T>) -> JsValue {
    val.map(Into::into).unwrap_or(JsValue::NULL)
}

async fn run_batch(db: &D1Database, stmts: &mut Vec<D1PreparedStatement>) -> Result<(), AppError> {
    if stmts.is_empty() {
        return Ok(());
    }

    let stmts = std::mem::take(stmts);
    db.batch(stmts).await.map_err(|_| AppError::Database)?;
    Ok(())
}
