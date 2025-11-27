use axum::{extract::State, Json};
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;
use worker::{query, D1PreparedStatement, Env};

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::models::cipher::{Cipher, CipherData};
use crate::models::folder::Folder;
use crate::models::import::ImportRequest;

/// Get the batch size from environment variable IMPORT_BATCH_SIZE.
/// Defaults to 30 if not set or invalid.
fn get_batch_size(env: &Env) -> usize {
    env.var("IMPORT_BATCH_SIZE")
        .ok()
        .and_then(|v| v.to_string().parse::<usize>().ok())
        .unwrap_or(30)
}

/// Execute statements in batches. If batch_size is 0, execute all in one batch.
async fn execute_in_batches(
    db: &worker::D1Database,
    statements: Vec<D1PreparedStatement>,
    batch_size: usize,
) -> Result<(), AppError> {
    if statements.is_empty() {
        return Ok(());
    }

    if batch_size == 0 {
        // Execute all statements in one batch
        db.batch(statements).await?;
    } else {
        // Execute in chunks of batch_size
        for chunk in statements.chunks(batch_size) {
            db.batch(chunk.to_vec()).await?;
        }
    }

    Ok(())
}

#[worker::send]
pub async fn import_data(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(mut payload): Json<ImportRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let batch_size = get_batch_size(&env);

    // Prepare all folder insert statements
    let mut folder_statements: Vec<D1PreparedStatement> = Vec::with_capacity(payload.folders.len());

    for import_folder in &payload.folders {
        let folder = Folder {
            id: import_folder.id.clone(),
            user_id: claims.sub.clone(),
            name: import_folder.name.clone(),
            created_at: now.clone(),
            updated_at: now.clone(),
        };

        let stmt = query!(
            &db,
            "INSERT OR IGNORE INTO folders (id, user_id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            folder.id,
            folder.user_id,
            folder.name,
            folder.created_at,
            folder.updated_at
        )
        .map_err(|_| AppError::Database)?;

        folder_statements.push(stmt);
    }

    // Execute folder inserts in batches
    execute_in_batches(&db, folder_statements, batch_size).await?;

    // Process folder relationships
    for relationship in payload.folder_relationships {
        if let Some(cipher) = payload.ciphers.get_mut(relationship.key) {
            if let Some(folder) = payload.folders.get(relationship.value) {
                cipher.folder_id = Some(folder.id.clone());
            }
        }
    }

    // Prepare all cipher insert statements
    let mut cipher_statements: Vec<D1PreparedStatement> = Vec::with_capacity(payload.ciphers.len());

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

        let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

        let cipher = Cipher {
            id: Uuid::new_v4().to_string(),
            user_id: Some(claims.sub.clone()),
            organization_id: import_cipher.organization_id.clone(),
            r#type: import_cipher.r#type,
            data: data_value,
            favorite: import_cipher.favorite,
            folder_id: import_cipher.folder_id.clone(),
            deleted_at: None,
            created_at: now.clone(),
            updated_at: now.clone(),
            object: "cipher".to_string(),
            organization_use_totp: false,
            edit: true,
            view_password: true,
            collection_ids: None,
        };

        let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

        let stmt = query!(
            &db,
            "INSERT OR IGNORE INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
             cipher.id,
             cipher.user_id,
             cipher.organization_id,
             cipher.r#type,
             data,
             cipher.favorite,
             cipher.folder_id,
             cipher.created_at,
             cipher.updated_at,
        ).map_err(|_| AppError::Database)?;

        cipher_statements.push(stmt);
    }

    // Execute cipher inserts in batches
    execute_in_batches(&db, cipher_statements, batch_size).await?;

    Ok(Json(()))
}