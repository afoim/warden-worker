use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Worker error: {0}")]
    Worker(#[from] worker::Error),

    #[error("Database query failed: {0}")]
    Database(String),

    #[error("Database constraint violation: {0}")]
    DatabaseConstraint(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Too many requests: {0}")]
    TooManyRequests(String),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error(transparent)]
    JsonWebToken(#[from] jsonwebtoken::errors::Error),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AppError::Worker(e) => {
                log::error!("🔴 Worker error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Worker error: {}", e),
                )
            }
            AppError::Database(msg) => {
                log::error!("💾 Database error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database error".to_string(),
                )
            }
            AppError::DatabaseConstraint(msg) => {
                log::warn!("⚠️ Database constraint violation: {}", msg);
                (StatusCode::BAD_REQUEST, msg.clone())
            }
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::TooManyRequests(msg) => (StatusCode::TOO_MANY_REQUESTS, msg.clone()),
            AppError::Crypto(msg) => {
                log::error!("🔐 Crypto error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Crypto error: {}", msg),
                )
            }
            AppError::JsonWebToken(_) => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
            AppError::Internal(msg) => {
                log::error!("🔥 Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };

        let body = Json(json!({ "error": error_message }));
        (status, body).into_response()
    }
}
