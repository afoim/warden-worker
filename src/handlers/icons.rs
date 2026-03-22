use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Response,
};
use std::sync::Arc;
use worker::Env;

use crate::error::AppError;

#[worker::send]
pub async fn get_icon(
    State(_env): State<Arc<Env>>,
    Path(path): Path<String>,
) -> Result<Response, AppError> {
    let domain = path
        .strip_suffix("/icon.png")
        .unwrap_or(&path)
        .to_string();

    let target_url = format!("https://vault.bitwarden.com/icons/{}/icon.png", domain);

    let request = worker::Request::new(&target_url, worker::Method::Get)
        .map_err(|_| AppError::Internal)?;

    let mut upstream_response = worker::Fetch::Request(request)
        .send()
        .await
        .map_err(|e| {
            log::error!("Failed to fetch icon from Bitwarden: {:?}", e);
            AppError::Internal
        })?;

    let status = upstream_response.status_code();

    let body_bytes = upstream_response
        .bytes()
        .await
        .map_err(|e| {
            log::error!("Failed to read icon response body: {:?}", e);
            AppError::Internal
        })?;

    let mut response = Response::new(axum::body::Body::from(body_bytes));
    *response.status_mut() = StatusCode::from_u16(status)
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    if let Ok(Some(content_type)) = upstream_response.headers().get("content-type") {
        if let Ok(header_value) = axum::http::HeaderValue::from_str(&content_type) {
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                header_value,
            );
        }
    }

    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("public, max-age=604800, immutable"),
    );

    Ok(response)
}
