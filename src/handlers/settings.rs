use axum::{extract::State, Json};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use worker::Env;

use crate::{auth::Claims, db, domains, error::AppError};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainsUpdateRequest {
    pub excluded_global_equivalent_domains: Option<Vec<i32>>,
    pub equivalent_domains: Option<Vec<Vec<String>>>,
}

#[worker::send]
pub async fn get_domains(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let domains = domains::build_domains_object(&db, &claims.sub, false).await?;
    Ok(Json(domains))
}

#[worker::send]
pub async fn post_domains(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<DomainsUpdateRequest>,
) -> Result<Json<Value>, AppError> {
    update_domains(claims, State(env), payload).await
}

#[worker::send]
pub async fn put_domains(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<DomainsUpdateRequest>,
) -> Result<Json<Value>, AppError> {
    update_domains(claims, State(env), payload).await
}

async fn update_domains(
    claims: Claims,
    State(env): State<Arc<Env>>,
    payload: DomainsUpdateRequest,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().to_rfc3339();

    let equivalent_domains = payload.equivalent_domains.unwrap_or_default();
    let excluded_globals = payload.excluded_global_equivalent_domains.unwrap_or_default();

    domains::update_domains_settings(&db, &claims.sub, equivalent_domains, excluded_globals, &now)
        .await?;

    Ok(Json(json!({})))
}
