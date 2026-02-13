use std::convert::TryFrom;
use tower_http::cors::{Any, CorsLayer};
use tower_service::Service;
use worker::*;

mod auth;
mod crypto;
mod db;
mod error;
mod handlers;
mod jwt;
mod models;
mod notifications;
mod router;
mod two_factor;
mod webauthn;

#[event(fetch)]
pub async fn main(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    // Set up logging
    console_error_panic_hook::set_once();
    let _ = console_log::init_with_level(log::Level::Debug);

    // Allow all origins for CORS, which is typical for a public API like Bitwarden's.
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    if notifications::is_notifications_path(req.uri().path()) {
        let worker_req = Request::try_from(req)?;
        let worker_resp = notifications::proxy_notifications_request(&env, worker_req).await?;
        return Ok(worker_resp.into());
    }

    let mut app = router::api_router(env).layer(cors);

    Ok(app.call(req).await?)
}
