use axum::{
    routing::{get, post, put, delete},
    Router,
    response::Html,
};
use std::sync::Arc;
use worker::Env;

use crate::handlers::{accounts, ciphers, config, identity, sync, folders, import, two_factor, devices};

pub fn api_router(env: Env) -> Router {
    let app_state = Arc::new(env);

    Router::new()
        .route("/", get(|| async { Html(include_str!("../static/index.html")) }))
        // Identity/Auth routes
        .route("/identity/accounts/prelogin", post(accounts::prelogin))
        .route("/api/accounts/prelogin", post(accounts::prelogin))
        .route(
            "/identity/accounts/register/finish",
            post(accounts::register),
        )
        .route("/identity/connect/token", post(identity::token))
        .route(
            "/identity/accounts/register/send-verification-email",
            post(accounts::send_verification_email),
        )
        .route("/api/accounts/profile", get(accounts::profile))
        .route("/api/accounts/revision-date", get(accounts::revision_date))
        .route("/api/accounts/export", post(accounts::export_vault))
        .route("/api/accounts", delete(accounts::delete_account))
        .route("/api/devices/knowndevice", get(devices::knowndevice))
        .route("/api/accounts/password", put(accounts::change_master_password))
        .route("/api/accounts/email", put(accounts::change_email))
        .route("/api/two-factor", get(two_factor::two_factor_status))
        .route("/api/two-factor/authenticator/request", post(two_factor::authenticator_request))
        .route("/api/two-factor/authenticator/enable", post(two_factor::authenticator_enable))
        .route("/api/two-factor/authenticator/disable", post(two_factor::authenticator_disable))
        // Main data sync route
        .route("/api/sync", get(sync::get_sync_data))
        // Ciphers CRUD
        .route("/api/ciphers/create", post(ciphers::create_cipher))
        .route("/api/ciphers", post(ciphers::post_ciphers))
        .route("/api/ciphers/import", post(import::import_data))
        .route("/api/ciphers/{id}", put(ciphers::update_cipher))
        .route("/api/ciphers/{id}/delete", put(ciphers::delete_cipher))
        // Folders CRUD
        .route("/api/folders", post(folders::create_folder))
        .route("/api/folders/{id}", put(folders::update_folder))
        .route("/api/folders/{id}", delete(folders::delete_folder))
        .route("/api/config", get(config::config))
        .route("/api/alive", get(config::alive))
        .route("/api/now", get(config::now))
        .route("/api/version", get(config::version))
        .route("/api/webauthn", get(config::webauthn))
        .with_state(app_state)
}
