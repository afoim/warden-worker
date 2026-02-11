use axum::{
    routing::{get, post, put, delete},
    Router,
    response::Html,
};
use axum::extract::DefaultBodyLimit;
use std::sync::Arc;
use worker::Env;

use crate::handlers::{accounts, ciphers, config, identity, sync, folders, import, two_factor, devices, sends, usage};

pub fn api_router(env: Env) -> Router {
    let app_state = Arc::new(env);

    Router::new()
        .route("/demo.html", get(|| async { Html(include_str!("../static/demo.html")) }))
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
        .route("/api/devices/knowndevice", get(devices::knowndevice))
        .route(
            "/api/devices/identifier/{id}/token",
            put(devices::device_token).post(devices::device_token),
        )
        .route("/api/accounts/password", put(accounts::change_master_password))
        .route("/api/accounts/email", put(accounts::change_email))
        .route("/api/two-factor", get(two_factor::two_factor_status))
        .route("/api/two-factor/get-authenticator", post(two_factor::get_authenticator))
        .route(
            "/api/two-factor/authenticator",
            post(two_factor::activate_authenticator)
                .put(two_factor::activate_authenticator_put)
                .delete(two_factor::disable_authenticator_vw),
        )
        .route("/api/two-factor/authenticator/request", post(two_factor::authenticator_request))
        .route("/api/two-factor/authenticator/enable", post(two_factor::authenticator_enable))
        .route("/api/two-factor/authenticator/disable", post(two_factor::authenticator_disable))
        .route("/api/sends", get(sends::get_sends).post(sends::post_send))
        .route("/api/sends/file/v2", post(sends::post_send_file_v2))
        .route("/api/sends/access/{access_id}", post(sends::post_access))
        .route(
            "/api/sends/{send_id}",
            get(sends::get_send).delete(sends::delete_send),
        )
        .route(
            "/api/sends/{send_id}/access/file/{file_id}",
            post(sends::post_access_file),
        )
        .route("/api/sends/{send_id}/{file_id}", get(sends::download_send))
        .route(
            "/api/sends/{send_id}/file/{file_id}",
            post(sends::post_send_file_v2_data)
                .layer(DefaultBodyLimit::max(100 * 1024 * 1024)),
        )
        .route(
            "/sends/{send_id}/file/{file_id}",
            post(sends::post_send_file_v2_data)
                .layer(DefaultBodyLimit::max(100 * 1024 * 1024)),
        )
        // Main data sync route
        .route("/api/sync", get(sync::get_sync_data))
        // Ciphers CRUD
        .route("/api/ciphers/create", post(ciphers::create_cipher))
        .route(
            "/api/ciphers",
            post(ciphers::post_ciphers).delete(ciphers::hard_delete_ciphers_delete),
        )
        .route("/api/ciphers/import", post(import::import_data))
        .route(
            "/api/ciphers/{id}",
            put(ciphers::update_cipher).delete(ciphers::hard_delete_cipher),
        )
        .route(
            "/api/ciphers/{id}/delete",
            put(ciphers::soft_delete_cipher).post(ciphers::hard_delete_cipher_post),
        )
        .route("/api/ciphers/{id}/restore", put(ciphers::restore_cipher))
        .route(
            "/api/ciphers/delete",
            put(ciphers::soft_delete_ciphers).post(ciphers::hard_delete_ciphers),
        )
        .route("/api/ciphers/restore", put(ciphers::restore_ciphers))
        // Folders CRUD
        .route("/api/folders", post(folders::create_folder))
        .route("/api/folders/{id}", put(folders::update_folder))
        .route("/api/folders/{id}", delete(folders::delete_folder))
        .route("/api/config", get(config::config))
        .route("/api/alive", get(config::alive))
        .route("/api/now", get(config::now))
        .route("/api/version", get(config::version))
        .route("/api/webauthn", get(config::webauthn))
        .route("/api/d1/usage", get(usage::d1_usage))
        .with_state(app_state)
}
