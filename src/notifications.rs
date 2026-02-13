use constant_time_eq::constant_time_eq;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::{
    durable_object, DurableObject, Env, Error, Headers, Method, Request, RequestInit, Response,
    Result, State, WebSocket, WebSocketIncomingMessage, WebSocketPair,
};

use crate::{auth::Claims, jwt};

const DO_BINDING: &str = "NOTIFICATIONS_HUB";
const DO_INSTANCE_NAME: &str = "global";
const INTERNAL_AUTH_HEADER: &str = "x-internal-notify";

const RECORD_SEPARATOR: u8 = 0x1e;
const INITIAL_RESPONSE: [u8; 3] = [0x7b, 0x7d, RECORD_SEPARATOR];

const UPDATE_TYPE_AUTH_REQUEST: i32 = 15;
const UPDATE_TYPE_AUTH_REQUEST_RESPONSE: i32 = 16;

const HUB_PATH: &str = "/hub";
const ANONYMOUS_HUB_PATH: &str = "/anonymous-hub";
const HUB_PATH_WITH_PREFIX: &str = "/notifications/hub";
const ANONYMOUS_HUB_PATH_WITH_PREFIX: &str = "/notifications/anonymous-hub";

const INTERNAL_AUTH_REQUEST_PATH: &str = "/internal/auth-request";
const INTERNAL_AUTH_RESPONSE_PATH: &str = "/internal/auth-response";
const INTERNAL_CLOSE_ANONYMOUS_PATH: &str = "/internal/close-anonymous";

const TARGET_RECEIVE_MESSAGE: &str = "ReceiveMessage";
// 与 Bitwarden 上游保持拼写兼容（上游本身也拼错）
const TARGET_ANONYMOUS_AUTH_RESPONSE: &str = "AuthRequestResponseRecieved";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InitialHandshake {
    protocol: String,
    version: i32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthEventPayload {
    user_id: String,
    auth_request_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloseAnonymousPayload {
    token: String,
}

#[durable_object(websocket)]
pub struct NotificationsHub {
    state: State,
    env: Env,
}

impl DurableObject for NotificationsHub {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let path_owned = req.path();
        let path = normalize_path(&path_owned);

        if req.method() == Method::Get && (path == HUB_PATH || path == HUB_PATH_WITH_PREFIX) {
            return self.handle_user_hub(&req);
        }

        if req.method() == Method::Get
            && (path == ANONYMOUS_HUB_PATH || path == ANONYMOUS_HUB_PATH_WITH_PREFIX)
        {
            return self.handle_anonymous_hub(&req);
        }

        if req.method() == Method::Post && path == INTERNAL_AUTH_REQUEST_PATH {
            if !self.is_internal_request(&req) {
                return Response::error("Forbidden", 403);
            }
            return self.handle_internal_auth_request(&mut req).await;
        }

        if req.method() == Method::Post && path == INTERNAL_AUTH_RESPONSE_PATH {
            if !self.is_internal_request(&req) {
                return Response::error("Forbidden", 403);
            }
            return self.handle_internal_auth_response(&mut req).await;
        }

        if req.method() == Method::Post && path == INTERNAL_CLOSE_ANONYMOUS_PATH {
            if !self.is_internal_request(&req) {
                return Response::error("Forbidden", 403);
            }
            return self.handle_internal_close_anonymous(&mut req).await;
        }

        Response::error("Not found", 404)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        if let WebSocketIncomingMessage::String(text) = message {
            if is_signalr_messagepack_handshake(&text) {
                ws.send_with_bytes(INITIAL_RESPONSE)?;
            }
        }
        Ok(())
    }

    async fn websocket_close(
        &self,
        _ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, err: Error) -> Result<()> {
        log::warn!("notifications websocket error: {err}");
        Ok(())
    }
}

impl NotificationsHub {
    fn handle_user_hub(&self, req: &Request) -> Result<Response> {
        let access_token = extract_access_token(req)
            .ok_or_else(|| Error::RustError("Missing access token".to_string()))?;
        let jwt_secret = self.env.secret("JWT_SECRET")?.to_string();
        let claims: Claims = jwt::decode_hs256(&access_token, &jwt_secret)
            .map_err(|err| Error::RustError(err.to_string()))?;

        let tag = user_tag(&claims.sub);
        let tags = [tag.as_str()];
        self.accept_with_tags(&tags)
    }

    fn handle_anonymous_hub(&self, req: &Request) -> Result<Response> {
        let token = query_param(req, "token")
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| Error::RustError("Missing token".to_string()))?;

        let tag = anon_tag(&token);
        let tags = [tag.as_str()];
        self.accept_with_tags(&tags)
    }

    fn accept_with_tags(&self, tags: &[&str]) -> Result<Response> {
        let pair = WebSocketPair::new()?;
        self.state.accept_websocket_with_tags(&pair.server, tags);
        Response::from_websocket(pair.client)
    }

    async fn handle_internal_auth_request(&self, req: &mut Request) -> Result<Response> {
        let payload: AuthEventPayload = match req.json().await {
            Ok(v) => v,
            Err(_) => return Response::error("Bad request", 400),
        };

        let user_event = encode_user_update(
            UPDATE_TYPE_AUTH_REQUEST,
            &payload.auth_request_id,
            &payload.user_id,
        );
        self.broadcast_to_tag(&user_tag(&payload.user_id), &user_event);
        Response::empty().map(|resp| resp.with_status(204))
    }

    async fn handle_internal_auth_response(&self, req: &mut Request) -> Result<Response> {
        let payload: AuthEventPayload = match req.json().await {
            Ok(v) => v,
            Err(_) => return Response::error("Bad request", 400),
        };

        let user_event = encode_user_update(
            UPDATE_TYPE_AUTH_REQUEST_RESPONSE,
            &payload.auth_request_id,
            &payload.user_id,
        );
        self.broadcast_to_tag(&user_tag(&payload.user_id), &user_event);

        let anonymous_event =
            encode_anonymous_auth_response(&payload.auth_request_id, &payload.user_id);
        self.broadcast_to_tag(&anon_tag(&payload.auth_request_id), &anonymous_event);

        Response::empty().map(|resp| resp.with_status(204))
    }

    async fn handle_internal_close_anonymous(&self, req: &mut Request) -> Result<Response> {
        let payload: CloseAnonymousPayload = match req.json().await {
            Ok(v) => v,
            Err(_) => return Response::error("Bad request", 400),
        };

        self.close_tagged_websockets(&anon_tag(&payload.token), "auth-complete");
        Response::empty().map(|resp| resp.with_status(204))
    }

    fn broadcast_to_tag(&self, tag: &str, payload: &[u8]) {
        for ws in self.state.get_websockets_with_tag(tag) {
            if let Err(err) = ws.send_with_bytes(payload) {
                log::warn!("notifications send failed ({tag}): {err}");
            }
        }
    }

    fn close_tagged_websockets(&self, tag: &str, reason: &str) {
        for ws in self.state.get_websockets_with_tag(tag) {
            if let Err(err) = ws.close(Some(1000), Some(reason)) {
                log::warn!("notifications close failed ({tag}): {err}");
            }
        }
    }

    fn is_internal_request(&self, req: &Request) -> bool {
        let provided = req
            .headers()
            .get(INTERNAL_AUTH_HEADER)
            .ok()
            .flatten()
            .unwrap_or_default();
        if provided.is_empty() {
            return false;
        }

        let expected = match self.env.secret("JWT_SECRET") {
            Ok(secret) => secret.to_string(),
            Err(_) => return false,
        };
        constant_time_eq(provided.as_bytes(), expected.as_bytes())
    }
}

pub fn is_notifications_path(path: &str) -> bool {
    path == "/notifications" || path.starts_with("/notifications/")
}

pub async fn proxy_notifications_request(env: &Env, req: Request) -> Result<Response> {
    let namespace = env.durable_object(DO_BINDING)?;
    let stub = namespace.id_from_name(DO_INSTANCE_NAME)?.get_stub()?;
    stub.fetch_with_request(req).await
}

pub async fn publish_auth_request(env: &Env, user_id: &str, auth_request_id: &str) -> Result<()> {
    dispatch_internal(
        env,
        INTERNAL_AUTH_REQUEST_PATH,
        &AuthEventPayload {
            user_id: user_id.to_string(),
            auth_request_id: auth_request_id.to_string(),
        },
    )
    .await
}

pub async fn publish_auth_response(env: &Env, user_id: &str, auth_request_id: &str) -> Result<()> {
    dispatch_internal(
        env,
        INTERNAL_AUTH_RESPONSE_PATH,
        &AuthEventPayload {
            user_id: user_id.to_string(),
            auth_request_id: auth_request_id.to_string(),
        },
    )
    .await
}

pub async fn close_anonymous_subscription(env: &Env, token: &str) -> Result<()> {
    dispatch_internal(
        env,
        INTERNAL_CLOSE_ANONYMOUS_PATH,
        &CloseAnonymousPayload {
            token: token.to_string(),
        },
    )
    .await
}

async fn dispatch_internal(env: &Env, path: &str, payload: &impl Serialize) -> Result<()> {
    let namespace = env.durable_object(DO_BINDING)?;
    let stub = namespace.id_from_name(DO_INSTANCE_NAME)?.get_stub()?;
    let req = build_internal_request(env, path, payload)?;

    let mut resp = stub.fetch_with_request(req).await?;
    if resp.status_code() >= 400 {
        let detail = resp.text().await.unwrap_or_else(|_| String::new());
        return Err(Error::RustError(format!(
            "notifications internal call failed (status={}): {detail}",
            resp.status_code()
        )));
    }
    Ok(())
}

fn build_internal_request(env: &Env, path: &str, payload: &impl Serialize) -> Result<Request> {
    let payload_json = serde_json::to_string(payload)?;

    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set(INTERNAL_AUTH_HEADER, &env.secret("JWT_SECRET")?.to_string())?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&payload_json)));

    Request::new_with_init(&format!("https://notifications.internal{path}"), &init)
}

fn normalize_path(path: &str) -> &str {
    if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    }
}

fn extract_access_token(req: &Request) -> Option<String> {
    if let Some(token) = query_param(req, "access_token") {
        return Some(token);
    }

    let auth_header = req.headers().get("authorization").ok().flatten()?;
    auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
        .map(str::to_string)
}

fn query_param(req: &Request, key: &str) -> Option<String> {
    let url = req.url().ok()?;
    url.query_pairs().find_map(|(k, v)| {
        if k.eq_ignore_ascii_case(key) {
            Some(v.into_owned())
        } else {
            None
        }
    })
}

fn user_tag(user_id: &str) -> String {
    format!("user:{user_id}")
}

fn anon_tag(token: &str) -> String {
    format!("anon:{token}")
}

fn is_signalr_messagepack_handshake(text: &str) -> bool {
    let trimmed = text.trim_end_matches(RECORD_SEPARATOR as char).trim();
    if trimmed.is_empty() {
        return false;
    }

    let Ok(msg) = serde_json::from_str::<InitialHandshake>(trimmed) else {
        return false;
    };
    msg.protocol == "messagepack" && msg.version == 1
}

fn encode_user_update(update_type: i32, auth_request_id: &str, user_id: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(192);

    write_array_len(&mut payload, 5);
    write_i32(&mut payload, 1);
    write_map_len(&mut payload, 0);
    write_nil(&mut payload);
    write_str(&mut payload, TARGET_RECEIVE_MESSAGE);
    write_array_len(&mut payload, 1);

    write_map_len(&mut payload, 3);
    write_str(&mut payload, "ContextId");
    write_nil(&mut payload);
    write_str(&mut payload, "Type");
    write_i32(&mut payload, update_type);
    write_str(&mut payload, "Payload");
    write_auth_payload_map(&mut payload, auth_request_id, user_id);

    add_signalr_length_prefix(payload)
}

fn encode_anonymous_auth_response(auth_request_id: &str, user_id: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(192);

    write_array_len(&mut payload, 5);
    write_i32(&mut payload, 1);
    write_map_len(&mut payload, 0);
    write_nil(&mut payload);
    write_str(&mut payload, TARGET_ANONYMOUS_AUTH_RESPONSE);
    write_array_len(&mut payload, 1);

    write_map_len(&mut payload, 3);
    write_str(&mut payload, "Type");
    write_i32(&mut payload, UPDATE_TYPE_AUTH_REQUEST_RESPONSE);
    write_str(&mut payload, "Payload");
    write_auth_payload_map(&mut payload, auth_request_id, user_id);
    write_str(&mut payload, "UserId");
    write_str(&mut payload, user_id);

    add_signalr_length_prefix(payload)
}

fn write_auth_payload_map(out: &mut Vec<u8>, auth_request_id: &str, user_id: &str) {
    write_map_len(out, 2);
    write_str(out, "Id");
    write_str(out, auth_request_id);
    write_str(out, "UserId");
    write_str(out, user_id);
}

fn add_signalr_length_prefix(mut body: Vec<u8>) -> Vec<u8> {
    let mut len = body.len();
    let mut prefixed = Vec::with_capacity(body.len() + 5);

    loop {
        let mut part = (len & 0x7f) as u8;
        len >>= 7;
        if len > 0 {
            part |= 0x80;
        }
        prefixed.push(part);
        if len == 0 {
            break;
        }
    }

    prefixed.append(&mut body);
    prefixed
}

fn write_nil(out: &mut Vec<u8>) {
    out.push(0xc0);
}

fn write_i32(out: &mut Vec<u8>, value: i32) {
    if (0..=127).contains(&value) {
        out.push(value as u8);
        return;
    }

    if (-32..=-1).contains(&value) {
        out.push((value as i8) as u8);
        return;
    }

    if (i8::MIN as i32..=i8::MAX as i32).contains(&value) {
        out.push(0xd0);
        out.push(value as i8 as u8);
        return;
    }

    if (i16::MIN as i32..=i16::MAX as i32).contains(&value) {
        out.push(0xd1);
        out.extend_from_slice(&(value as i16).to_be_bytes());
        return;
    }

    out.push(0xd2);
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_array_len(out: &mut Vec<u8>, len: usize) {
    if len <= 15 {
        out.push(0x90 | (len as u8));
    } else if len <= u16::MAX as usize {
        out.push(0xdc);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0xdd);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

fn write_map_len(out: &mut Vec<u8>, len: usize) {
    if len <= 15 {
        out.push(0x80 | (len as u8));
    } else if len <= u16::MAX as usize {
        out.push(0xde);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0xdf);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

fn write_str(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = bytes.len();

    if len <= 31 {
        out.push(0xa0 | (len as u8));
    } else if len <= u8::MAX as usize {
        out.push(0xd9);
        out.push(len as u8);
    } else if len <= u16::MAX as usize {
        out.push(0xda);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0xdb);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
    out.extend_from_slice(bytes);
}
