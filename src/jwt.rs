use base64::{engine::general_purpose, Engine as _};
use constant_time_eq::constant_time_eq;
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;

use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;

fn decode_b64url(input: &str) -> Result<Vec<u8>, AppError> {
    if let Ok(v) = general_purpose::URL_SAFE_NO_PAD.decode(input) {
        return Ok(v);
    }
    let mut padded = input.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    general_purpose::URL_SAFE
        .decode(padded)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))
}

fn sign(input: &str, secret: &str) -> Result<Vec<u8>, AppError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| AppError::Internal)?;
    mac.update(input.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn encode_hs256<T: Serialize>(claims: &T, secret: &str) -> Result<String, AppError> {
    let header = serde_json::json!({
        "alg": "HS256",
        "typ": "JWT"
    });
    let header_b64 = general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|_| AppError::Internal)?);
    let payload_b64 = general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(claims).map_err(|_| AppError::Internal)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = sign(&signing_input, secret)?;
    let signature_b64 = general_purpose::URL_SAFE_NO_PAD.encode(signature);
    Ok(format!("{signing_input}.{signature_b64}"))
}

pub fn decode_hs256<T: DeserializeOwned>(token: &str, secret: &str) -> Result<T, AppError> {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AppError::Unauthorized("Invalid token".to_string()));
    };

    let header_bytes = decode_b64url(header_b64)?;
    let header_json: Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;
    let alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if alg != "HS256" {
        return Err(AppError::Unauthorized("Invalid token".to_string()));
    }

    let signing_input = format!("{header_b64}.{payload_b64}");
    let expected_sig = sign(&signing_input, secret)?;
    let actual_sig = decode_b64url(signature_b64)?;
    if !constant_time_eq(expected_sig.as_slice(), actual_sig.as_slice()) {
        return Err(AppError::Unauthorized("Invalid token".to_string()));
    }

    let payload_bytes = decode_b64url(payload_b64)?;
    let payload_json: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

    let now = chrono::Utc::now().timestamp();
    let exp = payload_json
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::Unauthorized("Invalid token".to_string()))?;
    if now >= exp {
        return Err(AppError::Unauthorized("Invalid token".to_string()));
    }
    if let Some(nbf) = payload_json.get("nbf").and_then(|v| v.as_i64()) {
        if now < nbf {
            return Err(AppError::Unauthorized("Invalid token".to_string()));
        }
    }

    serde_json::from_value(payload_json)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))
}
