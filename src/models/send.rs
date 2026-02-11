use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

pub const SEND_TYPE_TEXT: i32 = 0;
pub const SEND_TYPE_FILE: i32 = 1;

fn deserialize_trimmed_i32_opt<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<Value> = Option::deserialize(deserializer)?;
    let Some(v) = opt else { return Ok(None) };
    match v {
        Value::Number(n) => n
            .as_i64()
            .map(|v| v as i32)
            .ok_or_else(|| serde::de::Error::custom("Invalid number"))
            .map(Some),
        Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                return Ok(None);
            }
            s.parse::<i32>()
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
        _ => Err(serde::de::Error::custom("Invalid value")),
    }
}

mod bool_from_int {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<bool, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(serde::de::Error::custom("expected integer 0 or 1")),
        }
    }

    pub fn serialize<S>(value: &bool, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if *value {
            serializer.serialize_i64(1)
        } else {
            serializer.serialize_i64(0)
        }
    }
}

mod opt_bool_from_int {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<i64>::deserialize(deserializer)?;
        match value {
            None => Ok(None),
            Some(0) => Ok(Some(false)),
            Some(1) => Ok(Some(true)),
            Some(_) => Err(serde::de::Error::custom("expected integer 0 or 1")),
        }
    }

    pub fn serialize<S>(value: &Option<bool>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            None => serializer.serialize_none(),
            Some(true) => serializer.serialize_i64(1),
            Some(false) => serializer.serialize_i64(0),
        }
    }
}

fn deserialize_trimmed_i64_opt<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<Value> = Option::deserialize(deserializer)?;
    let Some(v) = opt else { return Ok(None) };
    match v {
        Value::Number(n) => n
            .as_i64()
            .ok_or_else(|| serde::de::Error::custom("Invalid number"))
            .map(Some),
        Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                return Ok(None);
            }
            s.parse::<i64>()
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
        _ => Err(serde::de::Error::custom("Invalid value")),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendData {
    #[serde(rename = "type")]
    pub r#type: i32,
    pub key: String,
    pub password: Option<String>,
    #[serde(default, deserialize_with = "deserialize_trimmed_i32_opt")]
    pub max_access_count: Option<i32>,
    pub expiration_date: Option<String>,
    pub deletion_date: String,
    #[serde(default)]
    pub disabled: bool,
    pub hide_email: Option<bool>,
    pub name: String,
    pub notes: Option<String>,
    pub text: Option<Value>,
    pub file: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_trimmed_i64_opt")]
    pub file_length: Option<i64>,
    pub id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendAccessData {
    pub password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendDBModel {
    pub id: String,
    pub user_id: String,
    pub organization_id: Option<String>,
    #[serde(rename = "type")]
    pub r#type: i32,
    pub name: String,
    pub notes: Option<String>,
    pub data: String,
    pub key: String,
    pub password_hash: Option<String>,
    pub password_salt: Option<String>,
    pub password_iter: Option<i32>,
    pub max_access_count: Option<i32>,
    pub access_count: i32,
    pub created_at: String,
    pub updated_at: String,
    pub expiration_date: Option<String>,
    pub deletion_date: String,
    #[serde(with = "bool_from_int")]
    pub disabled: bool,
    #[serde(default, with = "opt_bool_from_int")]
    pub hide_email: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendFileDBModel {
    pub id: String,
    pub send_id: String,
    pub user_id: String,
    pub file_name: String,
    pub size: i64,
    pub mime: Option<String>,
    pub data_base64: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

pub fn access_id_from_uuid(send_id: &str) -> String {
    let uuid = Uuid::parse_str(send_id).unwrap_or_default();
    general_purpose::URL_SAFE_NO_PAD.encode(uuid.as_bytes())
}

pub fn uuid_from_access_id(access_id: &str) -> Option<String> {
    let bytes = general_purpose::URL_SAFE_NO_PAD.decode(access_id.as_bytes()).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    Some(Uuid::from_slice(&bytes).ok()?.to_string())
}

pub fn send_to_json(send: &SendDBModel) -> Value {
    let mut data_value: Value = serde_json::from_str(&send.data).unwrap_or(Value::Null);
    if let Some(size) = data_value.get("size").and_then(|v| v.as_i64()) {
        if let Some(obj) = data_value.as_object_mut() {
            obj.insert("size".to_string(), Value::String(size.to_string()));
        }
    }

    json!({
        "id": send.id,
        "accessId": access_id_from_uuid(&send.id),
        "type": send.r#type,
        "name": send.name,
        "notes": send.notes,
        "text": if send.r#type == SEND_TYPE_TEXT { Some(&data_value) } else { None },
        "file": if send.r#type == SEND_TYPE_FILE { Some(&data_value) } else { None },
        "key": send.key,
        "maxAccessCount": send.max_access_count,
        "accessCount": send.access_count,
        "password": send
            .password_hash
            .as_deref()
            .and_then(|h| general_purpose::STANDARD.decode(h).ok())
            .map(|bytes| general_purpose::URL_SAFE_NO_PAD.encode(bytes)),
        "disabled": send.disabled,
        "hideEmail": send.hide_email,
        "revisionDate": send.updated_at,
        "expirationDate": send.expiration_date,
        "deletionDate": send.deletion_date,
        "object": "send",
    })
}

pub fn send_to_json_access(send: &SendDBModel, creator_identifier: Option<String>) -> Value {
    let mut data_value: Value = serde_json::from_str(&send.data).unwrap_or(Value::Null);
    if let Some(size) = data_value.get("size").and_then(|v| v.as_i64()) {
        if let Some(obj) = data_value.as_object_mut() {
            obj.insert("size".to_string(), Value::String(size.to_string()));
        }
    }

    json!({
        "id": send.id,
        "type": send.r#type,
        "name": send.name,
        "text": if send.r#type == SEND_TYPE_TEXT { Some(&data_value) } else { None },
        "file": if send.r#type == SEND_TYPE_FILE { Some(&data_value) } else { None },
        "expirationDate": send.expiration_date,
        "creatorIdentifier": creator_identifier,
        "object": "send-access",
    })
}
