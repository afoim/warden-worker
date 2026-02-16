use super::{cipher::Cipher, folder::FolderResponse};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct UserDecryption {
    #[serde(rename = "masterPasswordUnlock")]
    pub master_password_unlock: Value,
}

#[derive(Debug, Serialize)]
pub struct Profile {
    pub name: Option<String>,
    pub email: String,
    pub id: String,
    #[serde(rename = "avatarColor")]
    pub avatar_color: Option<String>,
    #[serde(rename = "masterPasswordHint")]
    pub master_password_hint: Option<String>,
    #[serde(rename = "securityStamp")]
    pub security_stamp: String,
    #[serde(rename = "Object")]
    pub object: String,
    #[serde(rename = "premiumFromOrganization")]
    pub premium_from_organization: bool,
    #[serde(rename = "forcePasswordReset")]
    pub force_password_reset: bool,
    #[serde(rename = "emailVerified")]
    pub email_verified: bool,
    #[serde(rename = "twoFactorEnabled")]
    pub two_factor_enabled: bool,
    pub premium: bool,
    #[serde(rename = "usesKeyConnector")]
    pub uses_key_connector: bool,
    #[serde(rename = "creationDate")]
    pub creation_date: String,
    #[serde(rename = "privateKey")]
    pub private_key: String,
    pub key: String,
}

#[derive(Debug, Serialize)]
pub struct SyncResponse {
    #[serde(rename = "profile")]
    pub profile: Profile,
    #[serde(rename = "folders")]
    pub folders: Vec<FolderResponse>,
    #[serde(rename = "ciphers")]
    pub ciphers: Vec<Cipher>,
    #[serde(rename = "Sends")]
    pub sends: Vec<Value>,
    #[serde(rename = "Domains")]
    pub domains: Value,
    #[serde(rename = "userDecryption")]
    pub user_decryption: UserDecryption,
    #[serde(rename = "Object")]
    pub object: String,
}
