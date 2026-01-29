use crate::error::AppError;
use std::sync::Arc;
use worker::{D1Database, Env};

pub fn get_db(env: &Arc<Env>) -> Result<D1Database, AppError> {
    // 尝试获取名为 "warden-mima" 的数据库绑定 (根据 wrangler.jsonc)
    // 如果失败,尝试旧的 "vault1" 以保持兼容性,或者报错
    env.d1("warden-mima")
        .or_else(|_| env.d1("vault1"))
        .map_err(|e| {
            log::error!("❌ Failed to get database binding: {}", e);
            AppError::Worker(e)
        })
}

/// 将 worker::Error 转换为更有意义的 AppError
pub fn handle_db_error(error: worker::Error) -> AppError {
    let error_str = error.to_string();
    
    // 记录原始错误以便调试
    log::error!("🗄️ Raw Database Error: {}", error_str);

    if error_str.contains("UNIQUE constraint failed") {
        if error_str.contains("email") {
            return AppError::DatabaseConstraint("Email already registered".to_string());
        }
        return AppError::DatabaseConstraint(format!("Record already exists: {}", error_str));
    }
    
    if error_str.contains("NOT NULL constraint failed") {
        return AppError::BadRequest(format!("Missing required field: {}", error_str));
    }
    
    if error_str.contains("FOREIGN KEY constraint failed") {
        return AppError::BadRequest("Invalid reference".to_string());
    }
    
    AppError::Database(error_str)
}
