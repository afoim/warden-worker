CREATE TABLE IF NOT EXISTS auth_requests (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    request_device_identifier TEXT NOT NULL,
    device_type INTEGER NOT NULL,
    request_ip TEXT NOT NULL,
    response_device_identifier TEXT,
    access_code_hash TEXT NOT NULL,
    public_key TEXT NOT NULL,
    enc_key TEXT,
    master_password_hash TEXT,
    approved INTEGER,
    creation_date TEXT NOT NULL,
    response_date TEXT,
    authentication_date TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_auth_requests_user_id ON auth_requests(user_id);
