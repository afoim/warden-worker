-- Drop tables if they exist to ensure a clean slate
DROP TABLE IF EXISTS folders;
DROP TABLE IF EXISTS ciphers;
DROP TABLE IF EXISTS send_file_chunks;
DROP TABLE IF EXISTS send_files;
DROP TABLE IF EXISTS sends;
DROP TABLE IF EXISTS two_factor_authenticator;
DROP TABLE IF EXISTS users;

-- Users table to store user accounts and their master keys/hashes
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT,
    email TEXT NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT 0,
    master_password_hash TEXT NOT NULL,
    master_password_hint TEXT,
    key TEXT NOT NULL, -- The encrypted symmetric key
    private_key TEXT NOT NULL, -- encrypted asymmetric private_key
    public_key TEXT NOT NULL, -- asymmetric public_key
    kdf_type INTEGER NOT NULL DEFAULT 0, -- 0 for PBKDF2
    kdf_iterations INTEGER NOT NULL DEFAULT 600000,
    security_stamp TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Ciphers table for storing encrypted vault items
CREATE TABLE IF NOT EXISTS ciphers (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT,
    organization_id TEXT,
    type INTEGER NOT NULL,
    data TEXT NOT NULL, -- JSON blob of all encrypted fields (name, notes, login, etc.)
    favorite BOOLEAN NOT NULL DEFAULT 0,
    folder_id TEXT,
    deleted_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS sends (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    organization_id TEXT,
    type INTEGER NOT NULL,
    name TEXT NOT NULL,
    notes TEXT,
    data TEXT NOT NULL,
    key TEXT NOT NULL,
    password_hash TEXT,
    password_salt TEXT,
    password_iter INTEGER,
    max_access_count INTEGER,
    access_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expiration_date TEXT,
    deletion_date TEXT NOT NULL,
    disabled BOOLEAN NOT NULL DEFAULT 0,
    hide_email BOOLEAN,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sends_user_id ON sends(user_id);
CREATE INDEX IF NOT EXISTS idx_sends_deletion_date ON sends(deletion_date);

CREATE TABLE IF NOT EXISTS send_files (
    id TEXT PRIMARY KEY NOT NULL,
    send_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    mime TEXT,
    data_base64 TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (send_id) REFERENCES sends(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_send_files_send_id ON send_files(send_id);

CREATE TABLE IF NOT EXISTS send_file_chunks (
    send_file_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    data_base64 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (send_file_id, chunk_index),
    FOREIGN KEY (send_file_id) REFERENCES send_files(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_send_file_chunks_send_file_id ON send_file_chunks(send_file_id);

-- Folders table for organizing ciphers
CREATE TABLE IF NOT EXISTS folders (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL, -- Encrypted folder name
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS two_factor_authenticator (
    user_id TEXT PRIMARY KEY NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT 0,
    secret_enc TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
