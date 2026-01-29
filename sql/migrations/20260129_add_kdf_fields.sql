-- Add KDF memory and parallelism columns to users table
-- These are required for Argon2id support

ALTER TABLE users ADD COLUMN kdf_memory INTEGER;
ALTER TABLE users ADD COLUMN kdf_parallelism INTEGER;
