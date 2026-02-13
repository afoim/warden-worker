ALTER TABLE two_factor_webauthn ADD COLUMN prf_status INTEGER NOT NULL DEFAULT 2;
ALTER TABLE two_factor_webauthn ADD COLUMN encrypted_public_key TEXT;
ALTER TABLE two_factor_webauthn ADD COLUMN encrypted_user_key TEXT;
ALTER TABLE two_factor_webauthn ADD COLUMN encrypted_private_key TEXT;
