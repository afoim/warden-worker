ALTER TABLE users ADD COLUMN equivalent_domains TEXT NOT NULL DEFAULT '[]';
ALTER TABLE users ADD COLUMN excluded_globals TEXT NOT NULL DEFAULT '[]';
