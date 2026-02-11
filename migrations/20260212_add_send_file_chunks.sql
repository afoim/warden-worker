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
