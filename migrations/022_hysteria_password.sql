-- Per-client Hysteria auth password (username derived from client name slug)
ALTER TABLE clients ADD COLUMN hysteria_password TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_hysteria_password ON clients(hysteria_password) WHERE hysteria_password IS NOT NULL;
