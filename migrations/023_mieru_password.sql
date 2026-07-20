-- Per-client Mieru password (synced into amnezia-mieru server.json users)
ALTER TABLE clients ADD COLUMN mieru_password TEXT;
