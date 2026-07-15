-- Track which panel user created each WireGuard client.
ALTER TABLE clients ADD COLUMN created_by TEXT NULL REFERENCES panel_users(id);
