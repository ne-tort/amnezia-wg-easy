-- Many-to-many: VPN clients assigned to panel users
CREATE TABLE IF NOT EXISTS client_panel_users (
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES panel_users(id) ON DELETE CASCADE,
  PRIMARY KEY (client_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_cpu_user ON client_panel_users(user_id);
CREATE INDEX IF NOT EXISTS idx_cpu_client ON client_panel_users(client_id);
