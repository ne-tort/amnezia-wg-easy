-- Per-client firewall rules (highest priority: individual then profile then global)
CREATE TABLE IF NOT EXISTS client_firewall_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  action TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
  destination_cidr TEXT NOT NULL,
  port_range TEXT,
  protocol TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_client_firewall_rules_client_id ON client_firewall_rules(client_id);
