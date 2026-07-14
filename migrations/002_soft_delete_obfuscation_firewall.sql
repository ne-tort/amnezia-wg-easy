-- Soft delete for clients
ALTER TABLE clients ADD COLUMN deleted_at INTEGER;

-- Obfuscation level/profile per config version
ALTER TABLE client_config_versions ADD COLUMN obfuscation_level INTEGER;
ALTER TABLE client_config_versions ADD COLUMN obfuscation_profile TEXT;

-- Global firewall rules (override profile rules; higher priority)
CREATE TABLE IF NOT EXISTS global_firewall_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
  destination_cidr TEXT NOT NULL,
  port_range TEXT,
  protocol TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0
);

ALTER TABLE rule_profiles ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0;
UPDATE rule_profiles SET sort_order = id WHERE sort_order = 0;
UPDATE rule_profiles SET sort_order = 1 WHERE id = 1;
UPDATE rule_profiles SET sort_order = 2 WHERE id = 2;
