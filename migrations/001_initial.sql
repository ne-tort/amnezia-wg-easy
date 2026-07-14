-- Panel users (web admin login, roles)
CREATE TABLE IF NOT EXISTS panel_users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'moderator', 'user')),
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_login_at INTEGER
);

-- Rule profiles (named sets of rules: full access, internet only, etc.)
CREATE TABLE IF NOT EXISTS rule_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT
);

-- IP rules per profile (allow/deny by destination)
CREATE TABLE IF NOT EXISTS ip_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_profile_id INTEGER NOT NULL REFERENCES rule_profiles(id) ON DELETE CASCADE,
  action TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
  destination_cidr TEXT NOT NULL,
  port_range TEXT,
  protocol TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0
);

-- App-wide settings (key-value)
CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

-- Protocol templates (default I1 signatures: dns, quic, stun, sip, webrtc, dtls)
CREATE TABLE IF NOT EXISTS protocol_templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id TEXT NOT NULL UNIQUE,
  default_hex TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Server WG/Amnezia config (singleton row)
CREATE TABLE IF NOT EXISTS server_config (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  private_key TEXT NOT NULL,
  public_key TEXT NOT NULL,
  address TEXT NOT NULL,
  jc INTEGER NOT NULL,
  jmin INTEGER NOT NULL,
  jmax INTEGER NOT NULL,
  s1 TEXT NOT NULL,
  s2 TEXT NOT NULL,
  s3 TEXT NOT NULL,
  s4 TEXT NOT NULL,
  h1 TEXT NOT NULL,
  h2 TEXT NOT NULL,
  h3 TEXT NOT NULL,
  h4 TEXT NOT NULL,
  i2 TEXT,
  i3 TEXT,
  i4 TEXT,
  i5 TEXT,
  updated_at INTEGER
);

-- VPN clients
CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT NOT NULL,
  public_key TEXT NOT NULL,
  private_key TEXT NOT NULL,
  pre_shared_key TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  note TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  expires_at INTEGER,
  rule_profile_id INTEGER REFERENCES rule_profiles(id),
  default_profile TEXT,
  default_level INTEGER
);

-- Versioned client config snapshots (parsed fields + raw .conf text)
CREATE TABLE IF NOT EXISTS client_config_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  private_key TEXT,
  address TEXT,
  dns TEXT,
  mtu TEXT,
  jc INTEGER,
  jmin INTEGER,
  jmax INTEGER,
  s1 TEXT,
  s2 TEXT,
  s3 TEXT,
  s4 TEXT,
  h1 TEXT,
  h2 TEXT,
  h3 TEXT,
  h4 TEXT,
  i_block TEXT,
  peer_public_key TEXT,
  preshared_key TEXT,
  allowed_ips TEXT,
  persistent_keepalive TEXT,
  endpoint TEXT,
  config_raw TEXT
);

CREATE INDEX IF NOT EXISTS idx_client_config_versions_client_id ON client_config_versions(client_id);
CREATE INDEX IF NOT EXISTS idx_clients_rule_profile_id ON clients(rule_profile_id);
CREATE INDEX IF NOT EXISTS idx_ip_rules_rule_profile_id ON ip_rules(rule_profile_id);

-- Seed rule profiles
INSERT INTO rule_profiles (id, name, description) VALUES
  (1, 'Full access', 'VPN + LAN + other clients'),
  (2, 'Internet only', 'No LAN, no other VPN clients');

-- Seed ip_rules for "Internet only" (profile 2): allow 0.0.0.0/0 (NAT), deny 10.8.0.0/24 and 192.168.0.0/16
INSERT INTO ip_rules (rule_profile_id, action, destination_cidr, sort_order) VALUES
  (2, 'allow', '0.0.0.0/0', 0),
  (2, 'deny', '10.8.0.0/24', 10),
  (2, 'deny', '192.168.0.0/16', 20);

-- Seed app_settings
INSERT OR IGNORE INTO app_settings (key, value) VALUES
  ('display_name', 'Amnezia WG-Easy'),
  ('language', 'en'),
  ('ui_traffic_stats', 'false'),
  ('ui_chart_type', '0'),
  ('check_update', 'false');

-- Seed protocol_templates from signatures.default.json (default I1 hex per profile)
INSERT INTO protocol_templates (profile_id, default_hex, updated_at) VALUES
  ('dns', '<b 0x084481800001000300000000077469636b65747306776964676574096b696e6f706f69736b0272750000010001c00c0005000100000039001806776964676574077469636b6574730679616e646578c025c0390005000100000039002b1765787465726e616c2d7469636b6574732d776964676574066166697368610679616e646578036e657400c05d000100010000001c000457fafe25>', 0),
  ('quic', '<b 0x68747470733a2f2f6578616d706c652e636f6d2f>', 0),
  ('sip', '<b 0x4f5054494f4e53207369703a7369702e6578616d706c652e636f6d205349502f322e300d0a5669613a205349502f322e302f554450203132372e302e302e313a353036303b6272616e63683d7a39684734624b393237333531613832326236643161320d0a4d61782d466f7277617264733a2037300d0a46726f6d3a203c7369703a636f6c6c6563746f72406c6f63616c686f73743e3b7461673d310d0a546f3a203c7369703a75736572407369702e6578616d706c652e636f6d3e0d0a43616c6c2d49443a20313461373834336562636564383730310d0a435365713a2031204f5054494f4e530d0a436f6e746163743a203c7369703a636f6c6c6563746f72403132372e302e302e313a353036303e0d0a436f6e74656e742d4c656e6774683a20300d0a0d0a>', 0),
  ('stun', '<b 0x000100002112a442544553545445535454455354>', 0),
  ('webrtc', '<b 0x000100002112a442000000000000000000000000>', 0),
  ('dtls', '<b 0x16fefd00000000000000000000001801000014000000000000000000>', 0);
