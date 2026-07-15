-- Server-side VPN address pools (one or more CIDRs on awg0).
CREATE TABLE IF NOT EXISTS vpn_address_pools (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cidr TEXT NOT NULL UNIQUE,
  gateway TEXT NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vpn_pools_sort ON vpn_address_pools(sort_order ASC, id ASC);
