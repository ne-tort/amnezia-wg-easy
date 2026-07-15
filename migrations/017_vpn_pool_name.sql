-- Human-readable name for VPN address pools (UI).
ALTER TABLE vpn_address_pools ADD COLUMN name TEXT NOT NULL DEFAULT '';

UPDATE vpn_address_pools SET name = 'Default' WHERE name = '' OR name IS NULL;
