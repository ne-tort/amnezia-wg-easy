-- Per-client MTU profile id (from mtu-profiles.json).
ALTER TABLE clients ADD COLUMN mtu_profile TEXT;
