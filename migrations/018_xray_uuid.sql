-- Per-client Xray VLESS UUID (synced into amnezia-xray server.json inbound clients)
ALTER TABLE clients ADD COLUMN xray_uuid TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_xray_uuid ON clients(xray_uuid) WHERE xray_uuid IS NOT NULL;
