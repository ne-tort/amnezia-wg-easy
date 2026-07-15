-- Per-source traffic deltas (awg | xray). Existing rows default to awg.
ALTER TABLE traffic_deltas ADD COLUMN source TEXT NOT NULL DEFAULT 'awg';

CREATE INDEX IF NOT EXISTS idx_traffic_deltas_client_source_ts
  ON traffic_deltas(client_id, source, ts);

-- Last known Xray user counters (uplink→last_rx, downlink→last_tx) for delta compute.
CREATE TABLE IF NOT EXISTS traffic_xray_snapshot (
  client_id TEXT PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
  last_rx INTEGER NOT NULL DEFAULT 0,
  last_tx INTEGER NOT NULL DEFAULT 0,
  sampled_at INTEGER NOT NULL
);
