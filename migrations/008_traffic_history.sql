-- Traffic snapshot: last known WG transfer_rx/transfer_tx per client (for delta computation and restart resilience).
CREATE TABLE IF NOT EXISTS traffic_snapshot (
  client_id TEXT PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
  last_rx INTEGER NOT NULL DEFAULT 0,
  last_tx INTEGER NOT NULL DEFAULT 0,
  sampled_at INTEGER NOT NULL
);

-- Traffic deltas: accumulated per-sample increments (rx_delta, tx_delta) for aggregation by period.
CREATE TABLE IF NOT EXISTS traffic_deltas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  rx_delta INTEGER NOT NULL DEFAULT 0,
  tx_delta INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_traffic_deltas_client_ts ON traffic_deltas(client_id, ts);
CREATE INDEX IF NOT EXISTS idx_traffic_deltas_ts ON traffic_deltas(ts);
