-- Per-client toggle: use server (Amnezia) DNS vs direct DNS. Only used when server DNS is available.
ALTER TABLE clients ADD COLUMN use_server_dns INTEGER NOT NULL DEFAULT 1;
