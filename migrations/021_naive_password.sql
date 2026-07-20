-- Per-client NaiveProxy forward_proxy basic_auth password (Caddyfile)
ALTER TABLE clients ADD COLUMN naive_password TEXT;
