-- SSL Certificate Manager inventory (PEM meta + Reality keys; PEM files live in certbot volume)
CREATE TABLE IF NOT EXISTS ssl_certificates (
  id TEXT PRIMARY KEY NOT NULL,
  type TEXT NOT NULL,
  label TEXT,
  domain TEXT,
  sni TEXT,
  email TEXT,
  storage_key TEXT,
  not_after INTEGER,
  issuer TEXT,
  fingerprint_sha256 TEXT,
  reality_private_key TEXT,
  reality_public_key TEXT,
  reality_short_id TEXT,
  reality_dest TEXT,
  source TEXT,
  managed INTEGER NOT NULL DEFAULT 0,
  notes TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ssl_certificates_type ON ssl_certificates(type);
CREATE INDEX IF NOT EXISTS idx_ssl_certificates_domain ON ssl_certificates(domain);
