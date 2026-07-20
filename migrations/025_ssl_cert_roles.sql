-- Panel is a role (is_panel), not a certificate type.
ALTER TABLE ssl_certificates ADD COLUMN is_panel INTEGER NOT NULL DEFAULT 0;

-- Migrate legacy type=panel rows to real material types + role flag.
UPDATE ssl_certificates
SET
  is_panel = 1,
  managed = 1,
  type = CASE
    WHEN lower(coalesce(source, '')) IN ('issued') THEN 'lets_encrypt'
    WHEN lower(coalesce(source, '')) IN ('imported_pem', 'imported_path') THEN 'manual'
    WHEN lower(coalesce(source, '')) IN ('generated') THEN 'self_signed'
    WHEN lower(coalesce(issuer, '')) LIKE '%let%encrypt%' THEN 'lets_encrypt'
    WHEN lower(coalesce(issuer, '')) LIKE '%let''s encrypt%' THEN 'lets_encrypt'
    ELSE 'self_signed'
  END
WHERE type = 'panel';

-- Keep managed rows marked as panel role.
UPDATE ssl_certificates SET is_panel = 1 WHERE managed = 1 AND type != 'reality';

CREATE INDEX IF NOT EXISTS idx_ssl_certificates_is_panel ON ssl_certificates(is_panel);
