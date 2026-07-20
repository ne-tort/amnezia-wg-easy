-- LE-on-IP as distinct type; Reality health; auto-renew flag.

ALTER TABLE ssl_certificates ADD COLUMN auto_renew INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ssl_certificates ADD COLUMN reality_status TEXT;
ALTER TABLE ssl_certificates ADD COLUMN reality_checked_at INTEGER;
ALTER TABLE ssl_certificates ADD COLUMN reality_check_detail TEXT;

-- Migrate existing LE rows whose domain/storage is an IPv4/IPv6 literal.
UPDATE ssl_certificates
SET type = 'lets_encrypt_ip'
WHERE type = 'lets_encrypt'
  AND (
    storage_key GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'
    OR domain GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'
    OR storage_key LIKE '%:%'
    OR domain LIKE '%:%'
  );

-- Default auto-renew on for Let's Encrypt lineages (domain + IP).
UPDATE ssl_certificates SET auto_renew = 1
WHERE type IN ('lets_encrypt', 'lets_encrypt_ip');
