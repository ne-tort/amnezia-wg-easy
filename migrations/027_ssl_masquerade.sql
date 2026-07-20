-- Masquerade camouflage URLs in SSL inventory (Hysteria etc.).
ALTER TABLE ssl_certificates ADD COLUMN masquerade_url TEXT;
