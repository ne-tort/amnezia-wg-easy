-- Per-client pinned junk snapshots keyed by CPS protocol id (JSON object).
ALTER TABLE clients ADD COLUMN junk_pins TEXT;
