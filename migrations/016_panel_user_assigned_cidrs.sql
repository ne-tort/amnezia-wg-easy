-- Per panel-user assigned VPN CIDR ranges (JSON array of strings).
ALTER TABLE panel_users ADD COLUMN assigned_cidrs TEXT NOT NULL DEFAULT '[]';
