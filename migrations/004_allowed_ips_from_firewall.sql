-- Seed Full Access (profile id=1) with default allow rules; global rules stay empty.
-- AllowedIPs in client configs are built from allow rules (global + profile + client).
INSERT INTO ip_rules (rule_profile_id, action, destination_cidr, sort_order)
SELECT 1, 'allow', '0.0.0.0/0', 0
WHERE NOT EXISTS (SELECT 1 FROM ip_rules WHERE rule_profile_id = 1 AND destination_cidr = '0.0.0.0/0');

INSERT INTO ip_rules (rule_profile_id, action, destination_cidr, sort_order)
SELECT 1, 'allow', '::/0', 1
WHERE NOT EXISTS (SELECT 1 FROM ip_rules WHERE rule_profile_id = 1 AND destination_cidr = '::/0');
