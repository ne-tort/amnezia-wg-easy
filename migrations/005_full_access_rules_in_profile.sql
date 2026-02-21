-- Migrate: move 0.0.0.0/0 and ::/0 from global to Full Access (profile 1).
-- For DBs that had these in global_firewall_rules, remove and add to ip_rules for profile 1.
DELETE FROM global_firewall_rules WHERE destination_cidr IN ('0.0.0.0/0', '::/0');

INSERT INTO ip_rules (rule_profile_id, action, destination_cidr, sort_order)
SELECT 1, 'allow', '0.0.0.0/0', 0
WHERE NOT EXISTS (SELECT 1 FROM ip_rules WHERE rule_profile_id = 1 AND destination_cidr = '0.0.0.0/0');

INSERT INTO ip_rules (rule_profile_id, action, destination_cidr, sort_order)
SELECT 1, 'allow', '::/0', 1
WHERE NOT EXISTS (SELECT 1 FROM ip_rules WHERE rule_profile_id = 1 AND destination_cidr = '::/0');
