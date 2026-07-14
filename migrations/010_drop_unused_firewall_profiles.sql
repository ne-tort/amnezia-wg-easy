-- Remove unused default firewall profiles: "Internet + one LAN IP" and "Synology".
UPDATE clients SET rule_profile_id = NULL WHERE rule_profile_id IN (3, 4);
DELETE FROM ip_rules WHERE rule_profile_id IN (3, 4);
DELETE FROM rule_profiles WHERE id IN (3, 4);
