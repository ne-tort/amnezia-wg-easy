-- Renumber sort_order to be unique within each group (order preserved by sort_order, id).
-- Groups: global_firewall_rules (single group); ip_rules per rule_profile_id; client_firewall_rules per client_id.

-- global_firewall_rules: one group, assign 0, 1, 2, ... by (sort_order, id)
UPDATE global_firewall_rules
SET sort_order = (
  SELECT COUNT(*) FROM global_firewall_rules g2
  WHERE g2.sort_order < global_firewall_rules.sort_order
     OR (g2.sort_order = global_firewall_rules.sort_order AND g2.id < global_firewall_rules.id)
);

-- ip_rules: per rule_profile_id, assign 0, 1, 2, ... by (sort_order, id)
UPDATE ip_rules
SET sort_order = (
  SELECT COUNT(*) FROM ip_rules i2
  WHERE i2.rule_profile_id = ip_rules.rule_profile_id
    AND (i2.sort_order < ip_rules.sort_order OR (i2.sort_order = ip_rules.sort_order AND i2.id < ip_rules.id))
);

-- client_firewall_rules: per client_id, assign 0, 1, 2, ... by (sort_order, id)
UPDATE client_firewall_rules
SET sort_order = (
  SELECT COUNT(*) FROM client_firewall_rules c2
  WHERE c2.client_id = client_firewall_rules.client_id
    AND (c2.sort_order < client_firewall_rules.sort_order OR (c2.sort_order = client_firewall_rules.sort_order AND c2.id < client_firewall_rules.id))
);
