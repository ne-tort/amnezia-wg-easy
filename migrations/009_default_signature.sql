-- Static signature bank: pin iteration number per client (protocol + variant).
ALTER TABLE clients ADD COLUMN default_signature TEXT;
