ALTER TABLE alerts ADD COLUMN rule_version INTEGER;
ALTER TABLE alerts ADD COLUMN rule_digest TEXT;
ALTER TABLE alerts ADD COLUMN rule_snapshot_json TEXT;
ALTER TABLE alerts ADD COLUMN fingerprint_version TEXT NOT NULL DEFAULT 'legacy-cloud-v0';
ALTER TABLE alerts ADD COLUMN detector_version TEXT NOT NULL DEFAULT 'legacy-cloud-unknown';
ALTER TABLE alerts ADD COLUMN evidence_json TEXT NOT NULL DEFAULT '{"provenance":"legacy-cloud-alert"}';
