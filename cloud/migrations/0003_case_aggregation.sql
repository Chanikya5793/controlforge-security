ALTER TABLE cases ADD COLUMN semantic_key TEXT;

CREATE UNIQUE INDEX idx_cases_open_semantic
ON cases(tenant_id, semantic_key)
WHERE semantic_key IS NOT NULL AND status != 'closed';
