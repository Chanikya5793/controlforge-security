CREATE TABLE case_notes (
  tenant_id TEXT NOT NULL,
  note_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  body TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, note_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id)
);
CREATE INDEX idx_case_notes_case_time
ON case_notes(tenant_id, case_id, created_at DESC);

CREATE TRIGGER case_notes_no_update
BEFORE UPDATE ON case_notes
BEGIN
  SELECT RAISE(ABORT, 'case notes are append-only');
END;

CREATE TRIGGER case_notes_no_delete
BEFORE DELETE ON case_notes
BEGIN
  SELECT RAISE(ABORT, 'case notes are append-only');
END;

CREATE TABLE case_dispositions (
  tenant_id TEXT NOT NULL,
  disposition_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  disposition TEXT NOT NULL CHECK (disposition IN (
    'true_positive', 'false_positive', 'benign_positive', 'inconclusive'
  )),
  rationale TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, disposition_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id)
);
CREATE INDEX idx_case_dispositions_case_time
ON case_dispositions(tenant_id, case_id, created_at DESC);

CREATE TRIGGER case_dispositions_no_update
BEFORE UPDATE ON case_dispositions
BEGIN
  SELECT RAISE(ABORT, 'case dispositions are append-only');
END;

CREATE TRIGGER case_dispositions_no_delete
BEFORE DELETE ON case_dispositions
BEGIN
  SELECT RAISE(ABORT, 'case dispositions are append-only');
END;

ALTER TABLE cases ADD COLUMN disposition_required_after TEXT;
