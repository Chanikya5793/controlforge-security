ALTER TABLE cases ADD COLUMN assignee_principal_id TEXT;

ALTER TABLE case_dispositions ADD COLUMN false_positive_reason TEXT;

CREATE TRIGGER case_dispositions_false_positive_reason_guard
BEFORE INSERT ON case_dispositions
WHEN (
  NEW.disposition = 'false_positive'
  AND (
    NEW.false_positive_reason IS NULL
    OR length(trim(NEW.false_positive_reason)) = 0
  )
) OR (
  NEW.disposition != 'false_positive'
  AND NEW.false_positive_reason IS NOT NULL
)
BEGIN
  SELECT RAISE(ABORT, 'false-positive reason is inconsistent with disposition');
END;
