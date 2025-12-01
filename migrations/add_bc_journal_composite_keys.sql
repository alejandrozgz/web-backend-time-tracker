-- Add composite key fields for BC Job Journal Lines
-- These fields are needed to properly update/delete entries in BC

ALTER TABLE time_entries
ADD COLUMN IF NOT EXISTS bc_journal_template_name VARCHAR(50);

ALTER TABLE time_entries
ADD COLUMN IF NOT EXISTS bc_journal_line_no INTEGER;

-- Add comment to explain the fields
COMMENT ON COLUMN time_entries.bc_journal_template_name IS 'BC Journal Template Name (e.g., PROJECT) - part of composite key';
COMMENT ON COLUMN time_entries.bc_journal_line_no IS 'BC Journal Line Number - part of composite key';

-- Note: bc_batch_name already exists and is part of the composite key
