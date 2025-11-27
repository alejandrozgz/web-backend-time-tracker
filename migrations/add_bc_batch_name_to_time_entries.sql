-- Migration: Add bc_batch_name column to time_entries table
-- This column stores the Business Central job journal batch name for each entry
-- It's set during entry creation from the user's JWT token (which contains jobJournalBatch from BC)

ALTER TABLE time_entries
ADD COLUMN IF NOT EXISTS bc_batch_name VARCHAR(50);

-- Add index for better query performance (used during sync operations)
CREATE INDEX IF NOT EXISTS idx_time_entries_bc_batch_name
ON time_entries(bc_batch_name);

-- Add comment for documentation
COMMENT ON COLUMN time_entries.bc_batch_name IS
'Business Central job journal batch name for this entry. Populated from resource.jobJournalBatch during entry creation.';
