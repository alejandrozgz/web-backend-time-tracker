-- Migration: Add approval tracking fields to time_entries
-- Date: 2025-12-01
-- Description: Add fields to track approval status and comments from BC Job Journal Lines

-- Add approval_status column
ALTER TABLE time_entries
ADD COLUMN IF NOT EXISTS approval_status VARCHAR(20) DEFAULT 'pending';

-- Add bc_comments column
ALTER TABLE time_entries
ADD COLUMN IF NOT EXISTS bc_comments TEXT;

-- Add index for faster filtering by approval status
CREATE INDEX IF NOT EXISTS idx_time_entries_approval_status
ON time_entries(approval_status);

-- Add comment
COMMENT ON COLUMN time_entries.approval_status IS 'Approval status from BC: pending, approved, rejected';
COMMENT ON COLUMN time_entries.bc_comments IS 'Comments from BC Job Journal Line';

-- Update existing records to have 'pending' status
UPDATE time_entries
SET approval_status = 'pending'
WHERE approval_status IS NULL;