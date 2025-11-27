-- FIX: Update get_pending_sync_entries to use NEW status names
-- New statuses: 'not_synced', 'synced', 'error'
-- This function returns entries that need to be synced to BC

-- Drop the existing function first
DROP FUNCTION IF EXISTS get_pending_sync_entries(UUID);

-- Create the corrected function
CREATE OR REPLACE FUNCTION get_pending_sync_entries(p_company_id UUID)
RETURNS TABLE (
  id UUID,
  tenant_id UUID,
  company_id UUID,
  bc_job_id VARCHAR,
  bc_task_id VARCHAR,
  date DATE,
  hours DECIMAL,
  description TEXT,
  start_time TIME,
  end_time TIME,
  resource_no VARCHAR,
  bc_batch_name VARCHAR,
  bc_sync_status VARCHAR,
  bc_journal_id VARCHAR,
  bc_last_sync_at TIMESTAMPTZ,
  is_editable BOOLEAN,
  created_at TIMESTAMPTZ,
  last_modified_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  RETURN QUERY
  SELECT
    te.id,
    te.tenant_id,
    te.company_id,
    te.bc_job_id,
    te.bc_task_id,
    te.date,
    te.hours,
    te.description,
    te.start_time,
    te.end_time,
    te.resource_no,
    te.bc_batch_name,
    te.bc_sync_status,
    te.bc_journal_id,
    te.bc_last_sync_at,
    te.is_editable,
    te.created_at,
    te.last_modified_at
  FROM time_entries te
  WHERE te.company_id = p_company_id
    AND te.is_editable = true
    AND (
      te.bc_sync_status = 'not_synced'  -- New entries not yet synced
      OR te.bc_sync_status = 'error'    -- Failed entries that need retry
      OR te.bc_sync_status IS NULL      -- Entries with no status set (legacy)
    )
  ORDER BY te.date ASC, te.created_at ASC;
END;
$$;

-- Grant execute permission to service_role
GRANT EXECUTE ON FUNCTION get_pending_sync_entries(UUID) TO service_role;

-- Add comment for documentation
COMMENT ON FUNCTION get_pending_sync_entries(UUID) IS
'Returns all time entries that are pending sync to Business Central. Includes entries with status: not_synced (new), error (failed), or NULL (legacy). Synced entries are NOT included as they are already synced to BC. Only editable entries are returned.';
