-- Update get_pending_sync_entries to filter by resource_no (user)
-- This ensures users only sync their own time entries

-- Drop the existing function
DROP FUNCTION IF EXISTS get_pending_sync_entries(UUID);
DROP FUNCTION IF EXISTS get_pending_sync_entries(UUID, VARCHAR);

-- Create the new function with resource_no filter
CREATE OR REPLACE FUNCTION get_pending_sync_entries(
  p_company_id UUID,
  p_resource_no VARCHAR DEFAULT NULL  -- Optional: if NULL, get all entries (for admin)
)
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
    AND (te.bc_sync_status = 'not_synced' OR te.bc_sync_status = 'error')  -- Sync not_synced and error entries
    AND te.is_editable = true
    AND (p_resource_no IS NULL OR te.resource_no = p_resource_no)  -- 🔑 Filter by user if provided
  ORDER BY te.date ASC, te.created_at ASC;
END;
$$;

-- Grant execute permission to service_role
GRANT EXECUTE ON FUNCTION get_pending_sync_entries(UUID, VARCHAR) TO service_role;

-- Add comment for documentation
COMMENT ON FUNCTION get_pending_sync_entries(UUID, VARCHAR) IS
'Returns time entries pending sync to Business Central. If p_resource_no is provided, filters entries for that specific user. If NULL, returns all pending entries (admin mode).';
