-- Update get_sync_dashboard to filter by resource_no (user)
-- This ensures users only see their own sync dashboard stats

-- Drop the existing function
DROP FUNCTION IF EXISTS get_sync_dashboard(UUID);
DROP FUNCTION IF EXISTS get_sync_dashboard(UUID, VARCHAR);

-- Create the new function with resource_no filter
CREATE OR REPLACE FUNCTION get_sync_dashboard(
  p_company_id UUID,
  p_resource_no VARCHAR DEFAULT NULL  -- Optional: if NULL, get all entries (for admin)
)
RETURNS TABLE (
  not_synced_entries BIGINT,
  synced_entries BIGINT,
  error_entries BIGINT,
  pending_hours NUMERIC
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  RETURN QUERY
  SELECT
    COUNT(*) FILTER (WHERE bc_sync_status = 'not_synced') AS not_synced_entries,
    COUNT(*) FILTER (WHERE bc_sync_status = 'synced') AS synced_entries,
    COUNT(*) FILTER (WHERE bc_sync_status = 'error') AS error_entries,
    COALESCE(SUM(hours) FILTER (WHERE bc_sync_status = 'not_synced' OR bc_sync_status = 'error'), 0) AS pending_hours
  FROM time_entries
  WHERE company_id = p_company_id
    AND is_editable = true
    AND (p_resource_no IS NULL OR resource_no = p_resource_no);  -- 🔑 Filter by user if provided
END;
$$;

-- Grant execute permission to service_role
GRANT EXECUTE ON FUNCTION get_sync_dashboard(UUID, VARCHAR) TO service_role;

-- Add comment for documentation
COMMENT ON FUNCTION get_sync_dashboard(UUID, VARCHAR) IS
'Returns sync dashboard stats. If p_resource_no is provided, filters stats for that specific user. If NULL, returns stats for all users (admin mode).';
