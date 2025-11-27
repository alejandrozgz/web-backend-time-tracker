-- Update get_sync_dashboard function to use new status names
-- Old statuses: 'local', 'draft', 'posted', 'modified'
-- New statuses: 'not_synced', 'synced', 'error'

DROP FUNCTION IF EXISTS get_sync_dashboard(UUID);

CREATE OR REPLACE FUNCTION get_sync_dashboard(p_company_id UUID)
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
    AND is_editable = true;
END;
$$;

GRANT EXECUTE ON FUNCTION get_sync_dashboard(UUID) TO service_role;

COMMENT ON FUNCTION get_sync_dashboard(UUID) IS
'Returns sync dashboard stats with new status names: not_synced, synced, error';
