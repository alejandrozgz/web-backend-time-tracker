-- FIX: Update get_sync_dashboard to include LEGACY statuses
-- This ensures entries with legacy statuses (modified, pending, failed, posted) are counted correctly
-- Legacy status mapping:
--   'modified', 'pending' -> count as 'not_synced'
--   'failed' -> count as 'error'
--   'posted' -> count as 'synced'

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
    -- Count not_synced + legacy statuses (modified, pending)
    COUNT(*) FILTER (WHERE bc_sync_status IN ('not_synced', 'modified', 'pending')) AS not_synced_entries,

    -- Count synced + legacy status (posted)
    COUNT(*) FILTER (WHERE bc_sync_status IN ('synced', 'posted')) AS synced_entries,

    -- Count error + legacy status (failed)
    COUNT(*) FILTER (WHERE bc_sync_status IN ('error', 'failed')) AS error_entries,

    -- Sum hours for entries pending sync (not_synced, modified, pending, error, failed)
    COALESCE(
      SUM(hours) FILTER (WHERE bc_sync_status IN ('not_synced', 'modified', 'pending', 'error', 'failed')),
      0
    ) AS pending_hours
  FROM time_entries
  WHERE company_id = p_company_id
    AND is_editable = true;
END;
$$;

GRANT EXECUTE ON FUNCTION get_sync_dashboard(UUID) TO service_role;

COMMENT ON FUNCTION get_sync_dashboard(UUID) IS
'Returns sync dashboard stats including legacy status support. Maps: modified/pending->not_synced, failed->error, posted->synced';

-- Verify the fix by checking current distribution
SELECT
    bc_sync_status,
    COUNT(*) as count,
    SUM(hours) as total_hours,
    CASE
        WHEN bc_sync_status IN ('not_synced', 'modified', 'pending') THEN 'COUNTED AS: not_synced'
        WHEN bc_sync_status IN ('synced', 'posted') THEN 'COUNTED AS: synced'
        WHEN bc_sync_status IN ('error', 'failed') THEN 'COUNTED AS: error'
        ELSE 'UNKNOWN STATUS - NOT COUNTED'
    END as mapping
FROM time_entries
WHERE is_editable = true
GROUP BY bc_sync_status
ORDER BY count DESC;
