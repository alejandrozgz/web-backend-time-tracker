-- FINAL CLEANUP: Normalize ALL bc_sync_status values to the 3 valid states
-- Valid statuses: 'not_synced', 'synced', 'error'
-- This script will:
-- 1. Convert all legacy statuses to valid ones
-- 2. Update functions to only recognize the 3 valid states
-- 3. Add a constraint to prevent invalid statuses in the future

-- ========================================
-- STEP 1: Clean up existing data
-- ========================================

-- Check current status distribution
SELECT
    bc_sync_status,
    COUNT(*) as count,
    CASE
        WHEN bc_sync_status IN ('not_synced', 'synced', 'error') THEN '✓ VALID'
        ELSE '✗ NEEDS_CLEANUP'
    END as status_validity
FROM time_entries
GROUP BY bc_sync_status
ORDER BY count DESC;

-- Convert all legacy statuses to valid ones
UPDATE time_entries
SET bc_sync_status = CASE
    -- Legacy statuses that mean "needs sync"
    WHEN bc_sync_status IN ('modified', 'pending', 'local', 'draft') THEN 'not_synced'

    -- Legacy statuses that mean "already synced"
    WHEN bc_sync_status = 'posted' THEN 'synced'

    -- Legacy statuses that mean "error"
    WHEN bc_sync_status = 'failed' THEN 'error'

    -- NULL means never synced
    WHEN bc_sync_status IS NULL THEN 'not_synced'

    -- Keep valid current statuses
    WHEN bc_sync_status IN ('not_synced', 'synced', 'error') THEN bc_sync_status

    -- Default: anything else becomes not_synced (safe default)
    ELSE 'not_synced'
END
WHERE bc_sync_status IS NULL
   OR bc_sync_status NOT IN ('not_synced', 'synced', 'error');

-- Verify the cleanup
SELECT
    bc_sync_status,
    COUNT(*) as count,
    SUM(hours) as total_hours
FROM time_entries
GROUP BY bc_sync_status
ORDER BY count DESC;

-- ========================================
-- STEP 2: Update get_sync_dashboard function
-- ========================================

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
    COALESCE(SUM(hours) FILTER (WHERE bc_sync_status IN ('not_synced', 'error')), 0) AS pending_hours
  FROM time_entries
  WHERE company_id = p_company_id
    AND is_editable = true;
END;
$$;

GRANT EXECUTE ON FUNCTION get_sync_dashboard(UUID) TO service_role;

COMMENT ON FUNCTION get_sync_dashboard(UUID) IS
'Returns sync dashboard stats with 3 valid statuses: not_synced, synced, error';

-- ========================================
-- STEP 3: Update get_pending_sync_entries function
-- ========================================

DROP FUNCTION IF EXISTS get_pending_sync_entries(UUID);

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
    AND te.bc_sync_status IN ('not_synced', 'error')  -- Only these 2 statuses need sync
  ORDER BY te.date ASC, te.created_at ASC;
END;
$$;

GRANT EXECUTE ON FUNCTION get_pending_sync_entries(UUID) TO service_role;

COMMENT ON FUNCTION get_pending_sync_entries(UUID) IS
'Returns time entries pending sync to BC. Only includes not_synced and error statuses.';

-- ========================================
-- STEP 4: Add constraint to enforce valid statuses (OPTIONAL - RECOMMENDED)
-- ========================================

-- Drop existing constraint if any
ALTER TABLE time_entries
DROP CONSTRAINT IF EXISTS check_bc_sync_status_values;

-- Add constraint to only allow the 3 valid statuses
ALTER TABLE time_entries
ADD CONSTRAINT check_bc_sync_status_values
CHECK (bc_sync_status IN ('not_synced', 'synced', 'error'));

-- Update column comment
COMMENT ON COLUMN time_entries.bc_sync_status IS
'Sync status with Business Central. Valid values: not_synced (needs sync), synced (synced to BC), error (sync failed)';

-- ========================================
-- FINAL VERIFICATION
-- ========================================

-- Verify all entries now have valid statuses
SELECT
    'FINAL STATUS CHECK' as check_name,
    COUNT(*) as total_entries,
    COUNT(*) FILTER (WHERE bc_sync_status = 'not_synced') as not_synced,
    COUNT(*) FILTER (WHERE bc_sync_status = 'synced') as synced,
    COUNT(*) FILTER (WHERE bc_sync_status = 'error') as error,
    COUNT(*) FILTER (WHERE bc_sync_status NOT IN ('not_synced', 'synced', 'error')) as invalid
FROM time_entries;

SELECT '✓ Migration complete! Only 3 valid statuses remain: not_synced, synced, error' as result;
