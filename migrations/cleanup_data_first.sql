-- STEP 1: First, clean up ALL existing data (without constraint)
-- This must be run BEFORE adding the constraint

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

-- Remove the constraint if it exists (so we can update the data)
ALTER TABLE time_entries
DROP CONSTRAINT IF EXISTS check_bc_sync_status_values;

-- Convert ALL legacy statuses to valid ones
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

-- Final verification - should show 0 invalid entries
SELECT
    'CLEANUP VERIFICATION' as check_name,
    COUNT(*) as total_entries,
    COUNT(*) FILTER (WHERE bc_sync_status = 'not_synced') as not_synced,
    COUNT(*) FILTER (WHERE bc_sync_status = 'synced') as synced,
    COUNT(*) FILTER (WHERE bc_sync_status = 'error') as error,
    COUNT(*) FILTER (WHERE bc_sync_status NOT IN ('not_synced', 'synced', 'error')) as invalid
FROM time_entries;

SELECT '✓ Data cleanup complete! Now you can add the constraint.' as result;
