-- Cleanup: Normalize bc_sync_status values to the new simplified schema
-- New valid statuses: 'not_synced', 'synced', 'error'
-- This migration cleans up any legacy status values

-- 1. Check current status distribution
SELECT
    bc_sync_status,
    COUNT(*) as count,
    CASE
        WHEN bc_sync_status IN ('not_synced', 'synced', 'error') THEN 'VALID'
        ELSE 'NEEDS_CLEANUP'
    END as status_validity
FROM time_entries
GROUP BY bc_sync_status
ORDER BY count DESC;

-- 2. Map legacy statuses to new schema:
--    'modified' -> 'not_synced' (needs to be re-synced)
--    'pending' -> 'not_synced' (not yet synced)
--    'posted' -> 'synced' (already synced and posted)
--    'failed' -> 'error' (sync failed)
--    NULL -> 'not_synced' (never synced)
--    Any other value -> 'not_synced' (default to not synced for safety)

UPDATE time_entries
SET bc_sync_status = CASE
    -- Legacy statuses that mean "needs sync"
    WHEN bc_sync_status IN ('modified', 'pending') THEN 'not_synced'

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

-- 3. Verify the cleanup
SELECT
    bc_sync_status,
    COUNT(*) as count
FROM time_entries
GROUP BY bc_sync_status
ORDER BY count DESC;

-- 4. Add a check constraint to prevent invalid statuses in the future (optional)
-- Uncomment if you want to enforce this at database level
/*
ALTER TABLE time_entries
DROP CONSTRAINT IF EXISTS check_bc_sync_status_values;

ALTER TABLE time_entries
ADD CONSTRAINT check_bc_sync_status_values
CHECK (bc_sync_status IN ('not_synced', 'synced', 'error'));
*/

COMMENT ON COLUMN time_entries.bc_sync_status IS
'Sync status with Business Central. Valid values: not_synced (needs sync), synced (synced to BC), error (sync failed)';
