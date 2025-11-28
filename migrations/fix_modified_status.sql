-- Simple fix: Convert all 'modified' status to 'not_synced'
-- This ensures modified entries will appear as pending and can be synced

-- Update all entries with 'modified' status to 'not_synced'
UPDATE time_entries
SET bc_sync_status = 'not_synced'
WHERE bc_sync_status = 'modified';

-- Also fix any other invalid statuses
UPDATE time_entries
SET bc_sync_status = CASE
    WHEN bc_sync_status IN ('modified', 'pending') THEN 'not_synced'
    WHEN bc_sync_status = 'posted' THEN 'synced'
    WHEN bc_sync_status = 'failed' THEN 'error'
    WHEN bc_sync_status IS NULL THEN 'not_synced'
    ELSE bc_sync_status
END
WHERE bc_sync_status NOT IN ('not_synced', 'synced', 'error')
   OR bc_sync_status IS NULL;

-- Verify the fix
SELECT
    bc_sync_status,
    COUNT(*) as count,
    COUNT(*) * 100.0 / SUM(COUNT(*)) OVER () as percentage
FROM time_entries
GROUP BY bc_sync_status
ORDER BY count DESC;
