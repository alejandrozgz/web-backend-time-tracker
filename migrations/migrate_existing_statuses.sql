-- Migrate existing bc_sync_status values to new status names
-- Old -> New:
-- 'local' -> 'not_synced'
-- 'draft' -> 'synced'
-- 'modified' -> 'not_synced'
-- 'posted' -> (delete, no longer used)
-- 'posting' -> (delete, no longer used)
-- 'error' -> 'error' (stays the same)

-- Update local entries to not_synced
UPDATE time_entries
SET bc_sync_status = 'not_synced'
WHERE bc_sync_status = 'local';

-- Update draft entries to synced
UPDATE time_entries
SET bc_sync_status = 'synced'
WHERE bc_sync_status = 'draft';

-- Update modified entries to not_synced
UPDATE time_entries
SET bc_sync_status = 'not_synced'
WHERE bc_sync_status = 'modified';

-- Mark posted/posting entries as not editable and set to synced
UPDATE time_entries
SET bc_sync_status = 'synced',
    is_editable = false
WHERE bc_sync_status IN ('posted', 'posting');

-- Check results
SELECT
  bc_sync_status,
  COUNT(*) as count
FROM time_entries
GROUP BY bc_sync_status
ORDER BY bc_sync_status;
