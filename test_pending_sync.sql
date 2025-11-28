-- Test script to verify get_pending_sync_entries function

-- 1. Check current function definition
SELECT
    routine_name,
    routine_definition
FROM information_schema.routines
WHERE routine_name = 'get_pending_sync_entries';

-- 2. Test the function (replace with your actual company_id)
-- SELECT * FROM get_pending_sync_entries('your-company-id-here');

-- 3. Check time entries with different sync statuses
SELECT
    id,
    resource_no,
    date,
    hours,
    description,
    bc_sync_status,
    is_editable,
    bc_batch_name,
    last_modified_at
FROM time_entries
WHERE company_id = 'your-company-id-here'  -- Replace with actual company_id
ORDER BY last_modified_at DESC
LIMIT 20;

-- 4. Count entries by sync status
SELECT
    bc_sync_status,
    is_editable,
    COUNT(*) as count
FROM time_entries
WHERE company_id = 'your-company-id-here'  -- Replace with actual company_id
GROUP BY bc_sync_status, is_editable;

-- 5. Check specifically for modified entries that should sync
SELECT
    id,
    resource_no,
    date,
    hours,
    description,
    bc_sync_status,
    bc_batch_name,
    is_editable,
    last_modified_at,
    bc_last_sync_at,
    -- Check if this entry SHOULD be included in pending sync
    CASE
        WHEN is_editable = true AND (bc_sync_status = 'not_synced' OR bc_sync_status = 'error' OR bc_sync_status IS NULL)
        THEN 'SHOULD BE SYNCED'
        ELSE 'WILL NOT BE SYNCED'
    END as sync_eligibility
FROM time_entries
WHERE company_id = 'your-company-id-here'  -- Replace with actual company_id
    AND last_modified_at > bc_last_sync_at  -- Modified after last sync
ORDER BY last_modified_at DESC;
