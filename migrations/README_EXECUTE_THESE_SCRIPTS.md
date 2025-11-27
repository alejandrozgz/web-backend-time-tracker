# 🚨 CRITICAL: SQL Scripts to Execute in Supabase

These SQL scripts MUST be executed in Supabase SQL Editor for the application to work correctly with the new simplified status system.

## Why These Scripts Are Needed

The application code has been updated to use new simplified status names:
- ✅ `not_synced` (was: `local`) - Entry not yet synced to BC
- ✅ `synced` (was: `draft`) - Entry synced to BC as editable journal line
- ✅ `error` - Sync failed, needs retry
- ❌ REMOVED: `posted`, `modified`, `posting` (no longer used)

However, the **DATABASE** still contains:
- ❌ Old status values in existing time_entries records
- ❌ Old stored procedures that filter by old status names

## Execution Order (IMPORTANT)

Execute these scripts **IN THIS EXACT ORDER** in Supabase SQL Editor:

### 1️⃣ FIRST: Update Dashboard Function
**File:** `update_sync_dashboard_function.sql`

This updates the `get_sync_dashboard()` function to count the new status names.

```sql
-- Execute this entire file in Supabase SQL Editor
```

### 2️⃣ SECOND: Update Pending Sync Function
**File:** `fix_get_pending_sync_entries_function.sql`

This updates the `get_pending_sync_entries()` function to filter by new status names and return the `bc_batch_name` field.

```sql
-- Execute this entire file in Supabase SQL Editor
```

### 3️⃣ THIRD: Migrate Existing Data
**File:** `migrate_existing_statuses.sql`

This updates ALL existing time_entries records from old status names to new status names.

**CRITICAL:** This will modify existing data. Recommended to backup first.

```sql
-- Execute this entire file in Supabase SQL Editor
```

## How to Execute in Supabase

1. Open your Supabase dashboard
2. Navigate to **SQL Editor**
3. Click **New Query**
4. Copy the ENTIRE contents of each SQL file
5. Paste into the SQL editor
6. Click **Run** (or press Ctrl+Enter)
7. Verify success message
8. Repeat for next file

## Verification After Execution

After executing all three scripts, run this verification query:

```sql
-- Check status distribution
SELECT
  bc_sync_status,
  COUNT(*) as count,
  SUM(hours) as total_hours
FROM time_entries
GROUP BY bc_sync_status
ORDER BY bc_sync_status;

-- Should only show: not_synced, synced, error (no local, draft, posted, etc.)
```

## What Happens If You Don't Execute These?

Without executing these scripts, you will see:
- ❌ Status badges showing raw text like `sync_status.draft`
- ❌ Sync button not appearing when there are entries to sync
- ❌ Dashboard showing 0 pending entries
- ❌ Translations not working for status names
- ❌ Sync operations may fail

## After Execution

Once all scripts are executed:
- ✅ All UI will show translated status names correctly
- ✅ Sync button will appear when there are pending entries
- ✅ Dashboard will show accurate counts
- ✅ Sync operations will work properly

## Troubleshooting

If you encounter errors:

### Error: "function ... does not exist"
**Solution:** The function may have a different signature. Run the DROP command separately first:
```sql
DROP FUNCTION IF EXISTS get_pending_sync_entries(UUID);
DROP FUNCTION IF EXISTS get_sync_dashboard(UUID);
```

### Error: "permission denied"
**Solution:** Make sure you're using the Supabase service_role key or executing from the SQL Editor as admin.

### No data changes after running migrate_existing_statuses.sql
**Solution:** Check if data already has new status names:
```sql
SELECT DISTINCT bc_sync_status FROM time_entries;
```

## Files Location

All SQL files are in:
```
backend/migrations/
├── fix_get_pending_sync_entries_function.sql  ← Execute 2nd
├── update_sync_dashboard_function.sql         ← Execute 1st
└── migrate_existing_statuses.sql              ← Execute 3rd
```

## Questions?

If anything fails or you're unsure, STOP and ask for help before proceeding.
