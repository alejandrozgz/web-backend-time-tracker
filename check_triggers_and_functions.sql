-- Script para verificar triggers y funciones que puedan estar modificando bc_sync_status

-- 1. Verificar triggers en la tabla time_entries
SELECT
    trigger_name,
    event_manipulation,
    event_object_table,
    action_statement,
    action_timing
FROM information_schema.triggers
WHERE event_object_table = 'time_entries'
ORDER BY trigger_name;

-- 2. Verificar funciones que mencionen bc_sync_status
SELECT
    routine_name,
    routine_type,
    data_type as return_type,
    routine_definition
FROM information_schema.routines
WHERE routine_definition ILIKE '%bc_sync_status%'
   OR routine_definition ILIKE '%modified%'
ORDER BY routine_name;

-- 3. Verificar políticas RLS en time_entries
SELECT
    schemaname,
    tablename,
    policyname,
    permissive,
    roles,
    cmd,
    qual,
    with_check
FROM pg_policies
WHERE tablename = 'time_entries';

-- 4. Verificar estructura actual de la columna bc_sync_status
SELECT
    column_name,
    data_type,
    column_default,
    is_nullable
FROM information_schema.columns
WHERE table_name = 'time_entries'
  AND column_name = 'bc_sync_status';

-- 5. Verificar distribución de estados actual
SELECT
    bc_sync_status,
    COUNT(*) as count,
    MIN(created_at) as oldest_entry,
    MAX(created_at) as newest_entry
FROM time_entries
GROUP BY bc_sync_status
ORDER BY count DESC;

-- 6. Verificar últimas 10 entradas creadas y su estado
SELECT
    id,
    bc_sync_status,
    description,
    hours,
    resource_no,
    created_at,
    last_modified_at,
    bc_last_sync_at
FROM time_entries
ORDER BY created_at DESC
LIMIT 10;
