-- Script para encontrar QUÉ está creando el estado 'modified'

-- 1. Verificar si hay triggers en time_entries
SELECT
    trigger_name,
    event_manipulation,
    action_statement,
    action_timing
FROM information_schema.triggers
WHERE event_object_table = 'time_entries';

-- 2. Verificar si hay funciones que mencionen 'modified'
SELECT
    routine_name,
    routine_type,
    routine_definition
FROM information_schema.routines
WHERE routine_definition ILIKE '%modified%'
  AND routine_definition ILIKE '%bc_sync_status%';

-- 3. Verificar la definición de la tabla time_entries
SELECT
    column_name,
    data_type,
    column_default,
    is_nullable
FROM information_schema.columns
WHERE table_name = 'time_entries'
  AND column_name = 'bc_sync_status';

-- 4. Verificar si hay políticas RLS que modifiquen el estado
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

-- 5. Ver una entrada específica que tiene 'modified'
SELECT
    id,
    bc_sync_status,
    created_at,
    last_modified_at,
    bc_last_sync_at,
    description
FROM time_entries
WHERE bc_sync_status = 'modified'
ORDER BY last_modified_at DESC
LIMIT 5;
