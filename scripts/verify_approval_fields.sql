-- Script para verificar si los campos de aprobación existen

-- 1. Verificar si las columnas existen en time_entries
SELECT
    column_name,
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns
WHERE table_name = 'time_entries'
  AND column_name IN ('approval_status', 'bc_comments')
ORDER BY column_name;

-- 2. Ver algunos registros con los nuevos campos
SELECT
    id,
    description,
    bc_sync_status,
    approval_status,
    bc_comments,
    bc_journal_id
FROM time_entries
WHERE bc_sync_status = 'synced'
LIMIT 10;

-- 3. Contar entries por approval_status
SELECT
    approval_status,
    COUNT(*) as count
FROM time_entries
GROUP BY approval_status
ORDER BY count DESC;
