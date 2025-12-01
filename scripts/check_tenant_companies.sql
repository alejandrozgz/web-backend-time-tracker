-- Script para verificar y crear companies para un tenant

-- 1. Ver todos los tenants
SELECT
  id,
  slug,
  name,
  bc_tenant_id,
  oauth_enabled,
  is_active
FROM tenants
ORDER BY created_at DESC;

-- 2. Ver companies del tenant 'empresa-demo'
SELECT
  c.id,
  c.tenant_id,
  c.bc_company_id,
  c.name,
  c.is_active,
  t.slug as tenant_slug
FROM companies c
JOIN tenants t ON c.tenant_id = t.id
WHERE t.slug = 'empresa-demo';

-- 3. Contar companies por tenant
SELECT
  t.slug,
  t.name as tenant_name,
  COUNT(c.id) as companies_count
FROM tenants t
LEFT JOIN companies c ON c.tenant_id = t.id
GROUP BY t.id, t.slug, t.name
ORDER BY t.slug;

-- 4. Si no hay companies, crear una de ejemplo:
-- NOTA: Reemplazar los valores según tu configuración de BC

/*
-- Primero obtener el tenant_id
SELECT id FROM tenants WHERE slug = 'empresa-demo';

-- Luego insertar la company (ajustar valores)
INSERT INTO companies (tenant_id, bc_company_id, name, is_active)
VALUES (
  (SELECT id FROM tenants WHERE slug = 'empresa-demo'),
  'CRONUS USA Inc.',  -- El Company Name en Business Central
  'CRONUS USA Inc.',  -- Nombre amigable
  true
);
*/