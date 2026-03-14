-- ============================================================
-- BASE SCHEMA — Tablas core del Time Tracker
-- Reconstruido desde schema_supabase.json (producción)
-- Debe ejecutarse ANTES que cualquier otra migración.
-- ============================================================

-- Habilitar extensiones necesarias
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── tenants ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  slug             VARCHAR(255) NOT NULL UNIQUE,
  name             VARCHAR(255) NOT NULL,
  bc_base_url      VARCHAR(255) NOT NULL,
  bc_environment   VARCHAR(100) DEFAULT 'Production',
  settings         JSONB DEFAULT '{}',
  is_active        BOOLEAN DEFAULT true,
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW(),
  bc_tenant_id     VARCHAR(255),
  bc_client_id     VARCHAR(255),
  bc_client_secret VARCHAR(255),
  oauth_enabled    BOOLEAN DEFAULT false
);

-- ── companies ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS companies (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id        UUID REFERENCES tenants(id) ON DELETE CASCADE,
  bc_company_id    VARCHAR(255) NOT NULL,
  name             VARCHAR(255) NOT NULL,
  bc_web_service_url VARCHAR(500),
  is_active        BOOLEAN DEFAULT true,
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW()
);

-- ── resources ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS resources (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id         UUID REFERENCES tenants(id) ON DELETE CASCADE,
  company_id        UUID REFERENCES companies(id) ON DELETE CASCADE,
  resource_no       VARCHAR(50) NOT NULL,
  display_name      VARCHAR(255) NOT NULL,
  web_username      VARCHAR(255),
  web_password_hash VARCHAR(255),
  permissions       JSONB DEFAULT '{}',
  is_active         BOOLEAN DEFAULT true,
  created_at        TIMESTAMPTZ DEFAULT NOW(),
  updated_at        TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, company_id, resource_no)
);

-- ── jobs ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS jobs (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id   UUID REFERENCES tenants(id) ON DELETE CASCADE,
  company_id  UUID REFERENCES companies(id) ON DELETE CASCADE,
  bc_job_id   VARCHAR(50) NOT NULL,
  name        VARCHAR(255) NOT NULL,
  description TEXT,
  status      VARCHAR(50) DEFAULT 'active',
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, company_id, bc_job_id)
);

-- ── job_tasks ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS job_tasks (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id   UUID REFERENCES tenants(id) ON DELETE CASCADE,
  company_id  UUID REFERENCES companies(id) ON DELETE CASCADE,
  job_id      UUID REFERENCES jobs(id) ON DELETE CASCADE,
  bc_task_id  VARCHAR(50) NOT NULL,
  description VARCHAR(255) NOT NULL,
  status      VARCHAR(50) DEFAULT 'active',
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, company_id, job_id, bc_task_id)
);

-- ── time_entries ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS time_entries (
  id                       UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id                UUID REFERENCES tenants(id) ON DELETE CASCADE,
  company_id               UUID REFERENCES companies(id) ON DELETE CASCADE,
  resource_id              UUID REFERENCES resources(id) ON DELETE SET NULL,
  job_id                   UUID REFERENCES jobs(id) ON DELETE SET NULL,
  task_id                  UUID REFERENCES job_tasks(id) ON DELETE SET NULL,
  -- Identificadores directos de BC (varchar, sin FK local)
  resource_no              VARCHAR(50),
  bc_job_id                VARCHAR(50),
  bc_task_id               VARCHAR(50),
  -- Datos de la entrada
  date                     DATE NOT NULL,
  hours                    NUMERIC NOT NULL,
  description              TEXT NOT NULL,
  start_time               TIME,
  end_time                 TIME,
  -- Estado de sincronización con BC
  bc_synced                BOOLEAN DEFAULT false,
  bc_sync_status           VARCHAR(20) DEFAULT 'not_synced',
  bc_entry_id              VARCHAR(255),
  bc_journal_id            VARCHAR(100),
  bc_last_sync_at          TIMESTAMPTZ,
  -- Edición y flujo
  is_editable              BOOLEAN DEFAULT true,
  -- Timestamps
  created_at               TIMESTAMPTZ DEFAULT NOW(),
  updated_at               TIMESTAMPTZ DEFAULT NOW(),
  last_modified_at         TIMESTAMPTZ DEFAULT NOW()
);

-- ── bc_sync_batches ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bc_sync_batches (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id     UUID REFERENCES tenants(id) ON DELETE CASCADE,
  company_id    UUID REFERENCES companies(id) ON DELETE CASCADE,
  batch_name    VARCHAR(50) NOT NULL,
  status        VARCHAR(20) DEFAULT 'draft',
  entries_count INT DEFAULT 0,
  total_hours   DECIMAL(10,2) DEFAULT 0,
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ── Columnas extra en time_entries (para tablas pre-existentes) ─
-- Si la tabla ya existía sin estas columnas, las añadimos de forma idempotente.
ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS resource_no        VARCHAR(50);
ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS bc_job_id          VARCHAR(50);
ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS bc_task_id         VARCHAR(50);
ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS bc_sync_status     VARCHAR(20) DEFAULT 'not_synced';
ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS bc_journal_id      VARCHAR(100);
ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS bc_last_sync_at    TIMESTAMPTZ;
ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS is_editable        BOOLEAN DEFAULT true;
ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS last_modified_at   TIMESTAMPTZ DEFAULT NOW();

-- ── Índices básicos ──────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_companies_tenant_id      ON companies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_resources_tenant_company ON resources(tenant_id, company_id);
CREATE INDEX IF NOT EXISTS idx_jobs_tenant_company      ON jobs(tenant_id, company_id);
CREATE INDEX IF NOT EXISTS idx_job_tasks_job_id         ON job_tasks(job_id);
CREATE INDEX IF NOT EXISTS idx_time_entries_resource    ON time_entries(resource_id);
CREATE INDEX IF NOT EXISTS idx_time_entries_date        ON time_entries(date);
CREATE INDEX IF NOT EXISTS idx_time_entries_company     ON time_entries(company_id);
CREATE INDEX IF NOT EXISTS idx_bc_sync_batches_company  ON bc_sync_batches(company_id);
