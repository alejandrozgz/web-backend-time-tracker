export interface Tenant {
  id: string;
  slug: string;
  name: string;
  bc_base_url: string;
  bc_environment: string;
  bc_tenant_id?: string;      // Azure AD Tenant ID
  bc_client_id?: string;      // OAuth Client ID
  bc_client_secret?: string;  // OAuth Client Secret
  oauth_enabled: boolean;     // OAuth habilitado para este tenant
  settings: Record<string, any>;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface Company {
  id: string;
  tenant_id: string;
  bc_company_id: string;
  name: string;
  bc_web_service_url?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface Resource {
  id: string;
  tenant_id: string;
  company_id: string;
  resource_no: string;
  display_name: string;
  web_username?: string;
  bc_journal_batch?: string;
  permissions: Record<string, any>;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface Job {
  id: string;
  tenant_id: string;
  company_id: string;
  bc_job_id: string;
  name: string;
  description?: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface JobTask {
  id: string;
  tenant_id: string;
  company_id: string;
  job_id: string;
  bc_task_id: string;
  description: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface TimeEntry {
  id: string;
  tenant_id: string;
  company_id: string;
  resource_id: string;
  job_id: string;
  task_id: string;
  date: string;
  hours: number;
  description: string;
  start_time?: string;
  end_time?: string;
  bc_synced: boolean;
  bc_entry_id?: string;
  created_at: string;
  updated_at: string;
}

// ============================================================
// PLANNING MODULE TYPES
// ============================================================

export type PlanningDraftStatus = 'draft' | 'locked' | 'publishing' | 'published' | 'error';
export type PublishLineStatus = 'pending' | 'created' | 'updated' | 'deleted' | 'unchanged' | 'error';
export type DiffLineStatus = 'new' | 'modified' | 'deleted' | 'unchanged';
export type UserRole = 'resource' | 'pm';

export interface PlanningDraft {
  id: string;
  tenant_id: string;
  company_id: string;
  created_by_resource: string;
  name: string;
  date_from: string;
  date_to: string;
  status: PlanningDraftStatus;
  bc_baseline_fetched_at?: string;
  published_at?: string;
  publish_summary?: PublishSummary;
  notes?: string;
  created_at: string;
  updated_at: string;
}

export interface PlanningEntry {
  id: string;
  draft_id: string;
  tenant_id: string;
  company_id: string;
  resource_no: string;
  bc_job_id: string;
  bc_task_id: string;
  planning_date: string;
  planned_hours: number;
  description?: string;
  publish_status: PublishLineStatus;
  bc_line_no?: number;
  bc_system_id?: string;
  bc_etag?: string;
  publish_error?: string;
  created_at: string;
  updated_at: string;
}

export interface PlanningBaselineLine {
  id: string;
  draft_id: string;
  tenant_id: string;
  company_id: string;
  resource_no: string;
  bc_job_id: string;
  bc_task_id: string;
  planning_date: string;
  quantity: number;
  description?: string;
  bc_line_no: number;
  bc_system_id?: string;
  bc_etag?: string;
  fetched_at: string;
}

export interface DiffLine {
  status: DiffLineStatus;
  resource_no: string;
  bc_job_id: string;
  bc_task_id: string;
  planning_date: string;
  baseline_hours?: number;
  planned_hours?: number;
  delta: number;
  bc_line_no?: number;
  bc_etag?: string;
  // Joined display fields
  job_name?: string;
  task_description?: string;
  resource_display_name?: string;
}

export interface PublishSummary {
  created: number;
  updated: number;
  deleted: number;
  unchanged: number;
  failed: number;
  errors: Array<{ line: DiffLine; error: string }>;
}

export interface CapacityDay {
  date: string;
  planned_hours: number;
  actual_hours: number;
  capacity_hours: number;
  is_overloaded: boolean;
}

export interface CapacityRow {
  resource_no: string;
  display_name: string;
  daily_capacity_hours: number;
  days: CapacityDay[];
  total_planned: number;
  total_actual: number;
  total_capacity: number;
}