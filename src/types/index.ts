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