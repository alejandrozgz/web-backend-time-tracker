import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { BusinessCentralClient } from '@/lib/bc-api';
import { requirePMRole } from '@/lib/planning-auth';
import { logger } from '@/lib/logger';

function corsHeaders() {
  return { 'Access-Control-Allow-Origin': '*' };
}

// GET /api/[tenant]/planning/projects?companyId=...
// Returns all jobs, tasks, and active resources for the company (PM view)
// Fetches from BC when OAuth enabled, falls back to Supabase
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  try {
    const payload = requirePMRole(request);
    const { searchParams } = new URL(request.url);
    const companyId = searchParams.get('companyId');
    const pmResourceNo = payload.resourceNo;
    const { tenant: tenantSlug } = await params;

    if (!companyId) {
      return NextResponse.json({ error: 'companyId required' }, { status: 400, headers: corsHeaders() });
    }

    const { data: tenant, error: tenantError } = await supabaseAdmin
      .from('tenants')
      .select('*')
      .eq('slug', tenantSlug)
      .single();

    if (tenantError || !tenant) {
      return NextResponse.json({ error: 'Tenant not found' }, { status: 404, headers: corsHeaders() });
    }

    const { data: company, error: companyError } = await supabaseAdmin
      .from('companies')
      .select('*')
      .eq('id', companyId)
      .eq('tenant_id', tenant.id)
      .single();

    if (companyError || !company) {
      return NextResponse.json({ error: 'Company not found' }, { status: 404, headers: corsHeaders() });
    }

    // Try BC first when OAuth is configured
    if (tenant.oauth_enabled && tenant.bc_client_id && tenant.bc_client_secret && tenant.bc_tenant_id) {
      try {
        const bcClient = new BusinessCentralClient(tenant, company);
        const [{ jobs: bcJobs, tasks: bcTasks }, bcResources] = await Promise.all([
          bcClient.getAllJobsAndTasks(pmResourceNo),
          bcClient.getAllResources()
        ]);

        const jobs = bcJobs.map((j: any) => ({
          id: j.systemId || j.id,
          bc_job_id: j.no || j.number,
          name: j.description || j.name || j.no,
          description: j.description
        }));

        const tasks = bcTasks.map((t: any) => ({
          id: t.systemId || t.id,
          job_id: jobs.find((j: any) => j.bc_job_id === (t.jobNo || t.jobNumber))?.id,
          bc_task_id: t.jobTaskNo || t.taskNo,
          description: t.description || t.jobTaskNo
        })).filter((t: any) => t.job_id);

        const resources = bcResources.map((r: any) => ({
          resource_no: r.resourceNo,
          display_name: r.displayName,
          daily_capacity_hours: 8
        }));

        logger.info('GET planning projects from BC', { tenantSlug, jobs: jobs.length, tasks: tasks.length, resources: resources.length });

        return NextResponse.json({ jobs, tasks, resources }, { headers: corsHeaders() });
      } catch (bcError) {
        logger.warn('BC fetch failed for planning projects, falling back to Supabase', { error: bcError instanceof Error ? bcError.message : bcError });
      }
    }

    // Fallback: Supabase
    const [jobsResult, tasksResult, resourcesResult] = await Promise.all([
      supabaseAdmin.from('jobs').select('id, bc_job_id, name, description, status').eq('company_id', companyId).eq('status', 'active').order('name'),
      supabaseAdmin.from('job_tasks').select('id, bc_task_id, job_id, description, status').eq('company_id', companyId).order('description'),
      supabaseAdmin.from('resources').select('resource_no, display_name, daily_capacity_hours').eq('company_id', companyId).eq('is_active', true).order('display_name')
    ]);

    if (jobsResult.error) throw jobsResult.error;
    if (tasksResult.error) throw tasksResult.error;
    if (resourcesResult.error) throw resourcesResult.error;

    return NextResponse.json({
      jobs: jobsResult.data || [],
      tasks: tasksResult.data || [],
      resources: resourcesResult.data || []
    }, { headers: corsHeaders() });

  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    if (msg === 'UNAUTHORIZED') return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders() });
    if (msg === 'FORBIDDEN')    return NextResponse.json({ error: 'PM role required' }, { status: 403, headers: corsHeaders() });
    logger.error('GET planning projects failed', { error: msg });
    return NextResponse.json({ error: msg }, { status: 500, headers: corsHeaders() });
  }
}

export async function OPTIONS() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}
