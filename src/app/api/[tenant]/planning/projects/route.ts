import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { requirePMRole } from '@/lib/planning-auth';
import { logger } from '@/lib/logger';

function corsHeaders() {
  return { 'Access-Control-Allow-Origin': '*' };
}

// GET /api/[tenant]/planning/projects?companyId=...
// Returns all jobs, tasks, and active resources for the company (PM view — no resource filter)
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  try {
    requirePMRole(request);
    const { searchParams } = new URL(request.url);
    const companyId = searchParams.get('companyId');

    if (!companyId) {
      return NextResponse.json({ error: 'companyId required' }, { status: 400, headers: corsHeaders() });
    }

    const [jobsResult, tasksResult, resourcesResult] = await Promise.all([
      supabaseAdmin
        .from('jobs')
        .select('id, bc_job_id, name, description, status')
        .eq('company_id', companyId)
        .eq('status', 'active')
        .order('name'),
      supabaseAdmin
        .from('job_tasks')
        .select('id, bc_task_id, job_id, description, status')
        .eq('company_id', companyId)
        .order('description'),
      supabaseAdmin
        .from('resources')
        .select('resource_no, display_name, daily_capacity_hours')
        .eq('company_id', companyId)
        .eq('is_active', true)
        .order('display_name')
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
