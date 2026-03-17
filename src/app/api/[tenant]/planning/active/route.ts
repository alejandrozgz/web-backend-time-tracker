import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { BusinessCentralClient } from '@/lib/bc-api';
import { requirePMRole } from '@/lib/planning-auth';
import { logger } from '@/lib/logger';

function corsHeaders() {
  return { 'Access-Control-Allow-Origin': '*' };
}

// GET /api/[tenant]/planning/active?companyId=...
// Returns the active (non-published) draft for this company.
// Auto-creates one if none exists, fetching BC baseline on creation.
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  try {
    const payload = requirePMRole(request);
    const { tenant: tenantSlug } = await params;
    const { searchParams } = new URL(request.url);
    const companyId = searchParams.get('companyId') || payload.companyId;

    if (!companyId) {
      return NextResponse.json({ error: 'companyId required' }, { status: 400, headers: corsHeaders() });
    }

    // Find existing active draft
    const { data: existing, error: findError } = await supabaseAdmin
      .from('planning_drafts')
      .select('*')
      .eq('company_id', companyId)
      .neq('status', 'published')
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (findError) throw findError;

    if (existing) {
      return NextResponse.json({ draft: existing }, { headers: corsHeaders() });
    }

    // No active draft — auto-create one
    const [tenantResult, companyResult] = await Promise.all([
      supabaseAdmin.from('tenants').select('*').eq('slug', tenantSlug).single(),
      supabaseAdmin.from('companies').select('*').eq('id', companyId).single()
    ]);
    if (tenantResult.error || !tenantResult.data) throw new Error('Tenant not found');
    if (companyResult.error || !companyResult.data) throw new Error('Company not found');

    const tenant = tenantResult.data;
    const company = companyResult.data;

    // Wide date range: today → 1 year from now
    const today = new Date().toISOString().slice(0, 10);
    const oneYearLater = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

    const { data: draft, error: createError } = await supabaseAdmin
      .from('planning_drafts')
      .insert({
        tenant_id: tenant.id,
        company_id: companyId,
        created_by_resource: payload.resourceNo,
        name: 'Plan de Recursos',
        date_from: today,
        date_to: oneYearLater,
        status: 'draft',
        bc_baseline_fetched_at: null
      })
      .select()
      .single();

    if (createError || !draft) throw new Error(createError?.message || 'Failed to create draft');

    // Fetch BC baseline to pre-populate planning_entries
    if (tenant.oauth_enabled) {
      try {
        const bcClient = new BusinessCentralClient(tenant, company);
        const bcLines = await bcClient.getJobPlanningLines({ dateFrom: today, dateTo: oneYearLater });

        if (bcLines.length > 0) {
          const baselineRows = bcLines.map((l: any) => ({
            draft_id: draft.id,
            tenant_id: tenant.id,
            company_id: companyId,
            resource_no: l.no,
            bc_job_id: l.jobNo,
            bc_task_id: l.jobTaskNo,
            planning_date: l.planningDate,
            quantity: parseFloat(l.quantity) || 0,
            description: l.description || null,
            bc_line_no: l.lineNo,
            bc_system_id: l.systemId || null,
            bc_etag: l['@odata.etag'] || null
          }));

          await supabaseAdmin.from('planning_baseline_lines').insert(baselineRows);

          const entryRows = bcLines.map((l: any) => ({
            draft_id: draft.id,
            tenant_id: tenant.id,
            company_id: companyId,
            resource_no: l.no,
            bc_job_id: l.jobNo,
            bc_task_id: l.jobTaskNo,
            planning_date: l.planningDate,
            planned_hours: parseFloat(l.quantity) || 0,
            description: l.description || null,
            publish_status: 'unchanged'
          }));

          await supabaseAdmin.from('planning_entries').insert(entryRows);

          await supabaseAdmin
            .from('planning_drafts')
            .update({ bc_baseline_fetched_at: new Date().toISOString() })
            .eq('id', draft.id);
        }

        logger.info('Active draft auto-created with BC baseline', { draftId: draft.id, lines: bcLines.length });
      } catch (bcError) {
        logger.warn('Could not fetch BC baseline for auto-created draft', { draftId: draft.id, error: bcError });
      }
    }

    return NextResponse.json({ draft }, { status: 201, headers: corsHeaders() });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    if (msg === 'UNAUTHORIZED') return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders() });
    if (msg === 'FORBIDDEN')    return NextResponse.json({ error: 'PM role required' }, { status: 403, headers: corsHeaders() });
    logger.error('GET planning/active failed', { error: msg });
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
