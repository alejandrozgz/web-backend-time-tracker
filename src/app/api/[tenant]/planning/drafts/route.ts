import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { BusinessCentralClient } from '@/lib/bc-api';
import { requirePMRole } from '@/lib/planning-auth';
import { logger } from '@/lib/logger';

function corsHeaders() {
  return { 'Access-Control-Allow-Origin': '*' };
}

// GET /api/[tenant]/planning/drafts?companyId=...&status=...
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  try {
    const payload = requirePMRole(request);
    const { tenant: tenantSlug } = await params;
    const { searchParams } = new URL(request.url);
    const companyId = searchParams.get('companyId') || payload.companyId;
    const statusFilter = searchParams.get('status');

    let query = supabaseAdmin
      .from('planning_drafts')
      .select('*')
      .eq('company_id', companyId)
      .order('created_at', { ascending: false });

    if (statusFilter) query = query.eq('status', statusFilter);

    const { data: drafts, error } = await query;
    if (error) throw error;

    return NextResponse.json({ drafts: drafts || [] }, { headers: corsHeaders() });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    if (msg === 'UNAUTHORIZED') return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders() });
    if (msg === 'FORBIDDEN')    return NextResponse.json({ error: 'PM role required' }, { status: 403, headers: corsHeaders() });
    logger.error('GET planning/drafts failed', { error: msg });
    return NextResponse.json({ error: msg }, { status: 500, headers: corsHeaders() });
  }
}

// POST /api/[tenant]/planning/drafts
// Creates draft, fetches BC baseline, populates planning_entries from baseline
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  try {
    const payload = requirePMRole(request);
    const { tenant: tenantSlug } = await params;
    const body = await request.json();
    const { companyId, name, dateFrom, dateTo, resourceNos, notes } = body;

    if (!companyId || !name || !dateFrom || !dateTo) {
      return NextResponse.json({ error: 'companyId, name, dateFrom, dateTo required' }, { status: 400, headers: corsHeaders() });
    }

    // Fetch tenant and company
    const [tenantResult, companyResult] = await Promise.all([
      supabaseAdmin.from('tenants').select('*').eq('slug', tenantSlug).single(),
      supabaseAdmin.from('companies').select('*').eq('id', companyId).single()
    ]);
    if (tenantResult.error || !tenantResult.data) throw new Error('Tenant not found');
    if (companyResult.error || !companyResult.data) throw new Error('Company not found');

    const tenant = tenantResult.data;
    const company = companyResult.data;

    // Create draft record
    const { data: draft, error: draftError } = await supabaseAdmin
      .from('planning_drafts')
      .insert({
        tenant_id: tenant.id,
        company_id: companyId,
        created_by_resource: payload.resourceNo,
        name,
        date_from: dateFrom,
        date_to: dateTo,
        status: 'draft',
        notes: notes || null,
        bc_baseline_fetched_at: null
      })
      .select()
      .single();

    if (draftError || !draft) throw new Error(draftError?.message || 'Failed to create draft');

    // Fetch BC planning lines as baseline
    let baselineCount = 0;
    if (tenant.oauth_enabled) {
      try {
        const bcClient = new BusinessCentralClient(tenant, company);
        const bcLines = await bcClient.getJobPlanningLines({
          dateFrom,
          dateTo,
          resourceNo: resourceNos?.length === 1 ? resourceNos[0] : undefined
        });

        // Filter by resourceNos if provided
        const filteredLines = resourceNos?.length > 1
          ? bcLines.filter((l: any) => resourceNos.includes(l.no))
          : bcLines;

        if (filteredLines.length > 0) {
          // Insert baseline snapshot
          const baselineRows = filteredLines.map((l: any) => ({
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

          // Pre-populate planning_entries from baseline (PM starts from current BC plan)
          const entryRows = filteredLines.map((l: any) => ({
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
          baselineCount = filteredLines.length;
        }

        // Mark baseline as fetched
        await supabaseAdmin
          .from('planning_drafts')
          .update({ bc_baseline_fetched_at: new Date().toISOString() })
          .eq('id', draft.id);

      } catch (bcError) {
        logger.warn('Could not fetch BC baseline for draft', { draftId: draft.id, error: bcError });
      }
    }

    logger.info('Planning draft created', { draftId: draft.id, baselineCount, createdBy: payload.resourceNo });

    return NextResponse.json(
      { draft, baselineLinesCount: baselineCount },
      { status: 201, headers: corsHeaders() }
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    if (msg === 'UNAUTHORIZED') return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders() });
    if (msg === 'FORBIDDEN')    return NextResponse.json({ error: 'PM role required' }, { status: 403, headers: corsHeaders() });
    logger.error('POST planning/drafts failed', { error: msg });
    return NextResponse.json({ error: msg }, { status: 500, headers: corsHeaders() });
  }
}

export async function OPTIONS() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}
