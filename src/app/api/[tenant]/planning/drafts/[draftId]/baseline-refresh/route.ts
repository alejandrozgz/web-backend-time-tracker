import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { BusinessCentralClient } from '@/lib/bc-api';
import { requirePMRole } from '@/lib/planning-auth';
import { logger } from '@/lib/logger';

function corsHeaders() {
  return { 'Access-Control-Allow-Origin': '*' };
}

// POST /api/[tenant]/planning/drafts/[draftId]/baseline-refresh
// Re-fetches BC jobPlanningLines and updates planning_baseline_lines.
// Does NOT overwrite planning_entries (preserves PM edits).
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string; draftId: string }> }
) {
  try {
    requirePMRole(request);
    const { tenant: tenantSlug, draftId } = await params;
    const body = await request.json();
    const { companyId } = body;

    // Fetch draft
    const { data: draft, error: draftError } = await supabaseAdmin
      .from('planning_drafts')
      .select('*')
      .eq('id', draftId)
      .single();

    if (draftError || !draft) return NextResponse.json({ error: 'Draft not found' }, { status: 404, headers: corsHeaders() });
    if (draft.status === 'published') return NextResponse.json({ error: 'Draft already published' }, { status: 400, headers: corsHeaders() });

    const effectiveCompanyId = companyId || draft.company_id;

    const [tenantResult, companyResult] = await Promise.all([
      supabaseAdmin.from('tenants').select('*').eq('slug', tenantSlug).single(),
      supabaseAdmin.from('companies').select('*').eq('id', effectiveCompanyId).single()
    ]);
    if (tenantResult.error || !tenantResult.data) throw new Error('Tenant not found');
    if (companyResult.error || !companyResult.data) throw new Error('Company not found');

    const tenant = tenantResult.data;
    const company = companyResult.data;

    if (!tenant.oauth_enabled) {
      return NextResponse.json({ error: 'BC integration not enabled for this tenant' }, { status: 400, headers: corsHeaders() });
    }

    const bcClient = new BusinessCentralClient(tenant, company);
    const bcLines = await bcClient.getJobPlanningLines({
      dateFrom: draft.date_from,
      dateTo: draft.date_to
    });

    // Delete old baseline for this draft and re-insert
    await supabaseAdmin.from('planning_baseline_lines').delete().eq('draft_id', draftId);

    const fetchedAt = new Date().toISOString();

    if (bcLines.length > 0) {
      const rows = bcLines.map((l: any) => ({
        draft_id: draftId,
        tenant_id: draft.tenant_id,
        company_id: draft.company_id,
        resource_no: l.no,
        bc_job_id: l.jobNo,
        bc_task_id: l.jobTaskNo,
        planning_date: l.planningDate,
        quantity: parseFloat(l.quantity) || 0,
        description: l.description || null,
        bc_line_no: l.lineNo,
        bc_system_id: l.systemId || null,
        bc_etag: l['@odata.etag'] || null,
        fetched_at: fetchedAt
      }));
      await supabaseAdmin.from('planning_baseline_lines').insert(rows);
    }

    // Update draft's baseline timestamp
    await supabaseAdmin
      .from('planning_drafts')
      .update({ bc_baseline_fetched_at: fetchedAt, updated_at: fetchedAt })
      .eq('id', draftId);

    logger.info('Planning baseline refreshed', { draftId, linesRefreshed: bcLines.length });

    return NextResponse.json(
      { linesRefreshed: bcLines.length, fetchedAt },
      { headers: corsHeaders() }
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    if (msg === 'UNAUTHORIZED') return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders() });
    if (msg === 'FORBIDDEN')    return NextResponse.json({ error: 'PM role required' }, { status: 403, headers: corsHeaders() });
    logger.error('baseline-refresh failed', { error: msg });
    return NextResponse.json({ error: msg }, { status: 500, headers: corsHeaders() });
  }
}

export async function OPTIONS() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}
