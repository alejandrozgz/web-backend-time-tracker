import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { requirePMRole } from '@/lib/planning-auth';
import { logger } from '@/lib/logger';

function corsHeaders() {
  return { 'Access-Control-Allow-Origin': '*' };
}

// GET /api/[tenant]/planning/drafts/[draftId]/lines?companyId=...&resourceNo=...
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string; draftId: string }> }
) {
  try {
    requirePMRole(request);
    const { draftId } = await params;
    const { searchParams } = new URL(request.url);
    const resourceNo = searchParams.get('resourceNo');

    // Get the draft first
    const { data: draft, error: draftError } = await supabaseAdmin
      .from('planning_drafts')
      .select('*')
      .eq('id', draftId)
      .single();

    if (draftError || !draft) return NextResponse.json({ error: 'Draft not found' }, { status: 404, headers: corsHeaders() });

    // Get planning entries
    let query = supabaseAdmin
      .from('planning_entries')
      .select('*')
      .eq('draft_id', draftId)
      .order('resource_no')
      .order('bc_job_id')
      .order('bc_task_id')
      .order('planning_date');

    if (resourceNo) query = query.eq('resource_no', resourceNo);

    const { data: entries, error: entriesError } = await query;
    if (entriesError) throw entriesError;

    // Join job/task names from local cache
    const bcJobIds = [...new Set((entries || []).map((e: any) => e.bc_job_id))];
    const bcTaskIds = [...new Set((entries || []).map((e: any) => e.bc_task_id))];

    const [jobsResult, tasksResult, resourcesResult] = await Promise.all([
      bcJobIds.length > 0
        ? supabaseAdmin.from('jobs').select('bc_job_id, name').in('bc_job_id', bcJobIds).eq('company_id', draft.company_id)
        : { data: [] },
      bcTaskIds.length > 0
        ? supabaseAdmin.from('job_tasks').select('bc_task_id, description').in('bc_task_id', bcTaskIds).eq('company_id', draft.company_id)
        : { data: [] },
      supabaseAdmin.from('resources').select('resource_no, display_name').eq('company_id', draft.company_id)
    ]);

    const jobMap = new Map((jobsResult.data || []).map((j: any) => [j.bc_job_id, j.name]));
    const taskMap = new Map((tasksResult.data || []).map((t: any) => [t.bc_task_id, t.description]));
    const resourceMap = new Map((resourcesResult.data || []).map((r: any) => [r.resource_no, r.display_name]));

    const enrichedEntries = (entries || []).map((e: any) => ({
      ...e,
      job_name: jobMap.get(e.bc_job_id) || e.bc_job_id,
      task_description: taskMap.get(e.bc_task_id) || e.bc_task_id,
      resource_display_name: resourceMap.get(e.resource_no) || e.resource_no
    }));

    return NextResponse.json({ entries: enrichedEntries, draft }, { headers: corsHeaders() });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    if (msg === 'UNAUTHORIZED') return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders() });
    if (msg === 'FORBIDDEN')    return NextResponse.json({ error: 'PM role required' }, { status: 403, headers: corsHeaders() });
    logger.error('GET planning lines failed', { error: msg });
    return NextResponse.json({ error: msg }, { status: 500, headers: corsHeaders() });
  }
}

// PATCH /api/[tenant]/planning/drafts/[draftId]/lines — bulk upsert
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string; draftId: string }> }
) {
  try {
    const payload = requirePMRole(request);
    const { draftId } = await params;
    const body = await request.json();
    const { companyId, entries } = body;

    if (!entries || !Array.isArray(entries)) {
      return NextResponse.json({ error: 'entries array required' }, { status: 400, headers: corsHeaders() });
    }

    // Verify draft exists and is not published/locked
    const { data: draft, error: draftError } = await supabaseAdmin
      .from('planning_drafts')
      .select('id, status, tenant_id, company_id')
      .eq('id', draftId)
      .single();

    if (draftError || !draft) return NextResponse.json({ error: 'Draft not found' }, { status: 404, headers: corsHeaders() });
    if (['published', 'publishing'].includes(draft.status)) {
      return NextResponse.json({ error: 'Cannot edit a published draft' }, { status: 400, headers: corsHeaders() });
    }

    let created = 0, updated = 0, failed = 0;
    const errors: any[] = [];

    for (const entry of entries) {
      const { resourceNo, bcJobId, bcTaskId, planningDate, plannedHours, description } = entry;
      if (!resourceNo || !bcJobId || !bcTaskId || !planningDate) {
        failed++;
        errors.push({ entry, error: 'Missing required fields' });
        continue;
      }

      try {
        const { data: existing } = await supabaseAdmin
          .from('planning_entries')
          .select('id')
          .eq('draft_id', draftId)
          .eq('resource_no', resourceNo)
          .eq('bc_job_id', bcJobId)
          .eq('bc_task_id', bcTaskId)
          .eq('planning_date', planningDate)
          .single();

        const row = {
          draft_id: draftId,
          tenant_id: draft.tenant_id,
          company_id: draft.company_id,
          resource_no: resourceNo,
          bc_job_id: bcJobId,
          bc_task_id: bcTaskId,
          planning_date: planningDate,
          planned_hours: plannedHours,
          description: description || null,
          publish_status: 'pending',
          updated_at: new Date().toISOString()
        };

        if (existing) {
          await supabaseAdmin.from('planning_entries').update(row).eq('id', existing.id);
          updated++;
        } else {
          await supabaseAdmin.from('planning_entries').insert(row);
          created++;
        }
      } catch (rowError) {
        failed++;
        errors.push({ entry, error: rowError instanceof Error ? rowError.message : 'Unknown' });
      }
    }

    logger.info('Planning entries bulk saved', { draftId, created, updated, failed });

    return NextResponse.json(
      { created, updated, failed, errors: errors.length > 0 ? errors : undefined },
      { headers: corsHeaders() }
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    if (msg === 'UNAUTHORIZED') return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders() });
    if (msg === 'FORBIDDEN')    return NextResponse.json({ error: 'PM role required' }, { status: 403, headers: corsHeaders() });
    logger.error('PATCH planning lines failed', { error: msg });
    return NextResponse.json({ error: msg }, { status: 500, headers: corsHeaders() });
  }
}

export async function OPTIONS() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, PATCH, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}
