import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { requirePMRole } from '@/lib/planning-auth';
import { DiffLine, DiffLineStatus } from '@/types';
import { logger } from '@/lib/logger';

function corsHeaders() {
  return { 'Access-Control-Allow-Origin': '*' };
}

function buildKey(resourceNo: string, bcJobId: string, bcTaskId: string, date: string) {
  return `${resourceNo}|${bcJobId}|${bcTaskId}|${date}`;
}

// GET /api/[tenant]/planning/drafts/[draftId]/diff
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string; draftId: string }> }
) {
  try {
    requirePMRole(request);
    const { draftId } = await params;
    const { searchParams } = new URL(request.url);
    const resourceNo = searchParams.get('resourceNo');

    // Fetch draft
    const { data: draft, error: draftError } = await supabaseAdmin
      .from('planning_drafts')
      .select('*')
      .eq('id', draftId)
      .single();

    if (draftError || !draft) return NextResponse.json({ error: 'Draft not found' }, { status: 404, headers: corsHeaders() });

    // Fetch baseline and local entries in parallel
    let baselineQuery = supabaseAdmin.from('planning_baseline_lines').select('*').eq('draft_id', draftId);
    let entriesQuery  = supabaseAdmin.from('planning_entries').select('*').eq('draft_id', draftId);
    if (resourceNo) {
      baselineQuery = baselineQuery.eq('resource_no', resourceNo);
      entriesQuery  = entriesQuery.eq('resource_no', resourceNo);
    }

    const [baselineResult, entriesResult] = await Promise.all([baselineQuery, entriesQuery]);
    if (baselineResult.error) throw baselineResult.error;
    if (entriesResult.error)  throw entriesResult.error;

    const baseline = baselineResult.data || [];
    const entries  = entriesResult.data || [];

    // Build lookup maps
    const baselineMap = new Map(baseline.map((b: any) => [
      buildKey(b.resource_no, b.bc_job_id, b.bc_task_id, b.planning_date), b
    ]));
    const entriesMap = new Map(entries.map((e: any) => [
      buildKey(e.resource_no, e.bc_job_id, e.bc_task_id, e.planning_date), e
    ]));

    // Load display names
    const [jobsResult, tasksResult, resourcesResult] = await Promise.all([
      supabaseAdmin.from('jobs').select('bc_job_id, name').eq('company_id', draft.company_id),
      supabaseAdmin.from('job_tasks').select('bc_task_id, description').eq('company_id', draft.company_id),
      supabaseAdmin.from('resources').select('resource_no, display_name').eq('company_id', draft.company_id)
    ]);
    const jobMap      = new Map((jobsResult.data || []).map((j: any) => [j.bc_job_id, j.name]));
    const taskMap     = new Map((tasksResult.data || []).map((t: any) => [t.bc_task_id, t.description]));
    const resourceMap = new Map((resourcesResult.data || []).map((r: any) => [r.resource_no, r.display_name]));

    const diff: DiffLine[] = [];
    const summary = { new: 0, modified: 0, deleted: 0, unchanged: 0 };

    // Check local entries against baseline
    for (const [key, entry] of entriesMap) {
      const base = baselineMap.get(key);
      const planned = parseFloat(entry.planned_hours);

      if (!base) {
        if (planned > 0) {
          diff.push({
            status: 'new',
            resource_no: entry.resource_no,
            bc_job_id: entry.bc_job_id,
            bc_task_id: entry.bc_task_id,
            planning_date: entry.planning_date,
            planned_hours: planned,
            delta: planned,
            job_name: jobMap.get(entry.bc_job_id),
            task_description: taskMap.get(entry.bc_task_id),
            resource_display_name: resourceMap.get(entry.resource_no)
          });
          summary.new++;
        }
      } else {
        const baseQty = parseFloat(base.quantity);
        const delta = planned - baseQty;
        if (Math.abs(delta) >= 0.01) {
          diff.push({
            status: 'modified',
            resource_no: entry.resource_no,
            bc_job_id: entry.bc_job_id,
            bc_task_id: entry.bc_task_id,
            planning_date: entry.planning_date,
            baseline_hours: baseQty,
            planned_hours: planned,
            delta,
            bc_line_no: base.bc_line_no,
            bc_etag: base.bc_etag,
            job_name: jobMap.get(entry.bc_job_id),
            task_description: taskMap.get(entry.bc_task_id),
            resource_display_name: resourceMap.get(entry.resource_no)
          });
          summary.modified++;
        } else {
          summary.unchanged++;
        }
      }
    }

    // Check baseline lines that are NOT in local entries (deleted)
    for (const [key, base] of baselineMap) {
      if (!entriesMap.has(key)) {
        const baseQty = parseFloat(base.quantity);
        diff.push({
          status: 'deleted',
          resource_no: base.resource_no,
          bc_job_id: base.bc_job_id,
          bc_task_id: base.bc_task_id,
          planning_date: base.planning_date,
          baseline_hours: baseQty,
          delta: -baseQty,
          bc_line_no: base.bc_line_no,
          bc_etag: base.bc_etag,
          job_name: jobMap.get(base.bc_job_id),
          task_description: taskMap.get(base.bc_task_id),
          resource_display_name: resourceMap.get(base.resource_no)
        });
        summary.deleted++;
      }
    }

    // Sort: new → modified → deleted → unchanged, then by date
    const order: Record<DiffLineStatus, number> = { new: 0, modified: 1, deleted: 2, unchanged: 3 };
    diff.sort((a, b) => {
      const statusDiff = order[a.status] - order[b.status];
      if (statusDiff !== 0) return statusDiff;
      return a.planning_date.localeCompare(b.planning_date);
    });

    return NextResponse.json({ diff, summary }, { headers: corsHeaders() });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    if (msg === 'UNAUTHORIZED') return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders() });
    if (msg === 'FORBIDDEN')    return NextResponse.json({ error: 'PM role required' }, { status: 403, headers: corsHeaders() });
    logger.error('GET planning diff failed', { error: msg });
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
