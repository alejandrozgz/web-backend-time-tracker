import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { BusinessCentralClient } from '@/lib/bc-api';
import { requirePMRole } from '@/lib/planning-auth';
import { DiffLine, PublishSummary } from '@/types';
import { logger } from '@/lib/logger';

function corsHeaders() {
  return { 'Access-Control-Allow-Origin': '*' };
}

function buildKey(resourceNo: string, bcJobId: string, bcTaskId: string, date: string) {
  return `${resourceNo}|${bcJobId}|${bcTaskId}|${date}`;
}

// POST /api/[tenant]/planning/drafts/[draftId]/publish
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string; draftId: string }> }
) {
  const startTime = Date.now();
  try {
    requirePMRole(request);
    const { tenant: tenantSlug, draftId } = await params;
    const body = await request.json();
    const { companyId, dryRun } = body;

    // Fetch draft
    const { data: draft, error: draftError } = await supabaseAdmin
      .from('planning_drafts')
      .select('*')
      .eq('id', draftId)
      .single();

    if (draftError || !draft) return NextResponse.json({ error: 'Draft not found' }, { status: 404, headers: corsHeaders() });
    if (draft.status === 'published') return NextResponse.json({ error: 'Draft already published' }, { status: 400, headers: corsHeaders() });
    if (draft.status === 'publishing') return NextResponse.json({ error: 'Publish already in progress' }, { status: 409, headers: corsHeaders() });

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

    // Mark as publishing
    if (!dryRun) {
      await supabaseAdmin.from('planning_drafts').update({ status: 'publishing' }).eq('id', draftId);
    }

    // Compute diff (same logic as diff route)
    const [baselineResult, entriesResult] = await Promise.all([
      supabaseAdmin.from('planning_baseline_lines').select('*').eq('draft_id', draftId),
      supabaseAdmin.from('planning_entries').select('*').eq('draft_id', draftId)
    ]);
    if (baselineResult.error) throw baselineResult.error;
    if (entriesResult.error) throw entriesResult.error;

    const baseline = baselineResult.data || [];
    const entries  = entriesResult.data || [];

    const baselineMap = new Map(baseline.map((b: any) => [buildKey(b.resource_no, b.bc_job_id, b.bc_task_id, b.planning_date), b]));
    const entriesMap  = new Map(entries.map((e: any)  => [buildKey(e.resource_no, e.bc_job_id, e.bc_task_id, e.planning_date), e]));

    const toCreate: any[] = [];
    const toUpdate: any[] = [];
    const toDelete: any[] = [];

    for (const [key, entry] of entriesMap) {
      const base = baselineMap.get(key);
      const planned = parseFloat(entry.planned_hours);
      if (!base) {
        if (planned > 0) toCreate.push(entry);
      } else {
        if (Math.abs(planned - parseFloat(base.quantity)) >= 0.01) {
          toUpdate.push({ entry, base });
        }
      }
    }
    for (const [key, base] of baselineMap) {
      if (!entriesMap.has(key)) toDelete.push(base);
    }

    const summary: PublishSummary = { created: 0, updated: 0, deleted: 0, unchanged: 0, failed: 0, errors: [] };
    summary.unchanged = entries.length - toCreate.length - toUpdate.length;

    if (dryRun) {
      return NextResponse.json({
        success: true,
        dryRun: true,
        summary: {
          ...summary,
          would_create: toCreate.length,
          would_update: toUpdate.length,
          would_delete: toDelete.length
        }
      }, { headers: corsHeaders() });
    }

    const bcClient = new BusinessCentralClient(tenant, company);

    // Process creates
    for (const entry of toCreate) {
      try {
        const bcLine = await bcClient.createJobPlanningLine({
          jobNo: entry.bc_job_id,
          jobTaskNo: entry.bc_task_id,
          no: entry.resource_no,
          planningDate: entry.planning_date,
          quantity: parseFloat(entry.planned_hours),
          description: entry.description || undefined
        });
        await supabaseAdmin.from('planning_entries').update({
          publish_status: 'created',
          bc_line_no: bcLine.lineNo,
          bc_system_id: bcLine.systemId || null,
          bc_etag: bcLine['@odata.etag'] || null,
          publish_error: null
        }).eq('id', entry.id);
        summary.created++;
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : 'Unknown error';
        await supabaseAdmin.from('planning_entries').update({ publish_status: 'error', publish_error: errMsg }).eq('id', entry.id);
        summary.failed++;
        summary.errors.push({ line: entry as unknown as DiffLine, error: errMsg });
      }
    }

    // Process updates (with single etag retry on 412)
    for (const { entry, base } of toUpdate) {
      const currentEtag: string = base.bc_etag;
      const lineNo: number = base.bc_line_no;
      try {
        const bcLine = await bcClient.updateJobPlanningLine(lineNo, currentEtag, {
          quantity: parseFloat(entry.planned_hours),
          description: entry.description || undefined
        });
        await supabaseAdmin.from('planning_entries').update({
          publish_status: 'updated',
          bc_line_no: bcLine.lineNo ?? lineNo,
          bc_etag: bcLine['@odata.etag'] || null,
          publish_error: null
        }).eq('id', entry.id);
        summary.updated++;
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : 'Unknown error';
        // 412 Precondition Failed — re-fetch etag and retry once
        if (errMsg.includes('412')) {
          try {
            const freshLines = await bcClient.getJobPlanningLines({ jobNo: base.bc_job_id });
            const fresh = freshLines.find((l: any) => l.lineNo === lineNo);
            if (fresh) {
              const bcLine = await bcClient.updateJobPlanningLine(lineNo, fresh['@odata.etag'], {
                quantity: parseFloat(entry.planned_hours),
                description: entry.description || undefined
              });
              await supabaseAdmin.from('planning_entries').update({
                publish_status: 'updated',
                bc_line_no: bcLine.lineNo ?? lineNo,
                bc_etag: bcLine['@odata.etag'] || null,
                publish_error: null
              }).eq('id', entry.id);
              summary.updated++;
              continue;
            }
          } catch (retryErr) {
            // Fall through to error
          }
        }
        await supabaseAdmin.from('planning_entries').update({ publish_status: 'error', publish_error: errMsg }).eq('id', entry.id);
        summary.failed++;
        summary.errors.push({ line: entry as unknown as DiffLine, error: errMsg });
      }
    }

    // Process deletes
    for (const base of toDelete) {
      try {
        await bcClient.deleteJobPlanningLine(base.bc_line_no, base.bc_etag);
        summary.deleted++;
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : 'Unknown error';
        // 412 retry
        if (errMsg.includes('412')) {
          try {
            const freshLines = await bcClient.getJobPlanningLines({ jobNo: base.bc_job_id });
            const fresh = freshLines.find((l: any) => l.lineNo === base.bc_line_no);
            if (fresh) {
              await bcClient.deleteJobPlanningLine(base.bc_line_no, fresh['@odata.etag']);
              summary.deleted++;
              continue;
            }
          } catch (retryErr) {
            // Fall through to error
          }
        }
        summary.failed++;
        summary.errors.push({ line: base as unknown as DiffLine, error: errMsg });
      }
    }

    const finalStatus = summary.failed > 0 ? 'error' : 'published';

    const historyEntry = {
      publishedAt: new Date().toISOString(),
      status: finalStatus,
      summary: { created: summary.created, updated: summary.updated, deleted: summary.deleted, failed: summary.failed }
    };

    const { data: currentDraft } = await supabaseAdmin
      .from('planning_drafts')
      .select('publish_history')
      .eq('id', draftId)
      .single();

    const currentHistory = currentDraft?.publish_history || [];
    const newHistory = [historyEntry, ...currentHistory].slice(0, 20);

    await supabaseAdmin.from('planning_drafts').update({
      status: finalStatus === 'published' ? 'draft' : finalStatus,
      published_at: new Date().toISOString(),
      publish_summary: summary,
      publish_history: newHistory,
      updated_at: new Date().toISOString()
    }).eq('id', draftId);

    const duration = Date.now() - startTime;
    logger.info('Planning publish completed', { draftId, summary, durationMs: duration });

    return NextResponse.json({ success: summary.failed === 0, summary }, { headers: corsHeaders() });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    if (msg === 'UNAUTHORIZED') return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders() });
    if (msg === 'FORBIDDEN')    return NextResponse.json({ error: 'PM role required' }, { status: 403, headers: corsHeaders() });
    logger.error('publish failed', { error: msg });
    // Reset draft status to 'error' if we were publishing
    try {
      const { draftId } = await params;
      await supabaseAdmin.from('planning_drafts').update({ status: 'error' }).eq('id', draftId);
    } catch {}
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
