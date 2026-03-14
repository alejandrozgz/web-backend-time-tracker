import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { requirePMRole } from '@/lib/planning-auth';
import { logger } from '@/lib/logger';

function corsHeaders() {
  return { 'Access-Control-Allow-Origin': '*' };
}

// GET /api/[tenant]/planning/drafts/[draftId]
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string; draftId: string }> }
) {
  try {
    requirePMRole(request);
    const { draftId } = await params;

    const { data: draft, error } = await supabaseAdmin
      .from('planning_drafts')
      .select('*')
      .eq('id', draftId)
      .single();

    if (error || !draft) return NextResponse.json({ error: 'Draft not found' }, { status: 404, headers: corsHeaders() });

    return NextResponse.json({ draft }, { headers: corsHeaders() });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    if (msg === 'UNAUTHORIZED') return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders() });
    if (msg === 'FORBIDDEN')    return NextResponse.json({ error: 'PM role required' }, { status: 403, headers: corsHeaders() });
    return NextResponse.json({ error: msg }, { status: 500, headers: corsHeaders() });
  }
}

// PATCH /api/[tenant]/planning/drafts/[draftId] — update name, notes, status (lock/unlock)
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string; draftId: string }> }
) {
  try {
    requirePMRole(request);
    const { draftId } = await params;
    const body = await request.json();
    const { name, notes, status } = body;

    const updates: Record<string, any> = { updated_at: new Date().toISOString() };
    if (name !== undefined)   updates.name = name;
    if (notes !== undefined)  updates.notes = notes;
    if (status !== undefined) {
      const allowed = ['draft', 'locked'];
      if (!allowed.includes(status)) {
        return NextResponse.json({ error: `status must be one of: ${allowed.join(', ')}` }, { status: 400, headers: corsHeaders() });
      }
      updates.status = status;
    }

    const { data: draft, error } = await supabaseAdmin
      .from('planning_drafts')
      .update(updates)
      .eq('id', draftId)
      .select()
      .single();

    if (error || !draft) return NextResponse.json({ error: 'Draft not found or update failed' }, { status: 404, headers: corsHeaders() });

    return NextResponse.json({ draft }, { headers: corsHeaders() });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    if (msg === 'UNAUTHORIZED') return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders() });
    if (msg === 'FORBIDDEN')    return NextResponse.json({ error: 'PM role required' }, { status: 403, headers: corsHeaders() });
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
