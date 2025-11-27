import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  try {
    const { tenant: tenantSlug } = await params;
    const { searchParams } = new URL(request.url);

    const companyId = searchParams.get('companyId');
    const date_from = searchParams.get('date_from');
    const date_to = searchParams.get('date_to');

    if (!companyId) {
      return NextResponse.json({ error: 'Company ID required' }, { status: 400 });
    }

    // Get tenant
    const { data: tenant, error: tenantError } = await supabaseAdmin
      .from('tenants')
      .select('*')
      .eq('slug', tenantSlug)
      .single();

    if (tenantError || !tenant) {
      return NextResponse.json({ error: 'Tenant not found' }, { status: 404 });
    }

    // Default to last 30 days if not specified
    const defaultDateFrom = new Date();
    defaultDateFrom.setDate(defaultDateFrom.getDate() - 30);

    // Call the stored procedure to get sync statistics
    const { data: statistics, error: statsError } = await supabaseAdmin
      .rpc('get_sync_statistics', {
        p_company_id: companyId,
        p_date_from: date_from ? new Date(date_from).toISOString() : defaultDateFrom.toISOString(),
        p_date_to: date_to ? new Date(date_to).toISOString() : new Date().toISOString()
      });

    if (statsError) {
      console.error('Error fetching sync statistics:', statsError);
      throw statsError;
    }

    // The RPC function returns an array with a single row
    const stats = statistics?.[0] || {
      total_operations: 0,
      successful_operations: 0,
      failed_operations: 0,
      total_entries_processed: 0,
      total_entries_succeeded: 0,
      total_entries_failed: 0,
      total_hours: 0,
      avg_duration_ms: 0,
      last_sync_at: null,
      errors_by_code: {}
    };

    return NextResponse.json(stats);

  } catch (error) {
    console.error('Error in sync statistics route:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json(
      { error: 'Failed to fetch sync statistics', details: errorMessage },
      { status: 500 }
    );
  }
}
