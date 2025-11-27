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
    const hours = parseInt(searchParams.get('hours') || '24');

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

    // Call the stored procedure to get recent sync activity
    const { data: activity, error: activityError } = await supabaseAdmin
      .rpc('get_recent_sync_activity', {
        p_company_id: companyId,
        p_hours: hours
      });

    if (activityError) {
      console.error('Error fetching sync activity:', activityError);
      throw activityError;
    }

    return NextResponse.json({
      activity: activity || [],
      hours
    });

  } catch (error) {
    console.error('Error in sync activity route:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json(
      { error: 'Failed to fetch sync activity', details: errorMessage },
      { status: 500 }
    );
  }
}
