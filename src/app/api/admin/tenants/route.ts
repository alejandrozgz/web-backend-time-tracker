import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { withAdminAuth } from '@/middleware/adminAuth';

// GET /api/admin/tenants - List all tenants
async function getHandler(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const isActive = searchParams.get('is_active');
    const search = searchParams.get('search');
    const limit = parseInt(searchParams.get('limit') || '50');
    const offset = parseInt(searchParams.get('offset') || '0');

    let query = supabaseAdmin
      .from('tenants')
      .select('*', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    // Apply filters
    if (isActive !== null) {
      query = query.eq('is_active', isActive === 'true');
    }

    if (search) {
      query = query.or(`name.ilike.%${search}%,slug.ilike.%${search}%`);
    }

    const { data: tenants, error, count } = await query;

    if (error) throw error;

    return NextResponse.json({
      tenants: tenants || [],
      count: count || 0,
      limit,
      offset
    });

  } catch (error) {
    console.error('Error fetching tenants:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json(
      { error: 'Failed to fetch tenants', details: errorMessage },
      { status: 500 }
    );
  }
}

// POST /api/admin/tenants - Create new tenant
async function postHandler(request: NextRequest) {
  try {
    const data = await request.json();

    // Validate required fields
    if (!data.slug || !data.name || !data.bc_base_url) {
      return NextResponse.json(
        { error: 'Missing required fields: slug, name, bc_base_url' },
        { status: 400 }
      );
    }

    // Check if slug already exists
    const { data: existing } = await supabaseAdmin
      .from('tenants')
      .select('id')
      .eq('slug', data.slug)
      .single();

    if (existing) {
      return NextResponse.json(
        { error: 'Tenant with this slug already exists' },
        { status: 409 }
      );
    }

    // Create tenant
    const { data: tenant, error } = await supabaseAdmin
      .from('tenants')
      .insert({
        slug: data.slug,
        name: data.name,
        bc_base_url: data.bc_base_url,
        bc_environment: data.bc_environment || 'Production',
        bc_tenant_id: data.bc_tenant_id,
        bc_client_id: data.bc_client_id,
        bc_client_secret: data.bc_client_secret,
        oauth_enabled: data.oauth_enabled || false,
        settings: data.settings || {}
      })
      .select()
      .single();

    if (error) throw error;

    return NextResponse.json({ tenant }, { status: 201 });

  } catch (error) {
    console.error('Error creating tenant:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json(
      { error: 'Failed to create tenant', details: errorMessage },
      { status: 500 }
    );
  }
}

export const GET = withAdminAuth(getHandler);
export const POST = withAdminAuth(postHandler);
