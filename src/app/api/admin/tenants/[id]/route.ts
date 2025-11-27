import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { withAdminAuth } from '@/middleware/adminAuth';

// GET /api/admin/tenants/[id] - Get single tenant
async function getHandler(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;

    const { data: tenant, error } = await supabaseAdmin
      .from('tenants')
      .select('*')
      .eq('id', id)
      .single();

    if (error) throw error;

    if (!tenant) {
      return NextResponse.json(
        { error: 'Tenant not found' },
        { status: 404 }
      );
    }

    return NextResponse.json({ tenant });

  } catch (error) {
    console.error('Error fetching tenant:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json(
      { error: 'Failed to fetch tenant', details: errorMessage },
      { status: 500 }
    );
  }
}

// PATCH /api/admin/tenants/[id] - Update tenant
async function patchHandler(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const data = await request.json();

    // Build update object
    const updateData: any = {
      updated_at: new Date().toISOString()
    };

    if (data.name !== undefined) updateData.name = data.name;
    if (data.bc_base_url !== undefined) updateData.bc_base_url = data.bc_base_url;
    if (data.bc_environment !== undefined) updateData.bc_environment = data.bc_environment;
    if (data.bc_tenant_id !== undefined) updateData.bc_tenant_id = data.bc_tenant_id;
    if (data.bc_client_id !== undefined) updateData.bc_client_id = data.bc_client_id;
    if (data.bc_client_secret !== undefined) updateData.bc_client_secret = data.bc_client_secret;
    if (data.oauth_enabled !== undefined) updateData.oauth_enabled = data.oauth_enabled;
    if (data.settings !== undefined) updateData.settings = data.settings;
    if (data.is_active !== undefined) updateData.is_active = data.is_active;

    const { data: tenant, error } = await supabaseAdmin
      .from('tenants')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    return NextResponse.json({ tenant });

  } catch (error) {
    console.error('Error updating tenant:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json(
      { error: 'Failed to update tenant', details: errorMessage },
      { status: 500 }
    );
  }
}

// DELETE /api/admin/tenants/[id] - Delete tenant
async function deleteHandler(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;

    // Check if tenant has companies
    const { count: companiesCount } = await supabaseAdmin
      .from('companies')
      .select('id', { count: 'exact', head: true })
      .eq('tenant_id', id);

    if (companiesCount && companiesCount > 0) {
      return NextResponse.json(
        { error: 'Cannot delete tenant with existing companies. Delete companies first.' },
        { status: 409 }
      );
    }

    const { error } = await supabaseAdmin
      .from('tenants')
      .delete()
      .eq('id', id);

    if (error) throw error;

    return NextResponse.json({ message: 'Tenant deleted successfully' });

  } catch (error) {
    console.error('Error deleting tenant:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json(
      { error: 'Failed to delete tenant', details: errorMessage },
      { status: 500 }
    );
  }
}

export const GET = withAdminAuth(getHandler);
export const PATCH = withAdminAuth(patchHandler);
export const DELETE = withAdminAuth(deleteHandler);
