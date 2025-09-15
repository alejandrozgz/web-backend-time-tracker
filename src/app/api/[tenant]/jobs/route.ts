import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { BusinessCentralClient } from '@/lib/bc-api';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  try {
    const { tenant: tenantSlug } = await params;
    const url = new URL(request.url);
    const companyId = url.searchParams.get('companyId');

    console.log('🎯 ===== JOBS API CALLED =====');
    console.log('🔍 Tenant:', tenantSlug);
    console.log('🔍 Company ID:', companyId);

    if (!companyId) {
      return NextResponse.json({ error: 'Company ID required' }, { status: 400 });
    }

    // Get tenant from Supabase
    const { data: tenant, error: tenantError } = await supabaseAdmin
      .from('tenants')
      .select('*')
      .eq('slug', tenantSlug)
      .single();

    console.log('🔍 Tenant found:', tenant?.slug, 'OAuth enabled:', tenant?.oauth_enabled);

    if (tenantError || !tenant) {
      console.error('❌ Tenant not found:', tenantError);
      return NextResponse.json({ error: 'Tenant not found' }, { status: 404 });
    }

    // Get company from Supabase  
    const { data: company, error: companyError } = await supabaseAdmin
      .from('companies')
      .select('*')
      .eq('id', companyId)
      .eq('tenant_id', tenant.id)
      .single();

    console.log('🔍 Company found:', company?.name, 'BC Company ID:', company?.bc_company_id);

    if (companyError || !company) {
      console.error('❌ Company not found:', companyError);
      return NextResponse.json({ error: 'Company not found' }, { status: 404 });
    }

    // ✅ Business Central con OAuth
    if (tenant.oauth_enabled && tenant.bc_client_id && tenant.bc_client_secret && tenant.bc_tenant_id) {
      console.log('🚀 Attempting to fetch assignments from Business Central...');
      
      try {
        const bcClient = new BusinessCentralClient(tenant, company);
        
        console.log('🔍 BC Client created, fetching resource assignments...');
        
        // Get the current user's resource number from JWT token
        const authHeader = request.headers.get('authorization');
        let currentResourceNo = 'R0010'; // Default for demo
        
        if (authHeader && authHeader.startsWith('Bearer ')) {
          try {
            const token = authHeader.substring(7);
            const decodedToken = JSON.parse(Buffer.from(token, 'base64').toString());
            currentResourceNo = decodedToken.resourceNo || 'R0010';
            console.log('🔍 Current user resource:', currentResourceNo);
          } catch (e) {
            console.log('🔍 Could not decode token, using default resource');
          }
        }
        
        // ✅ UNA SOLA LLAMADA - Ya filtra jobs y tasks asignadas
        const assignments = await bcClient.getResourceAssignments(currentResourceNo);
        const { jobs: bcJobs, tasks: bcTasks } = assignments;

        console.log('🔍 BC Response - Assigned Jobs:', bcJobs?.length || 0, 'Assigned Tasks:', bcTasks?.length || 0);

        // Transform BC data to our format
        const jobs = bcJobs.map(job => ({
          id: job.systemId || job.id,
          bc_job_id: job.no || job.number,
          name: job.description || job.name || `Job ${job.no}`,
          description: job.description || job.name
        }));

        // Transform tasks - already filtered to assigned tasks only
        const tasks = bcTasks
          .filter(task => task.description && task.description.trim() !== '') // Remove empty descriptions
          .map(task => ({
            id: task.systemId || task.id,
            job_id: jobs.find(j => j.bc_job_id === task.jobNo)?.id,
            bc_task_id: task.jobTaskNo || task.taskNo,
            description: task.description
          }))
          .filter(task => task.job_id); // Only tasks with valid job_id

        console.log('✅ BC Data transformed:');
        console.log('📋 Assigned Jobs:', jobs.map(j => `${j.bc_job_id}: ${j.name}`));
        console.log('📋 Assigned Tasks:', tasks.map(t => `${t.bc_task_id}: ${t.description}`));

        return NextResponse.json({
          jobs,
          tasks,
          source: 'business_central_resource_assignments'
        });

      } catch (bcError) {
        console.error('❌ Business Central error:', bcError);
        console.log('🔄 Falling back to local Supabase data...');
      }
    } else {
      console.log('⚠️  OAuth not configured, using local Supabase data...');
    }

    // Fallback: Fetch from local Supabase database
    console.log('📂 Fetching from local Supabase database...');
    
    const [jobsResult, tasksResult] = await Promise.all([
      supabaseAdmin
        .from('jobs')
        .select('*')
        .eq('company_id', companyId)
        .eq('status', 'active')
        .order('name'),
      
      supabaseAdmin
        .from('job_tasks')
        .select('*')
        .eq('company_id', companyId)
        .eq('status', 'active')
        .order('description')
    ]);

    console.log('📂 Supabase data - Jobs:', jobsResult.data?.length || 0, 'Tasks:', tasksResult.data?.length || 0);

    if (jobsResult.error) {
      console.error('❌ Supabase jobs error:', jobsResult.error);
      throw jobsResult.error;
    }
    if (tasksResult.error) {
      console.error('❌ Supabase tasks error:', tasksResult.error);
      throw tasksResult.error;
    }

    console.log('🔚 ===== END JOBS API =====');

    return NextResponse.json({
      jobs: jobsResult.data || [],
      tasks: tasksResult.data || [],
      source: 'supabase_local'
    });

  } catch (error) {
	  console.error('❌ Jobs fetch error:', error);
	  const errorMessage = error instanceof Error ? error.message : 'Unknown error';
	  return NextResponse.json({ 
		error: 'Failed to fetch jobs',
		details: errorMessage  // ✅ CORRECTO
	  }, { status: 500 });
	}
}