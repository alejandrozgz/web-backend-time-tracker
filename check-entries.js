// Check if there are any entries to sync
const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = 'https://ltwlsrcamjukrqoesfij.supabase.co';
const supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imx0d2xzcmNhbWp1a3Jxb2VzZmlqIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1NjM2Njc1NywiZXhwIjoyMDcxOTQyNzU3fQ.tSb2sPIzEPOZSC_BF-eANAj93aPtJOk2y6pXHcnFwMc';

const supabase = createClient(supabaseUrl, supabaseKey);

async function checkEntries() {
  const companyId = 'fe3857d4-291c-4252-9d16-c9a5db7ba50f';

  console.log('🔍 Checking time entries for company:', companyId);

  // Check all time entries
  const { data: allEntries, error: allError } = await supabase
    .from('time_entries')
    .select('id, bc_sync_status, is_editable, bc_batch_name, description, date')
    .eq('company_id', companyId);

  if (allError) {
    console.error('❌ Error fetching all entries:', allError);
    return;
  }

  console.log('\n📊 All entries:', allEntries?.length || 0);
  if (allEntries && allEntries.length > 0) {
    console.log('\nEntries breakdown:');
    allEntries.forEach(e => {
      console.log(`  - ${e.id.substring(0, 8)}... | status: ${e.bc_sync_status || 'NULL'} | editable: ${e.is_editable} | batch: ${e.bc_batch_name || 'NULL'} | ${e.description}`);
    });
  }

  // Check entries with status 'local'
  const { data: localEntries, error: localError } = await supabase
    .from('time_entries')
    .select('*')
    .eq('company_id', companyId)
    .eq('bc_sync_status', 'local');

  if (localError) {
    console.error('❌ Error fetching local entries:', localError);
  } else {
    console.log('\n📊 Entries with status "local":', localEntries?.length || 0);
  }

  // Check entries with NULL status
  const { data: nullEntries, error: nullError } = await supabase
    .from('time_entries')
    .select('*')
    .eq('company_id', companyId)
    .is('bc_sync_status', null);

  if (nullError) {
    console.error('❌ Error fetching NULL entries:', nullError);
  } else {
    console.log('📊 Entries with NULL status:', nullEntries?.length || 0);
  }

  // Check entries that are editable
  const { data: editableEntries, error: editableError } = await supabase
    .from('time_entries')
    .select('*')
    .eq('company_id', companyId)
    .eq('is_editable', true);

  if (editableError) {
    console.error('❌ Error fetching editable entries:', editableError);
  } else {
    console.log('📊 Entries that are editable:', editableEntries?.length || 0);
  }

  // Now test the stored procedure
  console.log('\n🔍 Testing get_pending_sync_entries stored procedure...');
  const { data: pendingEntries, error: pendingError } = await supabase
    .rpc('get_pending_sync_entries', {
      p_company_id: companyId
    });

  if (pendingError) {
    console.error('❌ Error calling get_pending_sync_entries:', pendingError);
  } else {
    console.log('✅ get_pending_sync_entries returned:', pendingEntries?.length || 0, 'entries');
    if (pendingEntries && pendingEntries.length > 0) {
      console.log('\nPending entries:');
      pendingEntries.forEach(e => {
        console.log(`  - ${e.id.substring(0, 8)}... | batch: ${e.bc_batch_name || 'NULL'} | ${e.description}`);
      });
    }
  }
}

checkEntries();
