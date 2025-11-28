const bcrypt = require('bcryptjs');

async function createAdminHash() {
  // Genera hash para diferentes passwords comunes
  const passwords = ['admin', 'admin123', 'Admin123'];

  console.log('\n🔐 Admin Password Hashes:\n');

  for (const pwd of passwords) {
    const hash = await bcrypt.hash(pwd, 10);
    console.log(`Password: "${pwd}"`);
    console.log(`Hash: ${hash}`);
    console.log(`\nSQL to create/update admin user:`);
    console.log(`INSERT INTO admin_users (username, password_hash, email, is_active)
VALUES ('admin', '${hash}', 'admin@atpdynamics.com', true)
ON CONFLICT (username)
DO UPDATE SET password_hash = '${hash}', updated_at = NOW();`);
    console.log('\n' + '='.repeat(80) + '\n');
  }

  // Test comparison
  console.log('\n✅ Testing password comparison:\n');
  const testHash = await bcrypt.hash('admin', 10);
  const isValid = await bcrypt.compare('admin', testHash);
  console.log(`Hash for 'admin': ${testHash}`);
  console.log(`Compare 'admin' with hash: ${isValid ? '✅ MATCH' : '❌ NO MATCH'}`);
}

createAdminHash().catch(console.error);
