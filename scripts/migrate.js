#!/usr/bin/env node
/**
 * migrate.js — Script de migraciones para Supabase (staging y producción)
 *
 * Uso:
 *   node scripts/migrate.js               → usa .env.local (producción)
 *   ENV_FILE=.env.staging node scripts/migrate.js → usa .env.staging
 *   node scripts/migrate.js --dry-run     → muestra qué se aplicaría sin ejecutar
 *
 * O vía npm scripts (package.json):
 *   npm run migrate:staging
 *   npm run migrate:prod
 */

const fs   = require('fs');
const path = require('path');

// ── Cargar env file ──────────────────────────────────────────
const envFile = process.env.ENV_FILE || '.env.local';
const envPath = path.resolve(__dirname, '..', envFile);

if (!fs.existsSync(envPath)) {
  console.error(`❌ Env file no encontrado: ${envPath}`);
  process.exit(1);
}

// Parsear el .env manualmente (evita dependencia de dotenv)
const envContent = fs.readFileSync(envPath, 'utf8');
for (const line of envContent.split('\n')) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) continue;
  const eqIdx = trimmed.indexOf('=');
  if (eqIdx === -1) continue;
  const key = trimmed.slice(0, eqIdx).trim();
  const val = trimmed.slice(eqIdx + 1).trim();
  process.env[key] = val; // el archivo siempre tiene precedencia sobre el entorno del sistema
}

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL || DATABASE_URL.includes('STAGING-PROJECT-REF')) {
  console.error(`❌ DATABASE_URL no configurado en ${envFile}`);
  console.error('   Obtén la connection string en: Supabase Dashboard → Project Settings → Database → Connection String (URI)');
  process.exit(1);
}

const isDryRun = process.argv.includes('--dry-run');
const MIGRATIONS_DIR = path.resolve(__dirname, '..', 'migrations');
const ORDER_FILE     = path.join(MIGRATIONS_DIR, '_order.txt');

// ── Leer manifest de orden ───────────────────────────────────
function readOrderedMigrations() {
  const content = fs.readFileSync(ORDER_FILE, 'utf8');
  return content
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
}

// ── Conectar a Postgres ──────────────────────────────────────
async function getClient() {
  let pg;
  try {
    pg = require('pg');
  } catch {
    console.error('❌ Paquete "pg" no instalado. Ejecuta: npm install --save-dev pg');
    process.exit(1);
  }
  const { Client } = pg;
  // Parsear la URL manualmente para pasar parámetros explícitos
  // (evita problemas de URL-encoding con caracteres especiales en la contraseña)
  let clientConfig;
  try {
    const u = new URL(DATABASE_URL);
    clientConfig = {
      user:     decodeURIComponent(u.username),
      password: decodeURIComponent(u.password),
      host:     u.hostname,
      port:     parseInt(u.port, 10) || 5432,
      database: u.pathname.replace(/^\//, ''),
      ssl:      { rejectUnauthorized: false }
    };
  } catch {
    // Fallback: usar connectionString directamente
    clientConfig = { connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } };
  }
  const client = new Client(clientConfig);
  await client.connect();
  return client;
}

// ── Tabla de tracking ────────────────────────────────────────
async function ensureMigrationsTable(client) {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      filename   VARCHAR(255) PRIMARY KEY,
      applied_at TIMESTAMPTZ  DEFAULT NOW()
    );
  `);
}

async function getApplied(client) {
  const res = await client.query('SELECT filename FROM schema_migrations ORDER BY applied_at');
  return new Set(res.rows.map(r => r.filename));
}

async function markApplied(client, filename) {
  await client.query(
    'INSERT INTO schema_migrations (filename) VALUES ($1) ON CONFLICT DO NOTHING',
    [filename]
  );
}

// ── Main ─────────────────────────────────────────────────────
async function main() {
  const env = envFile === '.env.local' ? '🔴 PRODUCCIÓN' : `🟡 STAGING (${envFile})`;
  console.log(`\n📦 Migraciones — entorno: ${env}`);
  console.log(`   Base de datos: ${DATABASE_URL.replace(/:([^:@]{8})[^@]*@/, ':****@')}\n`);

  if (isDryRun) console.log('⚠️  DRY RUN — no se ejecutará nada\n');

  const ordered = readOrderedMigrations();
  console.log(`📋 ${ordered.length} migraciones en el manifest`);

  const client = await getClient();
  try {
    await ensureMigrationsTable(client);
    const applied = await getApplied(client);

    const pending = ordered.filter(f => !applied.has(f));

    if (pending.length === 0) {
      console.log('\n✅ Todas las migraciones ya están aplicadas. Nada que hacer.\n');
      return;
    }

    console.log(`\n🚀 ${pending.length} migración(es) pendiente(s):\n`);

    let ok = 0, failed = 0;

    for (const filename of pending) {
      const filePath = path.join(MIGRATIONS_DIR, filename);
      if (!fs.existsSync(filePath)) {
        console.warn(`  ⚠️  Archivo no encontrado, saltando: ${filename}`);
        continue;
      }

      const sql = fs.readFileSync(filePath, 'utf8');
      process.stdout.write(`  ▶ ${filename} ... `);

      if (isDryRun) {
        console.log('(dry run)');
        ok++;
        continue;
      }

      try {
        await client.query('BEGIN');
        await client.query(sql);
        await markApplied(client, filename);
        await client.query('COMMIT');
        console.log('✅');
        ok++;
      } catch (err) {
        await client.query('ROLLBACK');
        console.log('❌');
        console.error(`     Error: ${err.message}\n`);
        failed++;
        // Detener en el primer error para evitar migraciones en estado inconsistente
        console.error('⛔  Detenido tras primer error. Corrígelo antes de continuar.\n');
        break;
      }
    }

    console.log(`\n─────────────────────────────────────────`);
    console.log(`  ✅ Aplicadas: ${ok}   ❌ Fallidas: ${failed}`);
    console.log(`─────────────────────────────────────────\n`);

    if (failed > 0) process.exit(1);

  } finally {
    await client.end();
  }
}

main().catch(err => {
  console.error('Error fatal:', err);
  process.exit(1);
});
