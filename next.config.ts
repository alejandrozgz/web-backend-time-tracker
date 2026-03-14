import type { NextConfig } from "next";
import fs from "fs";
import path from "path";

// Cargar env file alternativo si se especifica con ENV_FILE
// Permite: ENV_FILE=.env.staging next dev
const envFile = process.env.ENV_FILE;
if (envFile && envFile !== ".env.local") {
  const envPath = path.resolve(process.cwd(), envFile);
  if (fs.existsSync(envPath)) {
    const content = fs.readFileSync(envPath, "utf8");
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eqIdx = trimmed.indexOf("=");
      if (eqIdx === -1) continue;
      const key = trimmed.slice(0, eqIdx).trim();
      const val = trimmed.slice(eqIdx + 1).trim();
      process.env[key] = val;
    }
    console.log(`\n🔧 Next.js cargando env: ${envFile}\n`);
  }
}

const nextConfig: NextConfig = {
  /* config options here */
};

export default nextConfig;
