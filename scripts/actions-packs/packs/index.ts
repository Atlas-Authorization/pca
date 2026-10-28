import { readdirSync } from 'node:fs';
import type { PackDef } from '../lib/pack';

/** Every packs/<name>.ts is a pack (index.ts and *.sources.json excluded), in name order. */
export async function ALL_PACKS(): Promise<PackDef[]> {
  const names = readdirSync(__dirname).filter((f) => f.endsWith('.ts') && f !== 'index.ts').map((f) => f.slice(0, -3)).sort();
  const out: PackDef[] = [];
  for (const n of names) out.push((await import(`./${n}`)).default as PackDef);
  return out;
}
