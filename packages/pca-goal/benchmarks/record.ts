// Regenerate the recorded model outputs: deno run --unstable-sloppy-imports -A benchmarks/record.ts
import { DOMAINS, fixturesFor } from './data.ts';
for (const d of DOMAINS) {
  const rec = fixturesFor(d);
  const sorted = Object.fromEntries(Object.entries(rec).sort(([a], [b]) => (a < b ? -1 : 1)));
  await Deno.writeTextFile(new URL(`./recorded/${d}.json`, import.meta.url), JSON.stringify(sorted) + '\n');
}
