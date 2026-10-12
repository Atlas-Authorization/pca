#!/usr/bin/env node
// Usage: merge-reports.mjs <out.json> <base.json> <overlay.json>...
// Overlays killed results onto a base Stryker report. A mutant that Survived / had NoCoverage in the base becomes Killed when an
// overlay report of the SAME source text killed the mutant at the same location with the same mutator and replacement.
//
// Why: with perTest coverage Stryker attributes a static (module-level) mutant to the tests that LOAD the module. A suite that
// re-imports modules inside a test (vi.resetModules + dynamic import) makes such mutants "covered" by that suite alone, so the
// tests that actually check the constant never run against them and they are reported as survivors. Re-measure those mutants with
// `run-proc.sh` (coverageAnalysis "off": every mutant runs the given test file from a fresh module graph) and overlay the result.
import fs from 'node:fs';
const [out, basePath, ...overlays] = process.argv.slice(2);
if (!out || !basePath || overlays.length === 0) {
  console.error('usage: merge-reports.mjs <out.json> <base.json> <overlay.json>...');
  process.exit(2);
}
const base = JSON.parse(fs.readFileSync(basePath, 'utf8'));
const key = (m) => [m.location.start.line, m.location.start.column, m.location.end.line, m.location.end.column, m.mutatorName, String(m.replacement)].join(':');
let changed = 0;
for (const op of overlays) {
  const ov = JSON.parse(fs.readFileSync(op, 'utf8'));
  for (const [file, f] of Object.entries(ov.files)) {
    const b = base.files[file];
    if (!b) continue;
    if (b.source !== f.source) {
      console.error(`skip ${file} from ${op}: source differs from the base report`);
      continue;
    }
    const killed = new Map(f.mutants.filter((m) => m.status === 'Killed').map((m) => [key(m), m]));
    for (const m of b.mutants) {
      if (m.status !== 'Survived' && m.status !== 'NoCoverage') continue;
      const k = killed.get(key(m));
      if (!k) continue;
      m.status = 'Killed';
      m.statusReason = `killed in overlay ${op}${k.killedBy ? ` by ${k.killedBy.join(',')}` : ''}`;
      changed++;
    }
  }
}
fs.writeFileSync(out, JSON.stringify(base));
console.log(`merged: ${changed} survivor(s) shown killed by the overlay run(s) -> ${out}`);
