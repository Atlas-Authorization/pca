// Joins generated inputs with engine decisions into fixtures/{cedar,rego}.jsonl. For Rego it drives `opa eval` per input.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const lines = (f) => readFileSync(f, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const only = process.env.ONLY;
const cedarIn = lines('.work/cedar-in.jsonl'), cedarOut = lines('.work/cedar-out.jsonl');
const byId = new Map(cedarOut.map((o) => [o.id, o.decisions]));
writeFileSync('fixtures/cedar.jsonl', cedarIn.map((c) => JSON.stringify({ ...c, expected: byId.get(c.id) })).join('\n') + '\n');

if (only === 'cedar') process.exit(0);
const tmp = mkdtempSync(join(tmpdir(), 'rego-'));
const out = [];
for (const c of lines('.work/rego-in.jsonl')) {
  writeFileSync(join(tmp, 'p.rego'), c.module);
  const expected = [];
  for (const input of c.inputs) {
    writeFileSync(join(tmp, 'in.json'), JSON.stringify(input));
    let r;
    try {
      r = JSON.parse(execFileSync('.work/opa', ['eval', '-f', 'json', '-d', join(tmp, 'p.rego'), '-i', join(tmp, 'in.json'), 'data.authz.allow'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
    } catch (e) {
      expected.push(`Error: ${String(e.stderr ?? e.message).split('\n')[0]}`);
      break;
    }
    const v = r.result?.[0]?.expressions?.[0]?.value;
    expected.push(v === true ? 'Allow' : 'Deny');
  }
  out.push(JSON.stringify({ ...c, expected }));
}
writeFileSync('fixtures/rego.jsonl', out.join('\n') + '\n');
writeFileSync('fixtures/ENGINES.json', JSON.stringify({ cedar: 'cedar-policy 4.2.2', opa: process.argv[2] }, null, 2) + '\n');
