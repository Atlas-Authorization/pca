// node circuits/r1cs-provenance.mjs <circuit-id> <a.r1cs> <b.r1cs> <out.json>
// Fails unless two independent compilations of the circuit are byte-identical, then writes the record
// { circuit, sourceSha256, r1csSha256 } (sourceSha256 from circuit-versions.json). A ceremony transcript's r1csSha256 and
// circuitProvenance() in zk-ceremony.ts use the same two hashes.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const [id, a, b, out] = process.argv.slice(2);
if (!id || !a || !b || !out) { console.error('usage: r1cs-provenance.mjs <circuit-id> <a.r1cs> <b.r1cs> <out.json>'); process.exit(2); }
const sha = (f) => createHash('sha256').update(readFileSync(f)).digest('hex');
const [ha, hb] = [sha(a), sha(b)];
if (ha !== hb) { console.error(`${id}: two compilations differ (${ha} vs ${hb})`); process.exit(1); }
const versions = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'circuit-versions.json'), 'utf8'));
const c = versions.circuits[id];
if (!c) { console.error(`unknown circuit ${id}`); process.exit(2); }
writeFileSync(out, JSON.stringify({ circuit: id, sourceSha256: c.source_sha256, r1csSha256: ha }, null, 2) + '\n');
console.log(`${id}: r1cs ${ha} (deterministic across two compilations)`);
