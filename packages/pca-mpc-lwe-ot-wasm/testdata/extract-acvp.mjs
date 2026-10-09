// Fetches the NIST ACVP-Server FIPS 203 (ML-KEM) internalProjection files at a PINNED commit and writes
// the ML-KEM-768 subset used by the tests to acvp-ml-kem-768.json (sha256 provenance of each upstream file).
// Usage: node testdata/extract-acvp.mjs
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const COMMIT = '975de31eb83d87039ec88934fdc47d8c312b892d'; // usnistgov/ACVP-Server master, 2026-08-12
const BASE = `https://raw.githubusercontent.com/usnistgov/ACVP-Server/${COMMIT}/gen-val/json-files`;
const PS = 'ML-KEM-768';
const lc = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined).map(([k, v]) => [k, typeof v === 'string' && /^[0-9A-Fa-f]+$/.test(v) ? v.toLowerCase() : v]));
async function get(dir) {
  const url = `${BASE}/${dir}/internalProjection.json`;
  const buf = Buffer.from(await (await fetch(url)).arrayBuffer());
  return { url, sha256: createHash('sha256').update(buf).digest('hex'), json: JSON.parse(buf.toString('utf8')) };
}
const kg = await get('ML-KEM-keyGen-FIPS203');
const ed = await get('ML-KEM-encapDecap-FIPS203');
const sel = (j, fn) => j.testGroups.filter((g) => g.parameterSet === PS && (fn === undefined || g.function === fn));
const out = {
  provenance: {
    kind: 'OFFICIAL NIST ACVP test vectors (FIPS 203, ML-KEM), subset parameterSet=' + PS,
    repository: 'https://github.com/usnistgov/ACVP-Server',
    commit: COMMIT,
    fetched: new Date().toISOString().slice(0, 10),
    files: [kg, ed].map((f) => ({ url: f.url, sha256: f.sha256, vsId: f.json.vsId, revision: f.json.revision })),
  },
  keyGen: sel(kg.json).flatMap((g) => g.tests.map((t) => lc({ tcId: t.tcId, d: t.d, z: t.z, ek: t.ek, dk: t.dk }))),
  encapsulation: sel(ed.json, 'encapsulation').flatMap((g) => g.tests.map((t) => lc({ tcId: t.tcId, ek: t.ek, m: t.m, c: t.c, k: t.k }))),
  decapsulation: sel(ed.json, 'decapsulation').flatMap((g) => g.tests.map((t) => lc({ tcId: t.tcId, dk: t.dk, c: t.c, k: t.k }))),
};
writeFileSync(join(dirname(fileURLToPath(import.meta.url)), 'acvp-ml-kem-768.json'), JSON.stringify(out) + '\n');
console.log(out.keyGen.length, out.encapsulation.length, out.decapsulation.length);
