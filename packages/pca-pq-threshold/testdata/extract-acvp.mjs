// Fetches the NIST ACVP-Server FIPS 204 (ML-DSA) internalProjection files at a PINNED commit and writes
// the ML-DSA-65 subset used by the tests to acvp-ml-dsa-65.json (with sha256 provenance of each upstream file).
// Usage: node testdata/extract-acvp.mjs
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const COMMIT = '975de31eb83d87039ec88934fdc47d8c312b892d'; // usnistgov/ACVP-Server master, 2026-08-12
const BASE = `https://raw.githubusercontent.com/usnistgov/ACVP-Server/${COMMIT}/gen-val/json-files`;
const PS = 'ML-DSA-65';
const lc = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, typeof v === 'string' && /^[0-9A-Fa-f]+$/.test(v) && k !== 'reason' && k !== 'hashAlg' ? v.toLowerCase() : v]));

async function get(dir) {
  const url = `${BASE}/${dir}/internalProjection.json`;
  const buf = Buffer.from(await (await fetch(url)).arrayBuffer());
  return { url, sha256: createHash('sha256').update(buf).digest('hex'), json: JSON.parse(buf.toString('utf8')) };
}
const groups = (j) => j.testGroups.filter((g) => g.parameterSet === PS);
const kg = await get('ML-DSA-keyGen-FIPS204');
const sg = await get('ML-DSA-sigGen-FIPS204');
const sv = await get('ML-DSA-sigVer-FIPS204');
const out = {
  provenance: {
    kind: 'OFFICIAL NIST ACVP test vectors (FIPS 204, ML-DSA), subset parameterSet=' + PS,
    repository: 'https://github.com/usnistgov/ACVP-Server',
    commit: COMMIT,
    fetched: new Date().toISOString().slice(0, 10),
    files: [kg, sg, sv].map((f) => ({ url: f.url, sha256: f.sha256, vsId: f.json.vsId, revision: f.json.revision })),
    excluded: 'preHash (HashML-DSA) groups: PCA does not use pre-hash mode',
  },
  keyGen: groups(kg.json).flatMap((g) => g.tests.map((t) => lc({ tcId: t.tcId, seed: t.seed, pk: t.pk, sk: t.sk }))),
  sigGen: groups(sg.json).filter((g) => g.preHash !== 'preHash').map((g) => ({
    tgId: g.tgId, deterministic: g.deterministic, signatureInterface: g.signatureInterface, externalMu: g.externalMu,
    tests: g.tests.map((t) => lc({ tcId: t.tcId, message: t.message, mu: t.mu, context: t.context, rnd: t.rnd, pk: t.pk, sk: t.sk, signature: t.signature })),
  })),
  sigVer: groups(sv.json).filter((g) => g.preHash !== 'preHash').map((g) => ({
    tgId: g.tgId, signatureInterface: g.signatureInterface, externalMu: g.externalMu,
    tests: g.tests.map((t) => lc({ tcId: t.tcId, testPassed: t.testPassed, reason: t.reason, message: t.message, mu: t.mu, context: t.context, pk: t.pk, signature: t.signature })),
  })),
};
const dst = join(dirname(fileURLToPath(import.meta.url)), 'acvp-ml-dsa-65.json');
writeFileSync(dst, JSON.stringify(out) + '\n');
console.log('wrote', dst, out.keyGen.length, out.sigGen.map((g) => g.tests.length), out.sigVer.map((g) => g.tests.length));
