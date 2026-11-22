// Shared helpers for the 0.6 native-port differential oracles (<package>.mts in this directory).
// Same case format as ../oracles-base/lib.mjs (header line, then one {fn, name, args, out} case per line, gzip):
// this file re-exports those helpers and adds refWrite, which writes out/ref-<package>.json.gz.
// Each native lane copies the file into sdks/<lang>-pca/test-data/.
// Run:  packages/pca/node_modules/tsx/dist/cli.mjs --tsconfig tools/pca-audit/oracles/tsconfig.json tools/pca-audit/oracles/<package>.mts
import fs from 'node:fs';
import zlib from 'node:zlib';
export * from '../oracles-base/lib.mjs';
import { ser, serWire, clockMember, assertNoGeneratorBugs, assertNotVacuous } from '../oracles-base/lib.mjs';

import { fileURLToPath } from 'node:url';
export const Ref_OUT = fileURLToPath(new URL('./out/', import.meta.url));

/** Write an Oracle (from ../oracles-base/lib.mjs) to out/ref-<pkg>.json.gz; refuses a corpus over 5 MB uncompressed. */
export function refWrite(o, pkg) {
  assertNoGeneratorBugs(o); // a throw the generator caused itself is never written as a reference result
  assertNotVacuous(o); // a fn whose cases all record one outcome, or only refusals, is reported (fatal under PCA_ORACLE_STRICT=1)
  fs.mkdirSync(Ref_OUT, { recursive: true });
  const body = '{"about":' + JSON.stringify(o.about) + ',"generator":' + JSON.stringify(String(o.generator).split("/").pop()) + ',"count":' + o.cases.length + clockMember() +
    ',"cases":[\n' + o.cases.map((c) => serWire(c, o.utf16Escape === true)).join(',\n') + '\n]}\n';
  if (Buffer.byteLength(body) > 5 * 1024 * 1024) throw new Error('oracle over 5 MB uncompressed: trim the generated space');
  const file = Ref_OUT + `ref-${pkg}.json.gz`;
  fs.writeFileSync(file, zlib.gzipSync(Buffer.from(body, 'utf8'), { level: 9, mtime: 0 }));
  const byFn = {};
  for (const c of o.cases) byFn[c.fn] = (byFn[c.fn] ?? 0) + 1;
  console.log(`wrote ${o.cases.length} cases to ${file}\n  by fn: ` + Object.entries(byFn).map(([k, v]) => `${k}=${v}`).join(' '));
}

/**
 * Write the cases of one Oracle whose fn is in `fns` as a corpus of their own, out/ref-<name>.json.gz (a lane that replays only part of a
 * generator's functions carries this file, so every lane copy of a corpus equals a generated corpus of the same name).
 */
export function refWriteSubset(o, name, fns, about) {
  const sub = Object.create(Object.getPrototypeOf(o));
  Object.assign(sub, o, { cases: o.cases.filter((c) => fns.includes(c.fn)), about: `${o.about} (${about})` });
  Object.defineProperty(sub, 'vacuousChecked', { value: true });
  if (sub.cases.length === 0) throw new Error(`refWriteSubset ${name}: no case of ${fns.join(', ')}`);
  refWrite(sub, name);
}

/**
 * Write an Oracle in two corpora: ref-<pkg>.json.gz (committed: no secret key material) and ref-<pkg>-gen.json.gz (the cases whose arguments or
 * results carry a private key that is not a function of a seed label the native lanes can derive). The second file is never committed: CI
 * regenerates it from this generator (scripts/pca-ci-workflows/_native/scripts/gen-secret-corpus.sh) next to the lane's test data before the
 * tests run, and a missing file fails the suite when CI is set. `secretsOf(caseJson)` returns the secret values (base64url strings) found in
 * one case; a case is moved when it contains any secret value found anywhere in the corpus.
 */
export function splitWrite(o, pkg, secretsOf) {
  const secrets = new Set();
  for (const c of o.cases) for (const v of secretsOf(ser(c))) if (v && v.length >= 20) secrets.add(v);
  const hit = (c) => { const j = ser(c); for (const v of secrets) if (j.includes(v)) return true; return false; };
  assertNotVacuous(o); // on the whole corpus: the successes of a fn may all carry a secret and sit in the generated half
  const gen = Object.create(Object.getPrototypeOf(o));
  Object.assign(gen, o, { cases: o.cases.filter(hit) });
  Object.defineProperty(gen, 'vacuousChecked', { value: true });
  o.cases = o.cases.filter((c) => !gen.cases.includes(c));
  gen.about = o.about + ' (cases that carry a private key: generated in CI, never committed)';
  refWrite(o, pkg);
  refWrite(gen, pkg + '-gen');
}
/** base64url tokens of 20+ characters inside the text matched by `re` (group 1, or the whole match). */
export const tokensIn = (json, re) => {
  const out = [];
  for (const m of json.matchAll(re)) for (const t of (m[1] ?? m[0]).match(/[A-Za-z0-9_-]{20,}/g) ?? []) out.push(t);
  return out;
};
