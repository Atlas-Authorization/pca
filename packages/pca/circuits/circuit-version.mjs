// Circuit versioning. A circuit's version is the SHA-256 over its complete .circom source set (the circuit's own files,
// every file they include, circomlib files included by path) plus the pinned compiler. circuit-versions.json holds the
// committed values; `node circuits/circuit-version.mjs --write` regenerates them, no argument prints them.
// The compiled constraint system's own hash (r1cs sha256) is checked by the circuit CI job, which also asserts that two
// compilations give the same bytes (see scripts in the zk-circuits workflow).
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join, normalize } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

export const CIRCOM_VERSION = '2.2.2';
export const CIRCUITS = { 'pca-compliance-v1': 'compliance.circom', 'pca-policyvm-v1': 'policyvm.circom', 'pca-policyvm-v2': 'policyvm_bound.circom' };
const here = dirname(fileURLToPath(import.meta.url));
const sha = (b) => createHash('sha256').update(b).digest('hex');

export function circomlibDir() {
  const req = createRequire(join(here, '..', 'package.json'));
  return join(dirname(req.resolve('circomlib/package.json')), 'circuits');
}

/** Transitive include closure of `file` (relative to `dir`): { 'path': sha256 }, circomlib files keyed `circomlib/<path>`. */
export function sourceSet(file, dir = here, lib = circomlibDir()) {
  const out = {};
  const visit = (key, abs) => {
    if (out[key] !== undefined) return;
    const text = readFileSync(abs, 'utf8').replace(/\r\n/g, '\n');
    out[key] = sha(text);
    for (const m of text.matchAll(/^\s*include\s+"([^"]+)"\s*;/gm)) {
      const local = normalize(join(dirname(abs), m[1]));
      if (existsSync(local) && abs.startsWith(dir)) visit(local.slice(dir.length + 1), local);
      else {
        const l = normalize(join(abs.startsWith(lib) ? dirname(abs) : lib, m[1]));
        if (!existsSync(l)) throw new Error(`unresolved include ${m[1]} in ${key}`);
        visit(`circomlib/${l.slice(lib.length + 1)}`, l);
      }
    }
  };
  visit(file, join(dir, file));
  return out;
}

export function computeVersions(dir = here, lib = circomlibDir()) {
  const circuits = {};
  for (const [id, main] of Object.entries(CIRCUITS)) {
    const sources = sourceSet(main, dir, lib);
    const sorted = Object.keys(sources).sort();
    const source_sha256 = sha(`circom ${CIRCOM_VERSION}\n` + sorted.map((k) => `${k}\0${sources[k]}\n`).join(''));
    circuits[id] = { main, source_sha256, sources: Object.fromEntries(sorted.map((k) => [k, sources[k]])) };
  }
  return { version: 1, circom: CIRCOM_VERSION, circomlib: JSON.parse(readFileSync(join(lib, '..', 'package.json'), 'utf8')).version, circuits };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const v = JSON.stringify(computeVersions(), null, 2) + '\n';
  if (process.argv.includes('--write')) writeFileSync(join(here, 'circuit-versions.json'), v);
  else process.stdout.write(v);
}
