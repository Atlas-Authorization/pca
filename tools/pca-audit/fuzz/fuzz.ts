/**
 * PCA fuzz driver. Usage (from repo root):
 *   packages/pca/node_modules/.bin/tsx tools/pca-audit/fuzz/fuzz.ts --target <substr|all> --ms 20000 --seed 1 [--list]
 *
 * For each selected target: mutate seeds for a bounded wall-clock budget; every input is classified (lib.ts). Anything
 * that is not `ok` or a typed throw is written to crashers/<target>/<hash>.json together with the verdict, and the
 * run exits non-zero. Inputs that are new `typed-throw` shapes are NOT stored (they are the expected rejections).
 */
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync, existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { exercise, mulberry32, type Rng, type Verdict } from './lib';
import { coreTargets, type Target } from './targets-core';
import { attestTargets } from './targets-attest';
import { ecosystemTargets } from './targets-ecosystem';

const wire = (v: unknown): unknown => JSON.parse(JSON.stringify(v ?? null));
const here = dirname(fileURLToPath(import.meta.url));
const arg = (n: string, d: string) => {
  const i = process.argv.indexOf(`--${n}`);
  return i >= 0 ? process.argv[i + 1]! : d;
};

export const allTargets = (): Target<any>[] => [...coreTargets(), ...attestTargets(), ...ecosystemTargets()];

export async function fuzzTarget(t: Target<any>, ms: number, seed: number, maxIter = Infinity) {
  const rng: Rng = mulberry32(seed);
  const seeds = t.seeds();
  const counts: Record<string, number> = {};
  const typed = new Map<string, number>();
  const found: Array<{ verdict: Verdict; input: unknown }> = [];
  const t0 = Date.now();
  let n = 0;
  // iteration 0..seeds: the unmutated seeds themselves (they must behave)
  const queue: unknown[] = [...seeds];
  while (Date.now() - t0 < ms && n < maxIter) {
    const raw = queue.length ? queue.shift()! : t.mutate(rng, seeds[Math.floor(rng() * seeds.length)], seeds);
    // Wire reality: verifiers only ever receive what JSON.parse (or raw bytes) can produce, so normalise through JSON
    // (drops `undefined`, array side-properties and other in-memory-only shapes a hostile network peer cannot send).
    const input = t.raw ? raw : wire(raw);
    n++;
    const v = await exercise(
      () => t.run(structuredClone(input)),
      t.allow,
      t.check ? (res) => t.check!(input, res) : undefined,
    );
    counts[v.kind] = (counts[v.kind] ?? 0) + 1;
    if (v.kind === 'typed-throw') typed.set(v.detail!.slice(0, 60), (typed.get(v.detail!.slice(0, 60)) ?? 0) + 1);
    if (v.kind !== 'ok' && v.kind !== 'typed-throw' && found.length < 25) found.push({ verdict: v, input });
  }
  return { n, counts, found, typed };
}

async function main() {
  const sel = arg('target', 'all');
  const ms = Number(arg('ms', '15000'));
  const seed = Number(arg('seed', '1'));
  const all = allTargets();
  if (process.argv.includes('--list')) {
    for (const t of all) console.log(t.name);
    return;
  }
  if (process.argv.includes('--regress')) {
    // Deterministic CI mode: replay committed crashers/ + a short fixed-seed fuzz of every target. Exit 1 on any finding.
    const n = Number(arg('iters', '150'));
    let fail = 0;
    const cdir = join(here, 'crashers');
    for (const t of all) {
      const r = await fuzzTarget(t, 600_000, seed, n);
      const dir = existsSync(cdir) ? readdirSync(cdir).filter((d) => t.name.replace(/[^a-z0-9]+/gi, '_').slice(0, 48) === d) : [];
      let replayed = 0;
      for (const d of dir) {
        for (const f of readdirSync(join(cdir, d)).filter((x) => x.endsWith('.json'))) {
          const rec = JSON.parse(readFileSync(join(cdir, d, f), 'utf8')) as { input: unknown };
          const v = await exercise(() => t.run(structuredClone(rec.input)), t.allow, t.check ? (res) => t.check!(rec.input, res) : undefined);
          replayed++;
          if (v.kind !== 'ok' && v.kind !== 'typed-throw') {
            fail++;
            console.log(`REGRESSION ${t.name} ${d}/${f}: ${v.kind} ${v.detail}`);
          }
        }
      }
      if (r.found.length) {
        fail++;
        for (const x of r.found) console.log(`FINDING ${t.name}: ${x.verdict.kind} ${x.verdict.detail}`);
      }
      console.log(`${r.found.length ? 'FAIL' : 'ok  '} ${t.name} :: ${r.n} inputs, ${replayed} crashers replayed`);
    }
    process.exitCode = fail ? 1 : 0;
    return;
  }
  const chosen = all.filter((t) => sel === 'all' || t.name.toLowerCase().includes(sel.toLowerCase()));
  let bad = 0;
  const summary: unknown[] = [];
  for (const t of chosen) {
    const r = await fuzzTarget(t, ms, seed);
    const status = r.found.length ? 'FINDINGS' : 'clean';
    console.log(`${status.padEnd(8)} ${t.name} :: ${r.n} inputs ${JSON.stringify(r.counts)}`);
    summary.push({ target: t.name, inputs: r.n, counts: r.counts, findings: r.found.length });
    for (const f of r.found) {
      bad++;
      const id = createHash('sha256').update(JSON.stringify(f.input)).digest('hex').slice(0, 12);
      const dir = join(process.env.PCA_FUZZ_OUT ?? join(here, 'crashers'), t.name.replace(/[^a-z0-9]+/gi, '_').slice(0, 48));
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, `${id}.json`), JSON.stringify({ target: t.name, verdict: f.verdict, input: f.input }));
      console.log(`   ${f.verdict.kind}: ${f.verdict.detail} -> ${id}`);
    }
  }
  if (process.env.PCA_FUZZ_SUMMARY) writeFileSync(process.env.PCA_FUZZ_SUMMARY, JSON.stringify(summary, null, 2));
  void existsSync;
  if (bad) process.exitCode = 1;
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) await main();
