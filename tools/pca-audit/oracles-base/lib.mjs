// Shared helpers for the PCA 0.5 differential oracles (tools/pca-audit/oracles-base/*-oracle.mts).
//
// Every oracle drives the TypeScript reference over a deterministic, boundary-heavy, mostly generated input space and writes
// tools/pca-audit/oracles-base/out/base-<module>.json.gz = {about, generator, count, cases: [{fn, name, args, out}]}:
//   fn    the reference function (each generator header names the native entry point for each fn)
//   name  unique case id (`fn/...`)
//   args  the positional arguments, as JSON (ser below: -0 survives as -0, an undefined argument / member is dropped,
//         an undefined array slot becomes null). Natives parse it with their lenient JSON reader (-0, 1.5, 2^53 intact).
//   out   exactly what the reference returned, as JSON (Uint8Array -> {"$bytes": b64url}); a throw is {"$throws": message, code?}.
// Run:  packages/pca/node_modules/tsx/dist/cli.mjs --tsconfig tools/pca-audit/oracles-base/tsconfig.json tools/pca-audit/oracles-base/<x>-oracle.mts
import fs from 'node:fs';
import zlib from 'node:zlib';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
export const OUT_DIR = fileURLToPath(new URL('./out/', import.meta.url));

/** Deterministic 32-byte seed (same derivation as the k042 oracles). */
// PCA_SEED_LOG=<file>: append every label derived here (the strip tool resolves keys through the labels a generator really used).
export const seed = (l) => {
  if (process.env.PCA_SEED_LOG) fs.appendFileSync(process.env.PCA_SEED_LOG, JSON.stringify(String(l)) + '\n');
  return new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
};

/** mulberry32: the same seeded PRNG as packages/pca-actions/test/vectors-gen.ts. */
export function rng(s) {
  let a = s >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (lo, hi) => lo + Math.floor(next() * (hi - lo + 1));
  const pick = (xs) => xs[int(0, xs.length - 1)];
  const sub = (xs, max = xs.length) => xs.filter(() => next() < 0.35).slice(0, max);
  return { next, int, pick, sub };
}

const b64u = (u8) => Buffer.from(u8).toString('base64url');

/** JSON text that keeps -0 and drops undefined members (the k042 `ser`). Throws on NaN / Infinity / functions / bigint. */
export const ser = (v) => serX(v, false);
/** `,"clockMs":<n>`: the frozen clock the generator ran under (the shim's start, or the value a generator pinned Date.now to); empty without the shim. */
export const clockMember = () => (Number.isFinite(globalThis.__pcaOracleClockMs) ? `,"clockMs":${globalThis.__pcaOracleClockMs}` : '');

/** The corpus (wire) form of ser; with `on` (an Oracle sets utf16Escape), a string holding a lone surrogate is written as {"$utf16": [code units]}. */
export const serWire = (v, on = true) => serX(v, on);
// u16: write a string holding a lone surrogate as {"$utf16": [code units]} (the corpus form); false keeps plain JSON text, for parsing back into the reference's input
function serX(v, u16) {
  const ser = (x) => serX(x, u16);
  if (typeof v === 'number') {
    if (Object.is(v, -0)) return '-0';
    if (!Number.isFinite(v)) throw new Error('ser: non-finite number');
    return JSON.stringify(v);
  }
  if (v instanceof Uint8Array) return ser({ $bytes: b64u(v) });
  if (Array.isArray(v)) return '[' + v.map((x) => (x === undefined ? 'null' : ser(x))).join(',') + ']';
  if (v !== null && typeof v === 'object') {
    if (v instanceof Map || v instanceof Set) throw new Error('ser: Map/Set (convert first)');
    return '{' + Object.keys(v).filter((k) => v[k] !== undefined).map((k) => JSON.stringify(k) + ':' + ser(v[k])).join(',') + '}';
  }
  if (v === undefined || typeof v === 'function' || typeof v === 'bigint' || typeof v === 'symbol') throw new Error(`ser: ${typeof v}`);
  if (u16 && typeof v === 'string' && /[\ud800-\udfff]/.test(v) && !v.isWellFormed()) return JSON.stringify({ $utf16: Array.from({ length: v.length }, (_, i) => v.charCodeAt(i)) }); // lone surrogate: the code units, which every JSON reader can carry
  return JSON.stringify(v);
}
/** What a native sees after parsing: run the reference on this, never on the original object. */
export const reparse = (x) => JSON.parse(ser(x));
export const clone = (x) => JSON.parse(JSON.stringify(x));

/** Normalize a reference result to JSON (bytes -> {$bytes}; Map -> object; Set -> sorted array; undefined -> null). */
export function jsonOut(v) {
  if (v === undefined) return null;
  if (v instanceof Uint8Array) return { $bytes: b64u(v) };
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [String(k), jsonOut(x)]));
  if (v instanceof Set) return [...v].map(jsonOut).sort();
  if (Array.isArray(v)) return v.map(jsonOut);
  if (v !== null && typeof v === 'object') return Object.fromEntries(Object.keys(v).filter((k) => v[k] !== undefined && typeof v[k] !== 'function').map((k) => [k, jsonOut(v[k])]));
  if (typeof v === 'bigint') return { $bigint: v.toString() };
  if (typeof v === 'number' && !Number.isFinite(v)) return { $num: String(v) }; // NaN / Infinity / -Infinity
  return v;
}

/** Call fn(...args) and capture its JSON result or the thrown message (async results are awaited). */
export async function capture(fn, args) {
  try {
    return jsonOut(await fn(...args));
  } catch (e) {
    // `code`: ActionKitError / UndoError carry a stable code; natives compare it exactly; a throw without a code only requires the native to refuse
    const out = { $throws: e instanceof Error ? e.message : String(e), ...(e && typeof e.code === 'string' ? { code: e.code } : {}) };
    if (raisedByGenerator(e)) Object.defineProperty(out, RAISED_HERE, { value: true }); // not enumerable: never serialized
    return out;
  }
}

// ---- generator-bug guard --------------------------------------------------------------------------------------------
// A recorded throw must be a refusal of the reference. A throw the generator caused itself (an import whose exports sit
// under `default`, a misspelt name, arguments passed in the wrong shape, an unresolved module) makes a corpus that only a
// port that also throws can pass. Three checks run before any corpus is written (assertNoGeneratorBugs):
//   1. a throw captured by capture() whose text is a programming error AND whose innermost stack frame is generator code
//      (this directory tree), not the reference: `X.f is not a function` at the call site;
//   2. a module-resolution error anywhere;
//   3. a fn whose every case throws a programming-error text (the generator never reached the reference).
// The reference does throw such TypeErrors itself for wrong-typed input, in a minority of the cases of a fn: those pass.
// Opt out per generator, per pattern, when a real case needs it:  o.allowProgrammingErrors = [/reading 'x'/];
export const PROGRAMMING_ERROR = /is not a function|is not a constructor|is not defined|Cannot read propert|undefined is not|is not iterable|ERR_MODULE_NOT_FOUND|Cannot find module/;
const MODULE_ERROR = /ERR_MODULE_NOT_FOUND|Cannot find module/;
const RAISED_HERE = Symbol('raised by generator code');
const GENERATOR_TREE = fileURLToPath(new URL('../', import.meta.url));
function raisedByGenerator(e) {
  if (!(e instanceof Error) || typeof e.stack !== 'string' || !PROGRAMMING_ERROR.test(e.message)) return false;
  const frame = e.stack.split('\n').find((l) => /^\s+at /.test(l));
  return frame !== undefined && frame.includes(GENERATOR_TREE);
}
/** The generator-caused throws of an Oracle, as `case name: message (why)` lines; empty when the corpus is sound. */
export function generatorBugs(o) {
  const allowed = (m) => (o.allowProgrammingErrors ?? []).some((re) => re.test(m));
  const bugs = [];
  const byFn = new Map();
  for (const c of o.cases) {
    const m = c.out !== null && typeof c.out === 'object' && typeof c.out.$throws === 'string' ? c.out.$throws : undefined;
    const st = byFn.get(c.fn) ?? byFn.set(c.fn, { n: 0, prog: [] }).get(c.fn);
    st.n++;
    if (m === undefined || allowed(m)) continue;
    if (PROGRAMMING_ERROR.test(m)) st.prog.push(c);
    if (MODULE_ERROR.test(m)) bugs.push(`${c.name}: ${m} (module resolution)`);
    else if (c.out[RAISED_HERE]) bugs.push(`${c.name}: ${m} (raised in generator code, not by the reference)`);
  }
  for (const [fn, st] of byFn) if (st.n > 0 && st.prog.length === st.n) bugs.push(`${st.prog[0].name}: ${st.prog[0].out.$throws} (all ${st.n} cases of ${fn} throw a programming error)`);
  return bugs;
}
/** Refuse to write a corpus that records a generator bug as a reference result: print the cases and exit 1. */
export function assertNoGeneratorBugs(o) {
  const bugs = generatorBugs(o);
  if (bugs.length === 0) return;
  console.error(`REFUSED to write the ${o.module} corpus: ${bugs.length} recorded throw(s) come from the generator, not the reference:`);
  for (const b of bugs.slice(0, 20)) console.error('  ' + b);
  if (bugs.length > 20) console.error(`  ... and ${bugs.length - 20} more`);
  console.error('Fix the generator (for a namespace import of a .ts module: `const M = (M0 as any).default ?? M0`), or set o.allowProgrammingErrors = [/pattern/] for a throw the reference really makes.');
  process.exit(1);
}

// ---- vacuous-function guard -----------------------------------------------------------------------------------------
// A function whose every case records the same outcome, or only refusals, cannot tell a correct port from a stub (`return []`, `throw`).
// It is nearly always a generator mistake: an argument of the wrong shape, a fixture that never validates, a limit no input is under.
// Before a corpus is written, every fn with at least VACUOUS_MIN_CASES cases is checked for
//   - a single distinct outcome (the same value, or the same refusal text, in every case);
//   - no success case (every case is a throw, or a verdict {ok: false} / {valid: false}).
// A finding is a loud warning on stderr; with PCA_ORACLE_STRICT=1 (the corpus-regeneration checks of CI) it is fatal and nothing is written.
// A fn that is constant or refusal-only on purpose is declared, with the reason, by its generator:
//   o.constantByDesign = { checkSomething: 'a property check: it holds for every input' };
// Write an oracle in halves only through splitWrite: the check runs on the whole corpus (a fn's successes may all be in the generated half).
export const VACUOUS_MIN_CASES = 8;
const isRefusal = (out) => out !== null && typeof out === 'object' && !Array.isArray(out) && (typeof out.$throws === 'string' || out.ok === false || out.valid === false);
/** The vacuous fns of an Oracle, as {fn, cases, why, sample} rows; empty when every fn of 8+ cases has varied outcomes and a success. */
export function vacuousFns(o) {
  const optOut = o.constantByDesign ?? {};
  const byFn = new Map();
  for (const c of o.cases) {
    const st = byFn.get(c.fn) ?? byFn.set(c.fn, { n: 0, outs: new Set(), refusals: 0, first: c }).get(c.fn);
    st.n++;
    st.outs.add(ser(c.out));
    if (isRefusal(c.out)) st.refusals++;
  }
  const rows = [];
  for (const [fn, st] of byFn) {
    if (st.n < VACUOUS_MIN_CASES || (typeof optOut[fn] === 'string' && optOut[fn].length > 0)) continue;
    const why = st.outs.size === 1 ? 'a single distinct outcome' : st.refusals === st.n ? 'no success case (every case is a refusal)' : null;
    if (why) rows.push({ fn, cases: st.n, why, sample: [...st.outs][0].slice(0, 160) });
  }
  for (const fn of Object.keys(optOut)) if (!byFn.has(fn)) rows.push({ fn, cases: 0, why: 'declared constantByDesign but the corpus has no such fn', sample: '' });
  return rows;
}
/** Warn about vacuous fns (stderr); exit 1 without writing when PCA_ORACLE_STRICT=1. Runs once per Oracle. */
export function assertNotVacuous(o) {
  if (o.vacuousChecked) return;
  Object.defineProperty(o, 'vacuousChecked', { value: true, configurable: true });
  const rows = vacuousFns(o);
  if (rows.length === 0) return;
  const strict = process.env.PCA_ORACLE_STRICT === '1';
  console.error(`\n!!!! VACUOUS CORPUS (${o.module}): ${rows.length} fn(s) cannot tell a correct port from a stub${strict ? ' -- REFUSED (PCA_ORACLE_STRICT=1), nothing written' : ''}`);
  for (const r of rows) console.error(`!!!!   ${r.fn}: ${r.cases} cases, ${r.why}${r.sample ? `: ${r.sample}` : ''}`);
  console.error('!!!! Fix the generator (give the fn an input that succeeds and one per refusal branch), or declare it:  o.constantByDesign = { fn: \'why it is constant\' }\n');
  if (strict) process.exit(1);
}

/** The case collector. add() dedupes by name (a bug) and silently by (fn, args) (generated spaces overlap). */
export class Oracle {
  constructor(module, generator, about) {
    Object.assign(this, { module, generator, about, cases: [], names: new Set(), seen: new Set() });
  }
  add(fn, name, args, out) {
    const n = `${fn}/${name}`;
    if (this.names.has(n)) throw new Error('duplicate case ' + n);
    const key = fn + '\u0000' + ser(args);
    if (this.seen.has(key)) return false;
    this.names.add(n);
    this.seen.add(key);
    this.cases.push({ fn, name: n, args, out: out === undefined ? null : out });
    return true;
  }
  /** Run `ref` on the re-parsed args (an undefined argument becomes null on BOTH sides) and record the result. */
  async run(fn, name, ref, args) {
    const a = reparse(args);
    return this.add(fn, name, a, await capture(ref, a));
  }
  write(file = `base-${this.module}.json.gz`) {
    assertNoGeneratorBugs(this);
    assertNotVacuous(this);
    fs.mkdirSync(OUT_DIR, { recursive: true });
    const body = '{"about":' + JSON.stringify(this.about) + ',"generator":' + JSON.stringify(String(this.generator).split("/").pop()) + ',"count":' + this.cases.length + clockMember() +
      ',"cases":[\n' + this.cases.map((c) => serWire(c, this.utf16Escape === true)).join(',\n') + '\n]}\n';
    const gz = zlib.gzipSync(Buffer.from(body, 'utf8'), { level: 9, mtime: 0 });
    fs.writeFileSync(OUT_DIR + file, gz);
    const byFn = {};
    for (const c of this.cases) byFn[c.fn] = (byFn[c.fn] ?? 0) + 1;
    console.log(`wrote ${this.cases.length} cases (${(gz.length / 1024).toFixed(0)} KiB gz) to ${OUT_DIR + file}`);
    console.log('  by fn: ' + Object.entries(byFn).map(([k, v]) => `${k}=${v}`).join(' '));
    if (gz.length > 5 * 1024 * 1024) throw new Error('oracle over 5 MB: trim the generated space');
  }
}

// ---- structural mutation of a valid seed value ---------------------------------------------------------------------
// The hostile scalar palette: every JSON type, the integer boundaries natives get wrong (-0, 1.5, 2^53, 1e21), and
// strings natives mishandle (empty, lone surrogate written as a JS string, NFD, whitespace, very long).
export const HOSTILE = [
  null, true, false, 0, -0, 1, -1, 1.5, 2 ** 53, 2 ** 53 + 2, -(2 ** 53), 1e21, '', 'x', ' ', '\u0000', '\ud800', 'é', '1', '-0',
  [], [null], ['x'], {}, { x: 1 },
];

/** Every path (array of keys) to a node in v, root first; capped depth. */
export function paths(v, depth = 6, pre = []) {
  const out = [pre];
  if (depth === 0 || v === null || typeof v !== 'object') return out;
  for (const k of Array.isArray(v) ? v.keys() : Object.keys(v)) out.push(...paths(v[k], depth - 1, [...pre, k]));
  return out;
}
export const getAt = (v, p) => p.reduce((a, k) => (a == null ? undefined : a[k]), v);
/** A copy of v with the node at p replaced by f(old) (f returning DEL deletes a member / array slot). */
export const DEL = Symbol('del');
export function setAt(v, p, f) {
  if (p.length === 0) return f(v);
  const c = Array.isArray(v) ? [...v] : { ...v };
  const [k, ...rest] = p;
  const nv = setAt(v[k], rest, f);
  if (nv === DEL) {
    if (Array.isArray(c)) c.splice(k, 1);
    else delete c[k];
  } else c[k] = nv;
  return c;
}

/**
 * Generated structural variants of a valid `seedValue`: [label, variant] pairs. For each node: delete it, replace it with
 * every HOSTILE scalar, and the type-aware boundary edits (numbers ±1 / negated / fraction; strings emptied, repeated to
 * the given lengths, case-flipped; arrays emptied, first item duplicated, junk appended; objects given an unknown member
 * first and last). `opts.lens` = string lengths to try (limits ±1), `opts.maxPaths` caps the work.
 */
export function* variants(seedValue, opts = {}) {
  const lens = opts.lens ?? [];
  const ps = paths(seedValue, opts.depth ?? 6).slice(0, opts.maxPaths ?? 10_000);
  const palette = opts.hostile ?? HOSTILE;
  for (const p of ps) {
    const at = '/' + p.join('/');
    const old = getAt(seedValue, p);
    if (p.length) yield [`${at} deleted`, setAt(seedValue, p, () => DEL)];
    for (const [i, h] of palette.entries()) yield [`${at} = hostile#${i}`, setAt(seedValue, p, () => h)];
    if (typeof old === 'number') {
      for (const d of new Set([old + 1, old - 1, -old, old + 0.5, old * 2, 0])) yield [`${at} = ${d}`, setAt(seedValue, p, () => d)];
    } else if (typeof old === 'string') {
      for (const n of lens) yield [`${at} len ${n}`, setAt(seedValue, p, () => (old || 'a').repeat(Math.ceil(n / Math.max(1, old.length))).slice(0, n))];
      yield [`${at} upper`, setAt(seedValue, p, () => old.toUpperCase())];
      yield [`${at} + space`, setAt(seedValue, p, () => old + ' ')];
      yield [`${at} + lone surrogate`, setAt(seedValue, p, () => old + '\udc00')];
    } else if (Array.isArray(old)) {
      if (old.length) yield [`${at} dup first`, setAt(seedValue, p, () => [old[0], ...old])];
      if (old.length > 1) yield [`${at} reversed`, setAt(seedValue, p, () => [...old].reverse())];
      yield [`${at} + junk`, setAt(seedValue, p, () => [...old, 'junk'])];
    } else if (old !== null && typeof old === 'object') {
      yield [`${at} + unknown first`, setAt(seedValue, p, () => ({ zz_unknown: 1, ...old }))];
      yield [`${at} + unknown last`, setAt(seedValue, p, () => ({ ...old, zz_unknown: 1 }))];
    }
  }
}

/** Strings of exact UTF-16 / UTF-8 lengths around a limit: ascii n-1, n, n+1 and a multibyte string crossing n bytes. */
export const around = (n, ch = 'a') => [ch.repeat(Math.max(0, n - 1)), ch.repeat(n), ch.repeat(n + 1), ch.repeat(Math.max(0, n - 1)) + 'é'];
