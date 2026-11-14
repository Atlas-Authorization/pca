// Shared helpers for the PCA 0.5 differential oracles (tools/pca-audit/k05-oracles/*-oracle.mts).
//
// Every oracle drives the TypeScript reference over a deterministic, boundary-heavy, mostly generated input space and writes
// tools/pca-audit/k05-oracles/out/k05-<module>.json.gz = {about, generator, count, cases: [{fn, name, args, out}]}:
//   fn    the reference function (each generator header names the native entry point for each fn)
//   name  unique case id (`fn/...`)
//   args  the positional arguments, as JSON (ser below: -0 survives as -0, an undefined argument / member is dropped,
//         an undefined array slot becomes null). Natives parse it with their lenient JSON reader (-0, 1.5, 2^53 intact).
//   out   exactly what the reference returned, as JSON (Uint8Array -> {"$bytes": b64url}); a throw is {"$throws": message, code?}.
// Run:  packages/pca/node_modules/tsx/dist/cli.mjs --tsconfig tools/pca-audit/k05-oracles/tsconfig.json tools/pca-audit/k05-oracles/<x>-oracle.mts
import fs from 'node:fs';
import zlib from 'node:zlib';
import { createHash } from 'node:crypto';

export const ROOT = new URL('../../../', import.meta.url).pathname;
export const OUT_DIR = new URL('./out/', import.meta.url).pathname;

/** Deterministic 32-byte seed (same derivation as the k042 oracles). */
export const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());

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
export function ser(v) {
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
    return { $throws: e instanceof Error ? e.message : String(e), ...(e && typeof e.code === 'string' ? { code: e.code } : {}) };
  }
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
  write(file = `k05-${this.module}.json.gz`) {
    fs.mkdirSync(OUT_DIR, { recursive: true });
    const body = '{"about":' + JSON.stringify(this.about) + ',"generator":' + JSON.stringify(this.generator) + ',"count":' + this.cases.length +
      ',"cases":[\n' + this.cases.map((c) => ser(c)).join(',\n') + '\n]}\n';
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
