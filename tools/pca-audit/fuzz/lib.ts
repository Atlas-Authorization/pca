/**
 * Structure-aware fuzzing library for the PCA audit program: deterministic PRNG, byte / text / JSON mutators, the
 * crash classifier, and the per-input harness (typed-error check, 1 s hang check, prototype-pollution check).
 *
 * Deliberately dependency-free (fast-check is used by the property tests, not by this coverage-less mutator) so a run
 * is bit-for-bit reproducible from `--seed`.
 */
export type Rng = () => number;

export function mulberry32(seed: number): Rng {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
export const ri = (r: Rng, n: number): number => Math.floor(r() * n);
export const pick = <T>(r: Rng, xs: readonly T[]): T => xs[ri(r, xs.length)]!;

export const INTERESTING_INTS = [0, 1, 2, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x10000, 0x7fffffff, 0x80000000, 0xffffffff];
export const LONG = (n: number, c = 'A'): string => c.repeat(n);

/** Adversarial JSON leaf values. Strings that survive JSON.stringify. */
export function adversarialValue(r: Rng): unknown {
  return pick(r, [
    null,
    true,
    false,
    0,
    -1,
    1,
    1.5,
    -0.0000001,
    2 ** 31,
    2 ** 32,
    2 ** 53 - 1,
    2 ** 53,
    1e21,
    1e308,
    5e-324,
    '',
    ' ',
    'A',
    '\u0000',
    '\ud800', // lone high surrogate (survives JSON.stringify as \ud800)
    '\udc00',
    'é',
    'é',
    '‮',
    '__proto__',
    'constructor',
    'prototype',
    'toString',
    '../../etc/passwd',
    '%00',
    '<script>',
    LONG(1000),
    LONG(70_000),
    'é'.repeat(300),
    [],
    {},
    [[]],
    [null],
    { __proto__: null },
    JSON.parse('{"__proto__":{"polluted":"yes"}}'),
    JSON.parse('{"constructor":{"prototype":{"polluted":"yes"}}}'),
    Array.from({ length: 200 }, () => 0),
    nest(r, 40),
    nest(r, 400),
  ]);
}
function nest(r: Rng, depth: number): unknown {
  let v: unknown = r() < 0.5 ? [] : {};
  for (let i = 0; i < depth; i++) v = r() < 0.5 ? [v] : { a: v };
  return v;
}

const isObj = (v: unknown): v is Record<string, unknown> | unknown[] => typeof v === 'object' && v !== null;

/** Collect every (container, key) location of a JSON value. */
function locations(root: unknown): Array<{ parent: Record<string, unknown> | unknown[]; key: string }> {
  const out: Array<{ parent: Record<string, unknown> | unknown[]; key: string }> = [];
  const seen = new Set<unknown>();
  const walk = (v: unknown, depth: number) => {
    if (!isObj(v) || seen.has(v) || depth > 12) return;
    seen.add(v);
    for (const k of Object.keys(v)) {
      out.push({ parent: v, key: k });
      walk((v as Record<string, unknown>)[k], depth + 1);
    }
  };
  walk(root, 0);
  return out;
}

export function cloneJson<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

/** One structure-aware mutation of a JSON value (returns a NEW value). */
export function mutateJson(r: Rng, root: unknown): unknown {
  const v = cloneJson(root);
  if (!isObj(v)) return adversarialValue(r);
  const locs = locations(v);
  if (locs.length === 0) return adversarialValue(r);
  const { parent, key } = pick(r, locs);
  const p = parent as Record<string, unknown>;
  switch (ri(r, 9)) {
    case 0: // delete
      if (Array.isArray(parent)) parent.splice(Number(key), 1);
      else delete p[key];
      break;
    case 1: // replace with adversarial
    case 2:
      p[key] = adversarialValue(r);
      break;
    case 3: { // type swap
      const cur = p[key];
      p[key] = typeof cur === 'string' ? Number(cur.length) : typeof cur === 'number' ? String(cur) : Array.isArray(cur) ? { ...cur } : isObj(cur) ? Object.values(cur) : cur === null ? '' : null;
      break;
    }
    case 4: { // mutate a string in place
      const cur = p[key];
      if (typeof cur === 'string' && cur.length > 0) {
        const i = ri(r, cur.length);
        const op = ri(r, 4);
        p[key] = op === 0 ? cur.slice(0, i) + cur.slice(i + 1) : op === 1 ? cur.slice(0, i) + pick(r, ['A', '=', '-', '_', '\u0000', '+', '/']) + cur.slice(i + 1) : op === 2 ? cur.slice(0, i) : cur + cur;
      } else p[key] = adversarialValue(r);
      break;
    }
    case 5: { // numeric nudge
      const cur = p[key];
      p[key] = typeof cur === 'number' ? pick(r, [cur + 1, cur - 1, -cur, cur * 2, 0, Number.MAX_SAFE_INTEGER]) : adversarialValue(r);
      break;
    }
    case 6: // add unknown / prototype-flavoured key
      p[pick(r, ['__proto__', 'constructor', 'prototype', 'extra', 'toString', 'hasOwnProperty', ''])] = adversarialValue(r);
      break;
    case 7: { // copy another location's value here
      const other = pick(r, locs);
      p[key] = cloneJson((other.parent as Record<string, unknown>)[other.key] ?? null);
      break;
    }
    default: // array element ops
      if (Array.isArray(parent)) {
        const i = Number(key);
        const op = ri(r, 3);
        if (op === 0) parent.push(parent[i]);
        else if (op === 1) parent.reverse();
        else parent.length = 0;
      } else p[key] = adversarialValue(r);
  }
  return v;
}

/** Byte-level mutation. */
export function mutateBytes(r: Rng, src: Uint8Array): Uint8Array {
  let b = Uint8Array.from(src);
  const n = 1 + ri(r, 3);
  for (let k = 0; k < n; k++) {
    const op = ri(r, 9);
    const i = b.length ? ri(r, b.length) : 0;
    switch (op) {
      case 0:
        if (b.length) b[i] = b[i]! ^ (1 << ri(r, 8));
        break;
      case 1:
        if (b.length) b[i] = pick(r, [0, 1, 0x7f, 0x80, 0xff]);
        break;
      case 2:
        if (b.length) b[i] = ri(r, 256);
        break;
      case 3: { // delete range
        const len = 1 + ri(r, Math.min(16, Math.max(1, b.length - i)));
        b = Uint8Array.from([...b.subarray(0, i), ...b.subarray(i + len)]);
        break;
      }
      case 4: { // insert random bytes
        const ins = Array.from({ length: 1 + ri(r, 8) }, () => ri(r, 256));
        b = Uint8Array.from([...b.subarray(0, i), ...ins, ...b.subarray(i)]);
        break;
      }
      case 5: // truncate
        b = b.slice(0, ri(r, b.length + 1));
        break;
      case 6: // extend with zeros / 0xff
        b = Uint8Array.from([...b, ...new Array(1 + ri(r, 64)).fill(r() < 0.5 ? 0 : 0xff)]);
        break;
      case 7: { // overwrite a LE/BE integer window with an interesting value
        const w = pick(r, [1, 2, 3, 4]);
        const val = pick(r, INTERESTING_INTS);
        const le = r() < 0.5;
        for (let j = 0; j < w && i + j < b.length; j++) b[i + j] = (val >>> (8 * (le ? j : w - 1 - j))) & 0xff;
        break;
      }
      default: { // duplicate a range
        const len = 1 + ri(r, Math.min(32, Math.max(1, b.length - i)));
        b = Uint8Array.from([...b.subarray(0, i + len), ...b.subarray(i, i + len), ...b.subarray(i + len)]);
      }
    }
  }
  return b;
}

const TEXT_TOKENS = [
  '\u0000', '\\u0000', '\\ud800', '\\udc00', '\\ud800\\udc00', '/*', '*/', '//', '\n', '\r', '\t', '﻿', ' ',
  '-0', '00', '01', '1.', '.5', '+1', '1e', '1e999', '-1e999', 'NaN', 'Infinity', '9007199254740993', '1E+2', '0.1e1',
  '"a":1,"a":2', '"__proto__":{"polluted":1}', '"constructor":{"prototype":{"polluted":1}}', ',', ',}', ',]', '[,]', '{,}',
  '\\', '\\x41', '\\u00', '\\uZZZZ', '"', "'", '{', '}', '[', ']', ':', 'null', 'true', 'false', 'tru', 'nul', '=',
];
export function mutateText(r: Rng, s: string): string {
  let t = s;
  const n = 1 + ri(r, 3);
  for (let k = 0; k < n; k++) {
    const i = t.length ? ri(r, t.length + 1) : 0;
    switch (ri(r, 8)) {
      case 7: // amplify: one character repeated many times (finds quadratic / super-linear scanners)
        t = t.slice(0, i) + pick(r, [' ', '\t', 'a', '0', '1', '"', '\\', '-', '.', ';', '(', ')', ',', '\n']).repeat(2000 + ri(r, 150_000)) + t.slice(i);
        break;
      case 0:
        t = t.slice(0, i) + pick(r, TEXT_TOKENS) + t.slice(i);
        break;
      case 1:
        t = t.slice(0, i) + t.slice(i + 1 + ri(r, 4));
        break;
      case 2:
        t = t.slice(0, i) + String.fromCharCode(ri(r, 0x300)) + t.slice(i + 1);
        break;
      case 3:
        t = t.slice(0, i);
        break;
      case 4:
        t = t + t.slice(0, ri(r, t.length + 1));
        break;
      case 5:
        t = t.slice(0, i) + (r() < 0.5 ? '['.repeat(1 + ri(r, 1200)) : '{"a":'.repeat(1 + ri(r, 600))) + t.slice(i);
        break;
      default: {
        const bytes = mutateBytes(r, new TextEncoder().encode(t));
        t = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      }
    }
  }
  return t;
}

// ---- classification --------------------------------------------------------------------------------------------

/** V8 / runtime-intrinsic error messages: a deliberate module check never reads like this. */
const ACCIDENTAL =
  /Cannot read propert|Cannot set propert|Cannot destructure|is not a function|is not iterable|is not a constructor|is not defined|undefined is not|null is not|Offset is outside the bounds|out of bounds|outside the bounds|Invalid typed array length|Invalid array length|Invalid string length|Maximum call stack|Cannot convert undefined or null|Cannot mix BigInt|Cannot convert a BigInt|Reduce of empty array|Invalid count value|Array buffer allocation failed|Invalid Date|ERR_OUT_OF_RANGE|The "[a-zA-Z]+" argument must be|ERR_INVALID_ARG|ERR_BUFFER|RangeError \[ERR|Unexpected token|Unexpected end of JSON|is not valid JSON|in JSON at position/;

export interface Verdict {
  kind: 'ok' | 'typed-throw' | 'accidental-throw' | 'property' | 'hang' | 'pollution';
  detail?: string;
  ms: number;
}

export type ThrowPolicy = (e: unknown) => boolean;

/** Allow only Errors a module raises on purpose: message starts with one of the given prefixes, or the class is named. */
export const typedBy =
  (opts: { prefixes?: string[]; names?: string[] }): ThrowPolicy =>
  (e) => {
    if (!(e instanceof Error)) return false;
    if (opts.names?.includes(e.name)) return true;
    const m = e.message;
    if (ACCIDENTAL.test(m) && !(opts.prefixes ?? []).some((p) => m.startsWith(p))) return false;
    return (opts.prefixes ?? []).some((p) => m.startsWith(p));
  };
export const neverThrows: ThrowPolicy = () => false;

const PROTOS: Array<[string, object]> = [
  ['Object.prototype', Object.prototype],
  ['Array.prototype', Array.prototype],
  ['Function.prototype', Function.prototype],
  ['String.prototype', String.prototype],
  ['Number.prototype', Number.prototype],
  ['Uint8Array.prototype', Uint8Array.prototype],
  ['Map.prototype', Map.prototype],
];
const BASELINE = new Map(PROTOS.map(([n, p]) => [n, Reflect.ownKeys(p).map(String).sort().join('|')]));

/** Returns a description if any shared prototype gained or lost an own property, or if a plain object inherits a surprise. */
export function pollutionCheck(): string | undefined {
  for (const [n, p] of PROTOS) {
    const now = Reflect.ownKeys(p).map(String).sort().join('|');
    if (now !== BASELINE.get(n)) return `${n} own keys changed`;
  }
  const probe = {} as Record<string, unknown>;
  if ('polluted' in probe || 'isAdmin' in probe || Object.getPrototypeOf(probe) !== Object.prototype) return 'plain-object inheritance changed';
  return undefined;
}

export const HANG_MS = 1000;

export async function exercise(
  fn: () => unknown,
  allow: ThrowPolicy,
  check?: (result: unknown) => string | undefined,
): Promise<Verdict> {
  const t0 = performance.now();
  let result: unknown;
  let thrown: unknown;
  let did = false;
  try {
    result = await fn();
  } catch (e) {
    thrown = e;
    did = true;
  }
  const ms = performance.now() - t0;
  const pol = pollutionCheck();
  if (pol) return { kind: 'pollution', detail: pol, ms };
  if (ms > HANG_MS) return { kind: 'hang', detail: `${ms.toFixed(0)} ms`, ms };
  if (did) {
    const msg = thrown instanceof Error ? `${thrown.name}: ${thrown.message}`.slice(0, 300) : `non-Error throw: ${String(thrown).slice(0, 100)}`;
    return allow(thrown) ? { kind: 'typed-throw', detail: msg, ms } : { kind: 'accidental-throw', detail: msg, ms };
  }
  const prop = check?.(result);
  if (prop) return { kind: 'property', detail: prop, ms };
  return { kind: 'ok', ms };
}

/**
 * Project `v` onto the key-shape of `base` (drop object keys `base` does not have, recursively). Used to separate
 * "verifier accepted a semantically different input" (a real finding) from "verifier ignores an unknown extra field"
 * (tolerated by design: the signed bytes are unchanged).
 */
export function projectOnto(base: unknown, v: unknown): unknown {
  if (Array.isArray(base) && Array.isArray(v)) return v.map((x, i) => projectOnto(base[i], x));
  if (base && v && typeof base === 'object' && typeof v === 'object' && !Array.isArray(base) && !Array.isArray(v)) {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(base as object)) if (Object.hasOwn(v as object, k)) out[k] = projectOnto((base as Record<string, unknown>)[k], (v as Record<string, unknown>)[k]);
    return out;
  }
  return v;
}

/** Path of the first difference between two JSON values (for finding messages). */
export function firstDiff(a: unknown, b: unknown, path = ''): string {
  if (JSON.stringify(a) === JSON.stringify(b)) return '';
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    for (const k of new Set([...Object.keys(a as object), ...Object.keys(b as object)])) {
      const d = firstDiff((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], `${path}/${k}`);
      if (d) return d;
    }
  }
  return `${path}: ${JSON.stringify(a)?.slice(0, 40)} -> ${JSON.stringify(b)?.slice(0, 40)}`;
}
