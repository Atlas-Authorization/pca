// Oracle: every export of packages/pca/src/entropy.ts (QRNG sources, SP 800-90B continuous health tests, the HKDF entropy combiner, secureSeed,
// generateKeyPairWithEntropy), TS reference. Writes out/ref-entropy.json.gz. Deterministic: the local CSPRNG, every QRNG source and every HTTP
// transport are INJECTED by the case (the library has no network client in the natives: the HTTP source takes a transport callback).
// Case shape (as every sibling): {fn, name, args, out}; `out` is what the reference returned, or {"$throws": message, code?, ...}.
//
// ARGUMENT FORMS
//   {"$bytes": b64url}      literal bytes.   {"$num": "NaN" | "Infinity" | "-Infinity"}  a non-finite double (anywhere in args; plain JSON cannot carry it).
//   source spec (secureSeed / generateKeyPairWithEntropy `source`):  {"name": s, "kind": "bytes", "value": bytes}   fetch(n) resolves to `value` whatever n is
//        {"kind": "reject", "message": s}  rejects with an Error(message)    {"kind": "rejectString", "message": s}  rejects with a bare string (not an Error)
//        {"kind": "nonbytes"}  resolves to a string     {"kind": "throwSync", "message": s}  fetch throws synchronously (before returning a promise)
//        The native source interface is fetch(n) -> bytes | failure; `requests` in the output lists every n it was asked for.
//   local spec (`randomBytesImpl`): {"kind": "fixed", "value": bytes} returns `value` whatever n is; {"kind": "throw", "message": s}; {"kind": "nonbytes"}.
//        absent = the platform CSPRNG (only used by cases whose result does not depend on it).
//   hook ("onQrngError"): "none" (not passed) | "collect" (records) | "throw" (records, then throws: must be swallowed).
//   http transport (HttpQrngSource `fetchImpl`, injected): {"kind": "json", "status": n, "ok"?: bool, "body": any}  {"kind": "text", "status": n, "ok"?: bool, "text": s}
//        {"kind": "jsonThrows", "status": n} (json() rejects)  {"kind": "textThrows", "status": n}  {"kind": "throw", "message": s}  {"kind": "throwString", "message": s}
//        {"kind": "hang"} (never answers; rejects with an AbortError when the request's abort signal fires)  {"kind": "none"} (no fetch implementation at all).
//        ok defaults to 200 <= status <= 299.  The native transport receives (url, headers, redirect="error", abortSignal/timeout) and returns (ok, status, json-or-text).
//   http config: {url, apiKey?, apiKeyHeader?, format?, timeoutMs?, maxBytes?, lengthParam?, extraParams?, allowInsecureLoopback?, buildUrl?}  with
//        buildUrl = {"suffix": s} meaning (base, n) => base + "/" + n + s   (a custom URL builder; its output goes through the same transport checks).
// PORTING (fn(args) -> native entry point; results compared by JSON value; a reference throw means the native refuses; messages that start with
// "QRNG", "HttpQrngSource", "mixEntropy" or "secureSeed" are compared exactly, every other message (JS runtime text) is not):
//   constants []                                    -> {NAME: value}
//   repetitionCutoff [h] -> number   proportionCutoff [h, w] -> number            (IEEE doubles; compare the integer; non-finite results are {"$num"})
//   healthTestBytes [bytes, opts?] -> {ok, test?}   opts = {h?, window?}; bytes of any length (NOT limited to a window); a missing opts = {}
//   parseAnuUint8 [json] -> bytes   parseHex [text] -> bytes   parseBase64 [text] -> bytes      (parseBase64 is JS atob: the WHATWG forgiving-base64 decode, see below)
//   mixEntropy [local, quantum, opts?] -> bytes     opts = {length?, context?}
//   secureSeed [opts] -> {seed, usedQuantum, quantumByteCount, source, qrngErrors: [{cls, message, code?}], localRequested, requests}  (a throw is {"$throws", code?, cls})
//        cls is the error class: "EntropyError" | "RangeError" | "TypeError" | "Error"; qrngErrors are the arguments of onQrngError, in order (empty when the hook is none).
//   generateKeyPairWithEntropy [opts] -> {publicKey, secretKeySha256 (hex of sha256 of the 32-byte secret), usedQuantum}  (the secret itself is never in the corpus)
//   httpQrng [config, numBytes, transport] -> {name, bytes, requests: [{url, headers, redirect, signal}]} | {$throws, cls, code?, name?, requests, leaksKey}
//        a constructor failure has no name/requests (the source was never built); requests lists every transport call (url, headers as sent, redirect mode,
//        whether an abort signal was given); leaksKey = the apiKey text appears in the error message (must be false).
//   nullQrng [reason|null, numBytes] -> {name, $throws}      (null = argument not given)   unavailableSource [reason|null, numBytes] -> same
//   entropyError [code, message] -> {name, code, message, isError}
// Notes: parseBase64 follows atob (WHATWG forgiving-base64: strip nothing but test the regex first; a length of 1 mod 4 after removing up to two
// trailing "=" is invalid; non-canonical trailing bits are accepted and dropped); parseHex accepts upper and lower case; the HTTP URL is serialised by the WHATWG
// URL (host lower-cased, a bare host gets "/", query values form-urlencoded, existing params kept, the length param replaced).
import { createHash } from 'node:crypto';
import { Oracle, refWrite, rng, capture } from './lib.mjs';

const E0: any = await import('../../../packages/pca/src/entropy.ts');
const E: any = E0.default ?? E0;
const o = new Oracle('entropy', 'tools/pca-audit/oracles/entropy.mts', 'TS-reference oracle for packages/pca/src/entropy.ts (QRNG sources, SP 800-90B health tests, HKDF entropy mixing, secureSeed).');
const r = rng(0x0e170);
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const B = (u: Uint8Array) => ({ $bytes: b64(u) });
const bytes = (n: number) => Uint8Array.from({ length: n }, () => r.int(0, 255));
const un = (v: any): any => {
  if (Array.isArray(v)) return v.map(un);
  if (v !== null && typeof v === 'object') {
    const k = Object.keys(v);
    if (k.length === 1 && k[0] === '$bytes') return new Uint8Array(Buffer.from(v.$bytes, 'base64url'));
    if (k.length === 1 && k[0] === '$num') return { NaN, Infinity, '-Infinity': -Infinity }[v.$num as 'NaN'];
    return Object.fromEntries(Object.entries(v).map(([a, x]) => [a, un(x)]));
  }
  return v;
};
const NUM = (s: string) => ({ $num: s });
const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');
const sha256hex = (u: Uint8Array) => createHash('sha256').update(u).digest('hex');
async function add(fn: string, name: string, args: any[], call: (...a: any[]) => any) { o.add(fn, name, args, await capture(call, args.map(un))); }

// ---- constants
await add('constants', 'all', [], () => Object.fromEntries(['MAX_HKDF_OUTPUT', 'MIN_LOCAL_BYTES', 'DEFAULT_SEED_BYTES', 'DEFAULT_MAX_QRNG_BYTES', 'DEFAULT_TIMEOUT_MS'].map((n) => [n, E[n]])));

// ---- cutoffs
const HS: any[] = [1, 2, 3, 4, 5, 6, 7, 8, 1.5, 2.5, 7.5, 7.999, 0.5, 0.01, 9, 16, 0, -1, NUM('NaN'), NUM('Infinity'), NUM('-Infinity')];
for (const [i, h] of HS.entries()) await add('repetitionCutoff', `h${i}`, [h], E.repetitionCutoff);
for (const h of [1, 2, 4, 7, 8, 1.5, 3.5, 0.5]) for (const w of [2, 3, 16, 64, 100, 512, 1024]) await add('proportionCutoff', `h${h}-w${w}`, [h, w], E.proportionCutoff);
for (const [nm, h, w] of [['w0', 8, 0], ['w1', 8, 1], ['h0', 0, 16], ['hneg', -1, 16], ['hnan', NUM('NaN'), 16], ['h9', 9, 512], ['wneg', 8, -4], ['w4096', 8, 4096], ['h1-w4096', 1, 4096]] as [string, any, number][])
  await add('proportionCutoff', nm, [h, w], E.proportionCutoff);

// ---- health tests
const rc = (h: number) => E.repetitionCutoff(h), ac = (h: number, w: number) => E.proportionCutoff(h, w);
const filler = (i: number, v: number) => { let x = (i * 37 + 11) & 255; if (x === v) x = (x + 1) & 255; return x; };
/** one window of `w` bytes whose first byte is `v` and that carries exactly `count` copies of v (Bresenham spread) */
function windowWith(w: number, v: number, count: number): Uint8Array {
  const u = Uint8Array.from({ length: w }, (_, i) => filler(i, v));
  const pos = new Set<number>([0]);
  for (let j = 1; j < count; j++) pos.add(Math.floor((j * w) / count));
  for (const p of pos) u[p] = v;
  return u;
}
const ht = (name: string, buf: Uint8Array, opts?: any, expect?: string) => (async () => {
  const args = opts === undefined ? [B(buf)] : [B(buf), opts];
  const out = await capture(E.healthTestBytes, args.map(un));
  if (expect !== undefined) { const got = out.ok ? 'ok' : out.test; if (got !== expect) console.log(`MISMATCH healthTestBytes/${name}: intended ${expect}, reference says ${JSON.stringify(out)}`); }
  o.add('healthTestBytes', name, args, out);
})();
for (const n of [1, 2, 3, 16, 31, 64, 511, 512, 513, 1000, 1024, 1536]) await ht(`random-${n}`, bytes(n));
await ht('empty', new Uint8Array(), undefined, 'repetition-count');
await ht('empty-h4', new Uint8Array(), { h: 4 }, 'repetition-count');
for (const h of [1, 2, 4, 7, 8]) {
  const c = rc(h);
  for (const [nm, k] of [['below', c - 1], ['at', c], ['above', c + 3]] as [string, number][]) {
    const mk = (pos: string) => { const u = Uint8Array.from({ length: 64 }, (_, i) => filler(i, 200)); const at = pos === 'start' ? 0 : pos === 'mid' ? 30 : 64 - k; for (let j = 0; j < k && at + j < 64; j++) u[at + j] = 200; return u; };
    const expected = k >= c ? 'repetition-count' : undefined;
    for (const pos of ['start', 'mid', 'end']) await ht(`run-h${h}-${nm}-${pos}`, mk(pos), { h }, expected ?? 'ok');
  }
}
{ const u = new Uint8Array(40); await ht('zeros-40', u, undefined, 'repetition-count'); await ht('zeros-3', new Uint8Array(3), undefined, 'adaptive-proportion'); await ht('zeros-4', new Uint8Array(4), undefined, 'repetition-count'); }
{ await ht('two-then-run', Uint8Array.from([5, 5, 5, 9, 9, 9, 9]), undefined, 'repetition-count'); await ht('runs-of-3', Uint8Array.from([5, 5, 5, 9, 9, 9, 5, 5, 5, 1]), undefined, 'adaptive-proportion'); }
// adaptive proportion
for (const [h, w] of [[8, 512], [8, 64], [4, 512], [2, 128], [1, 512], [1, 64], [6, 100], [8, 2], [8, 3]] as [number, number][]) {
  const c = ac(h, w);
  const okCount = Math.max(1, c - 1);
  // the repetition test must not trip first: keep runs below its cutoff by construction (Bresenham spread) and verify through the expected verdict
  await ht(`apt-h${h}-w${w}-below`, windowWith(w, 77, okCount), { h, window: w }, 'ok');
  if (c <= w) await ht(`apt-h${h}-w${w}-at`, windowWith(w, 77, c), { h, window: w }, c >= w && h <= 2 ? undefined : 'adaptive-proportion');
}
{ // the first byte of EACH window is the sample; the second window trips, the first does not
  const w = 64, c = ac(8, w); const a = windowWith(w, 10, 1), b = windowWith(w, 20, c); await ht('apt-second-window', new Uint8Array([...a, ...b]), { h: 8, window: w }, 'adaptive-proportion');
  const d = windowWith(w, 20, 1); await ht('apt-partial-tail-ignored', new Uint8Array([...a, ...d, ...windowWith(w, 30, c).subarray(0, 40)]), { h: 8, window: w }, 'ok'); }
for (const n of [100, 300, 512, 700, 1100]) await ht(`window-default-len${n}`, bytes(n), {});
await ht('window-larger-than-buffer', bytes(100), { window: 4096 });
await ht('window-2', bytes(50), { window: 2 }); await ht('window-3', bytes(60), { window: 3 });
for (const [nm, op] of [['h0', { h: 0 }], ['h-1', { h: -1 }], ['h9', { h: 9 }], ['h0.99', { h: 0.99 }], ['h1.0', { h: 1 }], ['h8.0', { h: 8 }], ['hnan', { h: NUM('NaN') }], ['hinf', { h: NUM('Infinity') }], ['h-frac', { h: 3.5 }],
  ['w1', { window: 1 }], ['w0', { window: 0 }], ['w-5', { window: -5 }], ['w2.5', { window: 2.5 }], ['wnan', { window: NUM('NaN') }], ['winf', { window: NUM('Infinity') }], ['wbig', { window: 4294967296 }], ['both-bad', { h: 0, window: 1 }]] as [string, any][])
  await ht(`opts-${nm}`, bytes(64), op);
await add('healthTestBytes', 'null-bytes', [null], E.healthTestBytes);
await add('healthTestBytes', 'null-opts', [B(bytes(8)), null], E.healthTestBytes);

// ---- parsers
const ANU = [
  ['ok', { success: true, data: [0, 1, 2, 255] }], ['no-success', { data: [9, 8, 7] }], ['empty', { data: [] }], ['extra-keys', { data: [1], type: 'uint8', length: 1, other: [1, 2] }],
  ['success-false', { success: false, data: [1] }], ['success-string', { success: 'true', data: [1] }], ['success-1', { success: 1, data: [1] }], ['success-null', { success: null, data: [1] }],
  ['no-data', { success: true }], ['data-null', { data: null }], ['data-object', { data: { 0: 1 } }], ['data-string', { data: '010203' }], ['elem-256', { data: [1, 256] }], ['elem-neg', { data: [-1] }],
  ['elem-frac', { data: [1.5] }], ['elem-string', { data: ['1'] }], ['elem-null', { data: [null] }], ['elem-bool', { data: [true] }], ['elem-array', { data: [[1]] }], ['elem-big', { data: [1e3] }],
  ['elem-float-int', { data: [1.0, 2.0] }], ['elem-exp', { data: [2e0] }], ['elem-neg-zero', { data: [-0] }], ['all-255', { data: Array(40).fill(255) }], ['long', { data: Array.from({ length: 700 }, (_, i) => (i * 7) & 255) }],
  ['array-body', [1, 2, 3]], ['string-body', 'abc'], ['number-body', 7], ['null-body', null], ['bool-body', true], ['empty-object', {}],
] as [string, any][];
for (const [nm, v] of ANU) await add('parseAnuUint8', nm, [v], E.parseAnuUint8);
const HEXES = ['', '00', 'ff', 'FF', 'aA', '0123456789abcdefABCDEF', 'abc', 'a', 'zz', 'g0', '0x00', ' 00', '00 ', '0 0', '00\n', '٠١', 'ａｂ', '-1', 'ab'.repeat(300), 'ABCDEF'.repeat(5), 'éé'];
for (const [i, t] of HEXES.entries()) await add('parseHex', `h${i}`, [t], E.parseHex);
await add('parseHex', 'null', [null], E.parseHex); await add('parseHex', 'number', [12], E.parseHex);
const B64S = ['', 'AAAA', 'AA==', 'AA=', 'AA', 'A', 'AAA', 'AAAAA', 'AAAAAA', 'AAAAAAA', '=', '==', '===', 'A===', 'AAAA=', 'AAAA==', 'AB==', 'AC==', 'AQ==', 'AR==', 'ABC=', 'ABD=', 'AB=', '+/+/', '+/8=', '-_8=', 'Zm9v', 'Zm9vYg==', 'Zm9vYg=', 'Zm9vYg', 'Zm9vYmE=', 'Zm9vYmE', 'Zm9vYmFy', 'AA==AA==', 'AA==A', 'A=A=', 'AAAA AAAA', 'AAAA\nAAAA', ' AAAA', 'AAAA ', 'éééé', 'AAA*', 'QUJD', 'QUJDRA==', 'QUJDRA=', 'QUJDRA', 'QUJDRAA=', 'x'.repeat(1024), 'AA'.repeat(700) + '==', Buffer.from(bytes(300)).toString('base64')];
for (const [i, t] of B64S.entries()) await add('parseBase64', `b${i}`, [t], E.parseBase64);
await add('parseBase64', 'null', [null], E.parseBase64); await add('parseBase64', 'number', [12], E.parseBase64);

// ---- mixEntropy
{
  const L = (n: number) => bytes(n), Q = (n: number) => bytes(n);
  const lens = [16, 17, 32, 33, 64, 100];
  for (const ln of lens) for (const qn of [0, 1, 32, 100]) await add('mixEntropy', `l${ln}-q${qn}`, [B(L(ln)), B(Q(qn))], E.mixEntropy);
  const l = L(32), q = Q(48);
  for (const len of [1, 2, 31, 32, 33, 64, 255, 256, 1000, 8160]) await add('mixEntropy', `len${len}`, [B(l), B(q), { length: len }], E.mixEntropy);
  for (const len of [0, -1, 8161, 8192, 1.5, NUM('NaN'), NUM('Infinity'), NUM('-Infinity'), 4294967296, '32', null]) await add('mixEntropy', `len-bad-${typeof len === 'object' && len ? JSON.stringify(len) : String(len)}`, [B(l), B(q), { length: len }], E.mixEntropy);
  for (const [nm, ctx] of [['empty', ''], ['x', 'x'], ['ascii', 'ed25519-key'], ['slash', 'a/b'], ['unicode', 'clé 中文'], ['emoji', '\u{1F511}'], ['long', 'c'.repeat(300)], ['nul', 'a\u0000b'], ['lone-surrogate', '\ud800'], ['bmp-edge', '￿']] as [string, string][])
    await add('mixEntropy', `ctx-${nm}`, [B(l), B(q), { context: ctx }], E.mixEntropy);
  await add('mixEntropy', 'ctx-null', [B(l), B(q), { context: null }], E.mixEntropy);
  await add('mixEntropy', 'ctx-number', [B(l), B(q), { context: 5 }], E.mixEntropy);
  await add('mixEntropy', 'len+ctx', [B(l), B(q), { length: 48, context: 'k' }], E.mixEntropy);
  await add('mixEntropy', 'opts-empty', [B(l), B(q), {}], E.mixEntropy);
  await add('mixEntropy', 'opts-absent', [B(l), B(q)], E.mixEntropy);
  // length framing: (local, quantum) pairs with the same concatenation must differ
  await add('mixEntropy', 'frame-a', [B(new Uint8Array(16).fill(1)), B(new Uint8Array(16).fill(1))], E.mixEntropy);
  await add('mixEntropy', 'frame-b', [B(new Uint8Array(20).fill(1)), B(new Uint8Array(12).fill(1))], E.mixEntropy);
  await add('mixEntropy', 'all-zero', [B(new Uint8Array(16)), B(new Uint8Array(0))], E.mixEntropy);
  await add('mixEntropy', 'all-ff', [B(new Uint8Array(16).fill(255)), B(new Uint8Array(64).fill(255))], E.mixEntropy);
  for (const n of [0, 1, 15]) await add('mixEntropy', `local-short-${n}`, [B(L(n)), B(Q(8))], E.mixEntropy);
  await add('mixEntropy', 'local-string', ['abcdefghijklmnopqrstuvwx', B(Q(8))], E.mixEntropy);
  await add('mixEntropy', 'quantum-string', [B(l), 'abc'], E.mixEntropy);
  await add('mixEntropy', 'quantum-null', [B(l), null], E.mixEntropy);
  await add('mixEntropy', 'local-null', [null, B(q)], E.mixEntropy);
}

// ---- secureSeed / generateKeyPairWithEntropy
interface Req { requests: number[] }
const buildSource = (spec: any, log: number[]): any => {
  if (!spec) return spec;
  const name = spec.name ?? 'test-src';
  return {
    name,
    fetch(n: number) {
      log.push(n);
      switch (spec.kind) {
        case 'bytes': return Promise.resolve(un(spec.value));
        case 'reject': return Promise.reject(new Error(spec.message));
        case 'rejectString': return Promise.reject(spec.message);
        case 'nonbytes': return Promise.resolve('not-bytes');
        case 'throwSync': throw new Error(spec.message);
        default: throw new Error('bad source spec');
      }
    },
  };
};
const buildLocal = (spec: any, log: number[]) => (n: number) => {
  log.push(n);
  if (spec.kind === 'fixed') return un(spec.value);
  if (spec.kind === 'throw') throw new Error(spec.message);
  return 'nonbytes' as any;
};
const errRec = (e: any) => ({ cls: e instanceof Error ? e.constructor.name : typeof e, message: e instanceof Error ? e.message : String(e), ...(e && typeof e.code === 'string' ? { code: e.code } : {}) });
async function seedRun(opts: any, withKeypair = false) {
  const reqs: number[] = [], locals: number[] = [], errs: any[] = [];
  const real: any = { ...un(opts) };
  delete real.hook; delete real.local;
  if (opts.source) real.source = buildSource(opts.source, reqs);
  if (opts.local) real.randomBytesImpl = buildLocal(opts.local, locals);
  const hook = opts.hook ?? 'none';
  if (hook !== 'none') real.onQrngError = (e: any) => { errs.push(errRec(e)); if (hook === 'throw') throw new Error('hook boom'); };
  if (opts.source === null) real.source = null;
  try {
    const res = withKeypair ? await E.generateKeyPairWithEntropy(real) : await E.secureSeed(real);
    if (withKeypair) return { publicKey: res.publicKey, secretKeySha256: sha256hex(res.secretKey), usedQuantum: res.usedQuantum, qrngErrors: errs, localRequested: locals[0] ?? null, requests: reqs };
    return { seed: res.seed, usedQuantum: res.usedQuantum, quantumByteCount: res.quantumByteCount, source: res.source, qrngErrors: errs, localRequested: locals[0] ?? null, requests: reqs };
  } catch (e: any) {
    return { $throws: e.message, cls: e.constructor.name, ...(typeof e.code === 'string' ? { code: e.code } : {}), qrngErrors: errs, localRequested: locals[0] ?? null, requests: reqs };
  }
}
const addSeed = async (name: string, opts: any, kp = false) => { o.add(kp ? 'generateKeyPairWithEntropy' : 'secureSeed', name, [opts], await seedRun(opts, kp)); };
const FX = (u: Uint8Array) => ({ kind: 'fixed', value: B(u) });
const QS = (u: Uint8Array, name = 'q-src') => ({ name, kind: 'bytes', value: B(u) });
const loc = (n: number) => bytes(n);
{
  const l32 = loc(32), q32 = bytes(32);
  await addSeed('no-source', { local: FX(l32) });
  await addSeed('no-source-null', { local: FX(l32), source: null });
  await addSeed('quantum-ok', { local: FX(l32), source: QS(q32) });
  await addSeed('quantum-ok-len64', { length: 64, local: FX(loc(64)), source: QS(bytes(64)) });
  await addSeed('quantum-ok-len16', { length: 16, local: FX(loc(32)), source: QS(bytes(32)) });
  await addSeed('quantum-ok-len1', { length: 1, local: FX(loc(32)), source: QS(bytes(32)) });
  await addSeed('quantum-ok-len8160', { length: 8160, local: FX(loc(8160)), source: QS(bytes(8160)) });
  await addSeed('context', { context: 'wallet', local: FX(l32), source: QS(q32) });
  await addSeed('context-empty', { context: '', local: FX(l32), source: QS(q32) });
  await addSeed('localBytes-16', { localBytes: 16, local: FX(loc(16)), source: QS(q32) });
  await addSeed('localBytes-100', { localBytes: 100, length: 32, local: FX(loc(100)), source: QS(q32) });
  await addSeed('quantumBytes-8', { quantumBytes: 8, local: FX(l32), source: QS(bytes(8)) });
  await addSeed('quantumBytes-1', { quantumBytes: 1, local: FX(l32), source: QS(bytes(1)), healthTest: false });
  await addSeed('quantumBytes-100', { quantumBytes: 100, local: FX(l32), source: QS(bytes(100)) });
  await addSeed('defaults-from-length-64', { length: 64, local: FX(loc(64)), source: QS(bytes(64)) });
  await addSeed('requests-recorded', { length: 40, localBytes: 20, quantumBytes: 50, local: FX(loc(20)), source: QS(bytes(50)) });
  // fallback paths (source fails: seed is mix(local, empty), usedQuantum false, error reported)
  await addSeed('fb-reject', { local: FX(l32), source: { name: 'bad', kind: 'reject', message: 'boom' }, hook: 'collect' });
  await addSeed('fb-reject-nohook', { local: FX(l32), source: { name: 'bad', kind: 'reject', message: 'boom' } });
  await addSeed('fb-reject-hook-throws', { local: FX(l32), source: { name: 'bad', kind: 'reject', message: 'boom' }, hook: 'throw' });
  await addSeed('fb-reject-string', { local: FX(l32), source: { name: 'bad', kind: 'rejectString', message: 'plain' }, hook: 'collect' });
  await addSeed('fb-throw-sync', { local: FX(l32), source: { name: 'bad', kind: 'throwSync', message: 'sync' }, hook: 'collect' });
  await addSeed('fb-nonbytes', { local: FX(l32), source: { name: 'bad', kind: 'nonbytes' }, hook: 'collect' });
  await addSeed('fb-short', { local: FX(l32), source: QS(bytes(31), 'short'), hook: 'collect' });
  await addSeed('fb-long', { local: FX(l32), source: QS(bytes(33), 'long'), hook: 'collect' });
  await addSeed('fb-empty', { local: FX(l32), source: QS(new Uint8Array(0), 'empty'), hook: 'collect' });
  await addSeed('fb-health-constant', { local: FX(l32), source: QS(new Uint8Array(32), 'zeros'), hook: 'collect' });
  await addSeed('fb-health-run4', { local: FX(l32), source: QS(Uint8Array.from([1, 2, 3, 9, 9, 9, 9, ...bytes(25)]), 'run'), hook: 'collect' });
  await addSeed('health-run3-ok', { local: FX(l32), source: QS(Uint8Array.from([1, 2, 3, 9, 9, 9, 4, ...bytes(25).map((x) => (x === 9 ? 10 : x))]), 'run3') });
  await addSeed('health-off-constant-used', { local: FX(l32), source: QS(new Uint8Array(32), 'zeros'), healthTest: false });
  await addSeed('health-h4-run6', { local: FX(l32), source: QS(Uint8Array.from([5, 5, 5, 5, 5, 5, ...bytes(26).map((x) => (x === 5 ? 6 : x))]), 'h4'), healthTest: { h: 4 }, hook: 'collect' });
  await addSeed('health-h4-run5-ok', { local: FX(l32), source: QS(Uint8Array.from([5, 5, 5, 5, 5, 7, ...bytes(26).map((x) => (x === 5 ? 6 : x))]), 'h4ok'), healthTest: { h: 4 } });
  await addSeed('health-bad-h', { local: FX(l32), source: QS(q32, 'badh'), healthTest: { h: 0 }, hook: 'collect' });
  await addSeed('health-bad-window', { local: FX(l32), source: QS(q32, 'badw'), healthTest: { window: 1 }, hook: 'collect' });
  await addSeed('health-window-8', { local: FX(l32), source: QS(q32, 'w8'), healthTest: { window: 8 } });
  // requireQuantum
  await addSeed('require-ok', { local: FX(l32), source: QS(q32), requireQuantum: true });
  await addSeed('require-no-source', { local: FX(l32), requireQuantum: true });
  await addSeed('require-no-source-default-csprng', { requireQuantum: true });
  await addSeed('require-source-fails', { local: FX(l32), source: { name: 'bad', kind: 'reject', message: 'boom' }, requireQuantum: true, hook: 'collect' });
  await addSeed('require-health-fails', { local: FX(l32), source: QS(new Uint8Array(32), 'zeros'), requireQuantum: true, hook: 'collect' });
  await addSeed('require-false', { local: FX(l32), requireQuantum: false });
  await addSeed('require-truthy-nonbool', { local: FX(l32), requireQuantum: 1 });
  // configuration errors (thrown before any source use)
  for (const [nm, op] of [['len0', { length: 0 }], ['len-1', { length: -1 }], ['len8161', { length: 8161 }], ['len1.5', { length: 1.5 }], ['lennan', { length: NUM('NaN') }], ['leninf', { length: NUM('Infinity') }], ['lenstr', { length: '32' }],
    ['local15', { localBytes: 15 }], ['local1.5', { localBytes: 16.5 }], ['local0', { localBytes: 0 }], ['localneg', { localBytes: -1 }], ['localnan', { localBytes: NUM('NaN') }],
    ['q0', { quantumBytes: 0 }], ['qneg', { quantumBytes: -3 }], ['q1.5', { quantumBytes: 1.5 }], ['qnan', { quantumBytes: NUM('NaN') }], ['qinf', { quantumBytes: NUM('Infinity') }]] as [string, any][])
    await addSeed(`cfg-${nm}`, { local: FX(l32), source: QS(q32), ...op });
  // local CSPRNG misbehaviour (the trust anchor: fail closed)
  await addSeed('local-short', { local: FX(loc(31)) });
  await addSeed('local-long', { local: FX(loc(33)), source: QS(q32) });
  await addSeed('local-nonbytes', { local: { kind: 'nonbytes' } });
  await addSeed('local-throws', { local: { kind: 'throw', message: 'rng down' } });
  await addSeed('local-short-with-source', { local: FX(loc(10)), source: QS(q32) });
  // the quantum bytes never replace the local bytes: same local, different quantum -> different seed; adversarial quantum still mixes local
  await addSeed('adversarial-constant-quantum', { local: FX(l32), source: QS(new Uint8Array(32).fill(0xaa), 'const'), healthTest: false });
  // keypair
  await addSeed('kp-no-source', { local: FX(l32) }, true);
  await addSeed('kp-quantum', { local: FX(l32), source: QS(q32) }, true);
  await addSeed('kp-context', { local: FX(l32), source: QS(q32), context: 'custom' }, true);
  await addSeed('kp-context-empty', { local: FX(l32), source: QS(q32), context: '' }, true);
  await addSeed('kp-length-ignored', { length: 64, local: FX(l32), source: QS(q32) }, true);
  await addSeed('kp-fallback', { local: FX(l32), source: { name: 'bad', kind: 'reject', message: 'boom' }, hook: 'collect' }, true);
  await addSeed('kp-require-fails', { local: FX(l32), requireQuantum: true }, true);
  await addSeed('kp-require-ok', { local: FX(l32), source: QS(q32), requireQuantum: true }, true);
  await addSeed('kp-local-short', { local: FX(loc(31)) }, true);
  await addSeed('kp-localBytes-16', { localBytes: 16, local: FX(loc(16)), source: QS(q32) }, true);
  await addSeed('kp-localBytes-15', { localBytes: 15, local: FX(loc(15)) }, true);
}

// ---- null source, unavailableSource, EntropyError
for (const [nm, args] of [['default', [null, 16]], ['reason', ['offline', 16]], ['empty-reason', ['', 16]], ['n0', [null, 0]], ['unicode', ['héllo', 1]]] as [string, any[]][]) {
  for (const fn of ['nullQrng', 'unavailableSource']) {
    const [reason, n] = args;
    const src = reason === null ? (fn === 'nullQrng' ? new E.NullQrngSource() : E.unavailableSource()) : (fn === 'nullQrng' ? new E.NullQrngSource(reason) : E.unavailableSource(reason));
    let out: any; try { await src.fetch(n); out = { name: src.name, ok: true }; } catch (e: any) { out = { name: src.name, $throws: e.message }; }
    o.add(fn, nm, args, out);
  }
}
for (const [nm, code, msg] of [['a', 'quantum_required', 'm'], ['b', 'health_test_failed', ''], ['c', 'insecure_transport', 'x y'], ['d', 'anything', 'z']] as [string, string, string][]) {
  const e = new E.EntropyError(code, msg);
  o.add('entropyError', nm, [code, msg], { name: e.name, code: e.code, message: e.message, isError: e instanceof Error });
}

// ---- HttpQrngSource (transport injected)
function transportOf(spec: any, log: any[]): any {
  if (spec.kind === 'none') return undefined;
  return (url: string, init: any) => {
    log.push({ url, headers: init?.headers ?? null, redirect: init?.redirect ?? null, signal: init?.signal !== undefined });
    const status = spec.status ?? 200, okv = spec.ok ?? (status >= 200 && status <= 299);
    switch (spec.kind) {
      case 'json': return Promise.resolve({ ok: okv, status, json: async () => spec.body, text: async () => { throw new Error('text unused'); } });
      case 'text': return Promise.resolve({ ok: okv, status, json: async () => { throw new Error('json unused'); }, text: async () => spec.text });
      case 'jsonThrows': return Promise.resolve({ ok: okv, status, json: async () => { throw new SyntaxError('bad json'); }, text: async () => '' });
      case 'textThrows': return Promise.resolve({ ok: okv, status, json: async () => ({}), text: async () => { throw new Error('read failed'); } });
      case 'throw': return Promise.reject(new Error(spec.message));
      case 'throwString': return Promise.reject(spec.message);
      case 'hang': return new Promise((_, rej) => { init.signal.addEventListener('abort', () => { const e = new Error('The operation was aborted'); e.name = 'AbortError'; rej(e); }); });
      default: throw new Error('bad transport spec');
    }
  };
}
async function httpRun(cfg: any, n: any, tr: any) {
  const log: any[] = [];
  const real: any = un(cfg);
  if (cfg.buildUrl) real.buildUrl = (base: string, k: number) => `${base}/${k}${cfg.buildUrl.suffix}`;
  const fi = transportOf(tr, log);
  if (fi) real.fetchImpl = fi; else real.fetchImpl = undefined;
  const g: any = globalThis; const savedFetch = g.fetch; if (tr.kind === 'none') g.fetch = undefined;
  let src: any;
  try { src = new E.HttpQrngSource(real); } catch (e: any) { g.fetch = savedFetch; return { $throws: e.message, cls: e.constructor.name, ...(typeof e.code === 'string' ? { code: e.code } : {}) }; }
  try {
    const b = await src.fetch(un(n));
    return { name: src.name, bytes: b, requests: log };
  } catch (e: any) {
    const apiKey = real.apiKey;
    return { $throws: e.message, cls: e.constructor.name, ...(typeof e.code === 'string' ? { code: e.code } : {}), name: src.name, requests: log, leaksKey: !!apiKey && e.message.includes(apiKey) };
  } finally { g.fetch = savedFetch; }
}
const hq = async (name: string, cfg: any, n: any, tr: any) => o.add('httpQrng', name, [cfg, n, tr], await httpRun(cfg, n, tr));
{
  const U = 'https://qrng.example/api';
  const jb = (u: Uint8Array) => ({ kind: 'json', status: 200, body: { success: true, data: [...u] } });
  const four = Uint8Array.from([1, 2, 3, 4]);
  await hq('ok-default', { url: U }, 4, jb(four));
  await hq('ok-no-success', { url: U }, 4, { kind: 'json', status: 200, body: { data: [...four] } });
  await hq('ok-key-default-header', { url: U, apiKey: 'sekret-1' }, 4, jb(four));
  await hq('ok-key-custom-header', { url: U, apiKey: 'sekret-1', apiKeyHeader: 'Authorization' }, 4, jb(four));
  await hq('ok-key-empty', { url: U, apiKey: '' }, 4, jb(four));
  await hq('ok-hex', { url: U, format: 'hex' }, 4, { kind: 'text', status: 200, text: '  01020304\n' });
  await hq('ok-hex-upper', { url: U, format: 'hex' }, 4, { kind: 'text', status: 200, text: '0A0B0c0D' });
  await hq('ok-base64', { url: U, format: 'base64' }, 4, { kind: 'text', status: 200, text: ' AQIDBA==\n' });
  await hq('ok-base64-nopad', { url: U, format: 'base64' }, 4, { kind: 'text', status: 200, text: 'AQIDBA' });
  await hq('ok-max-1024', { url: U }, 1024, jb(bytes(1024)));
  await hq('ok-lengthParam', { url: U, lengthParam: 'n' }, 4, jb(four));
  await hq('ok-extraParams', { url: U, extraParams: { type: 'uint8', b: '1 2', 'x&y': 'é' } }, 4, jb(four));
  await hq('ok-extra-overrides-length', { url: U, extraParams: { length: '99' } }, 4, jb(four));
  await hq('ok-existing-query', { url: U + '?a=1&length=7&z=%20' }, 4, jb(four));
  await hq('ok-fragment', { url: U + '#frag' }, 4, jb(four));
  await hq('ok-port-path', { url: 'https://Qrng.Example:8443/a/b/../c' }, 4, jb(four));
  await hq('ok-bare-host', { url: 'https://qrng.example' }, 4, jb(four));
  await hq('ok-userinfo', { url: 'https://user:pw@qrng.example/x' }, 4, jb(four));
  await hq('ok-buildUrl', { url: 'https://qrng.example/base', buildUrl: { suffix: '.json' } }, 4, jb(four));
  await hq('ok-buildUrl-http-refused', { url: 'http://qrng.example/base', buildUrl: { suffix: '' } }, 4, jb(four));
  await hq('ok-loopback-localhost', { url: 'http://localhost:9000/q', allowInsecureLoopback: true }, 4, jb(four));
  await hq('ok-loopback-127', { url: 'http://127.0.0.1/q', allowInsecureLoopback: true }, 4, jb(four));
  await hq('ok-loopback-v6', { url: 'http://[::1]:9/q', allowInsecureLoopback: true }, 4, jb(four));
  await hq('ok-loopback-upper', { url: 'HTTP://LOCALHOST/q', allowInsecureLoopback: true }, 4, jb(four));
  await hq('ok-maxBytes-equal', { url: U, maxBytes: 4 }, 4, jb(four));
  await hq('ok-ok-flag-true-status-500', { url: U }, 4, { kind: 'json', status: 500, ok: true, body: { data: [...four] } });
  // insecure / bad URLs
  await hq('insecure-http', { url: 'http://qrng.example/q' }, 4, jb(four));
  await hq('insecure-http-allow-nonloop', { url: 'http://qrng.example/q', allowInsecureLoopback: true }, 4, jb(four));
  await hq('insecure-http-localhost-noallow', { url: 'http://localhost/q' }, 4, jb(four));
  await hq('insecure-http-localhost-allow-string', { url: 'http://localhost/q', allowInsecureLoopback: 'yes' }, 4, jb(four));
  await hq('insecure-ftp', { url: 'ftp://qrng.example/q' }, 4, jb(four));
  await hq('insecure-http-0.0.0.0', { url: 'http://0.0.0.0/q', allowInsecureLoopback: true }, 4, jb(four));
  await hq('insecure-http-127.0.0.2', { url: 'http://127.0.0.2/q', allowInsecureLoopback: true }, 4, jb(four));
  await hq('bad-url', { url: 'not a url' }, 4, jb(four));
  await hq('bad-url-relative', { url: '/api' }, 4, jb(four));
  await hq('bad-url-buildUrl-garbage', { url: 'https://qrng.example', buildUrl: { suffix: '' } }, 4, jb(four));
  // response failures
  for (const st of [199, 300, 301, 400, 401, 404, 429, 500, 503]) await hq(`http-${st}`, { url: U, apiKey: 'sekret-1' }, 4, { kind: 'json', status: st, body: { data: [...four] } });
  await hq('ok-flag-false-status-200', { url: U }, 4, { kind: 'json', status: 200, ok: false, body: { data: [...four] } });
  await hq('short', { url: U }, 4, jb(Uint8Array.from([1, 2, 3])));
  await hq('long', { url: U }, 4, jb(Uint8Array.from([1, 2, 3, 4, 5])));
  await hq('empty-data', { url: U }, 4, jb(new Uint8Array()));
  await hq('body-not-object', { url: U }, 4, { kind: 'json', status: 200, body: 5 });
  await hq('body-null', { url: U }, 4, { kind: 'json', status: 200, body: null });
  await hq('body-success-false', { url: U }, 4, { kind: 'json', status: 200, body: { success: false, data: [1, 2, 3, 4] } });
  await hq('body-data-missing', { url: U }, 4, { kind: 'json', status: 200, body: { success: true } });
  await hq('body-elem-256', { url: U }, 4, { kind: 'json', status: 200, body: { data: [1, 2, 3, 256] } });
  await hq('body-elem-float', { url: U }, 4, { kind: 'json', status: 200, body: { data: [1, 2, 3, 1.5] } });
  await hq('json-throws', { url: U }, 4, { kind: 'jsonThrows', status: 200 });
  await hq('text-throws', { url: U, format: 'hex' }, 4, { kind: 'textThrows', status: 200 });
  await hq('hex-odd', { url: U, format: 'hex' }, 4, { kind: 'text', status: 200, text: '0102030' });
  await hq('hex-nonhex', { url: U, format: 'hex' }, 4, { kind: 'text', status: 200, text: '0102030g' });
  await hq('hex-short', { url: U, format: 'hex' }, 4, { kind: 'text', status: 200, text: '010203' });
  await hq('hex-empty', { url: U, format: 'hex' }, 4, { kind: 'text', status: 200, text: '' });
  await hq('base64-bad-char', { url: U, format: 'base64' }, 4, { kind: 'text', status: 200, text: 'AQID*A==' });
  await hq('base64-url-alphabet', { url: U, format: 'base64' }, 4, { kind: 'text', status: 200, text: 'AQ-_' });
  await hq('base64-wrong-len', { url: U, format: 'base64' }, 4, { kind: 'text', status: 200, text: 'AQID' });
  await hq('format-unknown', { url: U, format: 'json' }, 4, { kind: 'text', status: 200, text: '01020304' });
  // transport failures (the key never appears in the message)
  await hq('throw-plain', { url: U, apiKey: 'sekret-1' }, 4, { kind: 'throw', message: 'connection refused' });
  await hq('throw-leaks-key', { url: U, apiKey: 'sekret-1' }, 4, { kind: 'throw', message: 'bad header x-api-key: sekret-1 (sekret-1)' });
  await hq('throw-empty-key-text', { url: U, apiKey: '' }, 4, { kind: 'throw', message: 'plain' });
  await hq('throw-string', { url: U }, 4, { kind: 'throwString', message: 'strange' });
  await hq('timeout', { url: U, timeoutMs: 20, apiKey: 'sekret-1' }, 4, { kind: 'hang' });
  await hq('no-fetch', { url: U }, 4, { kind: 'none' });
  // numBytes
  for (const [nm, n] of [['0', 0], ['neg', -1], ['frac', 1.5], ['nan', NUM('NaN')], ['inf', NUM('Infinity')], ['str', '4'], ['null', null], ['over-default', 1025], ['over-max', 5]] as [string, any][])
    await hq(`count-${nm}`, nm === 'over-max' ? { url: U, maxBytes: 4 } : { url: U }, n, jb(four));
  await hq('count-1', { url: U }, 1, jb(Uint8Array.of(9)));
  await hq('count-max-custom', { url: U, maxBytes: 2000 }, 1500, jb(bytes(1500)));
  await hq('count-check-before-fetch-impl', { url: U }, 0, { kind: 'none' });
  await hq('insecure-check-before-transport', { url: 'http://qrng.example' }, 4, { kind: 'throw', message: 'must not be reached' });
  // constructor validation
  for (const [nm, cfg] of [['url-empty', { url: '' }], ['url-number', { url: 5 }], ['url-null', { url: null }], ['url-missing', {}], ['maxBytes-0', { url: U, maxBytes: 0 }], ['maxBytes-neg', { url: U, maxBytes: -1 }],
    ['maxBytes-frac', { url: U, maxBytes: 1.5 }], ['maxBytes-nan', { url: U, maxBytes: NUM('NaN') }], ['maxBytes-str', { url: U, maxBytes: '8' }], ['timeout-0', { url: U, timeoutMs: 0 }], ['timeout-neg', { url: U, timeoutMs: -5 }],
    ['timeout-frac', { url: U, timeoutMs: 0.5 }], ['timeout-inf', { url: U, timeoutMs: NUM('Infinity') }], ['name-host-only', { url: 'https://h.example:81/p?x=1' }], ['name-unparseable', { url: '%%%' }]] as [string, any][])
    await hq(`ctor-${nm}`, cfg, 4, jb(four));
}

refWrite(o, 'entropy');
void ({} as Req);
