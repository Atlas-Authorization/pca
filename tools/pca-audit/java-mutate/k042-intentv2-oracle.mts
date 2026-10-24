// Differential oracle for the Java IntentV2 0.4.2 mutation kills (sdks/java-pca/test/net/atlasauth/pca/K042IntentV2*Test.java).
//
// Every case is (pcactn, grant, intent_v2 context | absent, now) fed STRAIGHT to the reference decideIntentV2
// (packages/pca/src/intent-v2.ts): no core checks, so the PCActn may be edited without re-signing. The expected output
// is the exact check list (name, ok, reason) plus the canonical env. Sources of cases:
//   1. every wire-valid conformance vector that carries context.intent_v2 or pcactn.intent_session;
//   2. targeted variants of those (edited contexts / PCActns, re-signed roots / grants / receipts where needed).
// Reasons of a thrown internal error ("<check> error (fail closed): ...") differ by language by design: the oracle
// keeps only the prefix up to "(fail closed): " for those and the Java test compares that prefix.
//
//   npx tsx tools/pca-audit/java-mutate/k042-intentv2-oracle.mts     (from the repo root; deterministic)
// writes sdks/java-pca/test-data/k042-intentv2-cases.json.gz
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
const pcaMod: any = await import(new URL('../../../packages/pca/src/index.ts', import.meta.url).href);
const pca: any = pcaMod.decideIntentV2 ? pcaMod : pcaMod.default;

const ROOT = new URL('../../../', import.meta.url).pathname;
const core = JSON.parse(readFileSync(ROOT + 'packages/pca/conformance/vectors.json', 'utf8'));
const byName = new Map<string, any>();
for (const v of core.vectors) byName.set(v.name, v);

const clone = <T,>(x: T): T => (x === undefined ? x : JSON.parse(JSON.stringify(x)));
const ABSENT = Symbol('absent');

// -0 aware JSON writer (Java parses "-0" with its lenient parser)
function ser(v: any): string {
  if (v === null) return 'null';
  if (typeof v === 'number') { if (Object.is(v, -0)) return '-0'; if (!Number.isFinite(v)) throw new Error('non-finite'); return JSON.stringify(v); }
  if (typeof v === 'string' || typeof v === 'boolean') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(ser).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.entries(v).filter(([, x]) => x !== undefined).map(([k, x]) => JSON.stringify(k) + ':' + ser(x)).join(',') + '}';
  throw new Error('unserializable ' + typeof v);
}

const FAIL_CLOSED = '(fail closed): ';
const cases: any[] = [];
const names = new Set<string>();
/**
 * One case. `opts.ctxText` replaces the serialized context (raw JSON text, e.g. exponent-form numbers); `opts.wp` is the
 * raw JSON text of params a host supplies through Context.withParams (the reference sees ctx.params = JSON.parse(wp)).
 */
function add(name: string, p: any, grant: any, ctx: any, now: number, opts: { ctxText?: string; wp?: string } = {}) {
  if (names.has(name)) throw new Error('dup case ' + name);
  names.add(name);
  // what the Java side sees: a JSON round trip (the context is normalized by Context.fromJson)
  const ctxText = opts.ctxText ?? (ctx === ABSENT ? undefined : ser(ctx));
  const P = JSON.parse(ser(p)), G = JSON.parse(ser(grant));
  let C = ctxText === undefined ? undefined : JSON.parse(ctxText);
  if (opts.wp !== undefined) C = { ...C, params: JSON.parse(opts.wp) };
  const d = pca.decideIntentV2(P, G, C, now);
  const checks = d.checks.map((c: any) => {
    let reason = c.reason ?? null, prefix = false;
    if (reason !== null && reason.includes(FAIL_CLOSED) && /error \(fail closed\): /.test(reason)) { reason = reason.slice(0, reason.indexOf(FAIL_CLOSED) + FAIL_CLOSED.length); prefix = true; }
    return { name: c.name, ok: c.ok, reason, ...(prefix ? { prefix: true } : {}) };
  });
  cases.push({ name, now, p: ser(p), grant: ser(grant), ...(ctxText === undefined ? {} : { ctx: ctxText }), ...(opts.wp !== undefined ? { wp: opts.wp } : {}),
    checks, env: pca.canonicalize(d.env ?? {}), active: pca.intentV2Active(P, C) });
}

// ---- 1. the conformance vectors -----------------------------------------------------------------------------------
const base: Record<string, { p: any; grant: any; ctx: any; now: number }> = {};
// skipped: FN-DSA roots (the Java SDK does not implement FN-DSA: it refuses them with unsupported_suite, as the README
// requires of a runner without the suite) and schema-note-too-long (an ActionSchema reason-text difference, not IntentV2's)
const SKIP = new Set(['session-root-fn-dsa-512', 'session-root-fn-dsa-1024', 'schema-note-too-long']);
for (const v of core.vectors) {
  if (SKIP.has(v.name)) continue;
  const iv = v.context?.intent_v2;
  if (iv === undefined && (typeof v.pcactn !== 'object' || v.pcactn?.intent_session === undefined)) continue;
  if (typeof v.pcactn !== 'object' || v.pcactn === null || v.pcactn_json !== undefined) continue;
  if (pca.validateWireV2 ? pca.validateWireV2(v.pcactn) !== null : false) continue;
  const now = v.context?.now ?? 0;
  const ctx = v.context && Object.prototype.hasOwnProperty.call(v.context, 'intent_v2') ? v.context.intent_v2 : ABSENT;
  base[v.name] = { p: v.pcactn, grant: v.grant, ctx, now };
  add('vec/' + v.name, v.pcactn, v.grant, ctx, now);
}

// ---- 2. variants ----------------------------------------------------------------------------------------------------
type V = { p: any; grant: any; ctx: any; now: number };
function vary(name: string, from: string, f: (v: V) => void | V, opts?: (v: V) => { ctxText?: string; wp?: string }) {
  const b = base[from];
  if (!b) throw new Error('no base ' + from);
  const v: V = { p: clone(b.p), grant: clone(b.grant), ctx: b.ctx === ABSENT ? ABSENT : clone(b.ctx), now: b.now };
  const r = f(v) ?? v;
  add(name, r.p, r.grant, r.ctx, r.now, opts ? opts(r) : {});
}
export const helpers = { vary, add, ser, base, byName, ABSENT, clone, pca, seed: (l: string) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest()) };

const variants = await import('./k042-intentv2-variants.mts');
await variants.default(helpers);

const out = ROOT + 'sdks/java-pca/test-data/k042-intentv2-cases.json.gz';
writeFileSync(out, gzipSync(Buffer.from(JSON.stringify({ generator: 'tools/pca-audit/java-mutate/k042-intentv2-oracle.mts', cases }) + '\n'), { level: 9 }));
console.log(`${cases.length} cases -> ${out}`);
