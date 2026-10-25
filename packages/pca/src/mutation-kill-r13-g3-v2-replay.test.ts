/**
 * r13 (g3) mutation kills: the reference replays its OWN cross-language golden tables.
 *
 * The systemic gap: every native SDK replays the TS-generated oracles for Intent Layer v2 / intent sessions
 * (k042-intentv2-cases, k042-intentv2-mut (replayed here as a distinct-outcome subset), k042-sessrevoc-cases: tools/pca-audit/java-mutate; killV2, killSession:
 * tools/pca-audit/kotlin-mutate), but the reference itself never did, so a mutant of intent-v2.ts / intent-session.ts /
 * intent-session-caveat.ts that changes a decision, a reason text or the verifier env on those inputs could not fail
 * any TS test (the generators only ever ran against the code that wrote them). Here the pinned tables are the expected
 * output: every check (name, ok, exact reason; a thrown internal error keeps only its "(fail closed): " prefix, as the
 * generators record it), the canonical env and intentV2Active; session wire / caveat / root shape and verify reasons;
 * revocation reasons. Inputs are JSON text, so -0 / 1e21 / 1e400 reach the reference exactly as JSON.parse yields them.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { assert, describe, expect, it, vi } from 'vitest';
import { canonicalize, canonicalizeStrict } from './hash';
import * as rev from './intent-revocation';
import * as ses from './intent-session';
import * as cav from './intent-session-caveat';
import * as v2 from './intent-v2';

// Every function replayed here is documented as never throwing (a refusal is a value): a throw is a mismatch with the
// pinned value and is reported as an assertion failure naming the function.
const noThrow = <A extends unknown[], R>(name: string, f: (...a: A) => R) => (...a: A): R => {
  try {
    return f(...a);
  } catch (e) {
    return assert.fail(`${name} threw: ${(e as Error)?.message ?? String(e)}`);
  }
};
const decideIntentV2 = noThrow('decideIntentV2', v2.decideIntentV2);
const intentV2Active = noThrow('intentV2Active', v2.intentV2Active);
const checkSessionRevocation = noThrow('checkSessionRevocation', rev.checkSessionRevocation);
const revocationEpochShapeError = noThrow('revocationEpochShapeError', rev.revocationEpochShapeError);
const grantSessionCaveat = noThrow('grantSessionCaveat', ses.grantSessionCaveat);
const sessionRootShapeError = noThrow('sessionRootShapeError', ses.sessionRootShapeError);
const validateIntentSessionWire = noThrow('validateIntentSessionWire', ses.validateIntentSessionWire);
const verifySessionRoot = noThrow('verifySessionRoot', ses.verifySessionRoot);
const intentSessionCaveatError = noThrow('intentSessionCaveatError', cav.intentSessionCaveatError);

// Speed only, semantics unchanged: these tables re-verify the same few Ed25519 signatures tens of thousands of times
// (pure-JS bigint arithmetic, ~35 ms a case). The verdicts of the PURE functions ed25519.verify and point decoding /
// small-order / torsion checks are memoized by their exact input bytes, so a mutant that changes a signed message, key
// or signature still reaches the real arithmetic.
vi.mock('@noble/curves/ed25519', async (importOriginal) => {
  const m: any = await importOriginal();
  const ed = m.ed25519;
  const hex = (x: unknown) => (typeof x === 'string' ? 's' + x : x instanceof Uint8Array ? Buffer.from(x).toString('hex') : 'o' + String(x));
  const vc = new Map<string, { v?: boolean; e?: unknown }>();
  const verify = (sig: any, msg: any, pk: any, opts?: any) => {
    const k = `${hex(sig)}|${hex(msg)}|${hex(pk)}|${JSON.stringify(opts ?? null)}`;
    let r = vc.get(k);
    if (r === undefined) {
      try { r = { v: ed.verify(sig, msg, pk, opts) }; } catch (e) { r = { e }; }
      vc.set(k, r);
    }
    if ('e' in r) throw r.e;
    return r.v;
  };
  const EP = ed.ExtendedPoint;
  const pc = new Map<string, { p?: any; e?: unknown }>();
  const fromHex = (h: any, ...rest: any[]) => {
    const k = hex(h) + '|' + JSON.stringify(rest);
    let r = pc.get(k);
    if (r === undefined) {
      try {
        const p = EP.fromHex(h, ...rest);
        const memo = new Map<PropertyKey, boolean>();
        // the points are frozen: memoize the two predicates through a proxy (they live on the prototype)
        r = { p: new Proxy(p, { get: (t, f) => (f === 'isSmallOrder' || f === 'isTorsionFree' ? () => { if (!memo.has(f)) memo.set(f, t[f]()); return memo.get(f); } : Reflect.get(t, f)) }) };
      } catch (e) { r = { e }; }
      pc.set(k, r);
    }
    if ('e' in r) throw r.e;
    return r.p;
  };
  const EPx = new Proxy(EP, { get: (t, k) => (k === 'fromHex' ? fromHex : Reflect.get(t, k)) });
  return { ...m, ed25519: new Proxy(ed, { get: (t, k) => (k === 'verify' ? verify : k === 'ExtendedPoint' ? EPx : Reflect.get(t, k)) }) };
});

const load = (f: string): any => JSON.parse(gunzipSync(readFileSync(resolve(__dirname, '..', 'testdata', f))).toString('utf8'));
const FAIL_CLOSED = '(fail closed): ';
const cut = (r: string | null | undefined): string | null => (r == null ? null : r.includes(FAIL_CLOSED) ? r.slice(0, r.indexOf(FAIL_CLOSED) + FAIL_CLOSED.length) : r);

/** The kotlin-mutate generators' `toTs`: a rebuild by assignment (so an own "__proto__" member becomes the prototype). */
const toTs = (x: any): any => {
  if (Array.isArray(x)) return x.map(toTs);
  if (x && typeof x === 'object') { const o: any = {}; for (const [k, v] of Object.entries(x)) o[k] = toTs(v); return o; }
  return x;
};

/** The k042-intentv2-cases / -mut case format (tools/pca-audit/java-mutate/k042-intentv2-oracle.mts `add`). */
function replayK042(c: any): void {
  const P = JSON.parse(c.p), G = JSON.parse(c.grant);
  let C = c.ctx === undefined ? undefined : JSON.parse(c.ctx);
  if (c.wp !== undefined) C = { ...C, params: JSON.parse(c.wp) };
  const d = decideIntentV2(P, G, C, c.now);
  const checks = d.checks.map((k: any) => {
    let reason = k.reason ?? null, prefix = false;
    if (reason !== null && reason.includes(FAIL_CLOSED) && /error \(fail closed\): /.test(reason)) { reason = reason.slice(0, reason.indexOf(FAIL_CLOSED) + FAIL_CLOSED.length); prefix = true; }
    return { name: k.name, ok: k.ok, reason, ...(prefix ? { prefix: true } : {}) };
  });
  expect({ checks, env: canonicalize((d.env ?? {}) as any), active: intentV2Active(P, C) }, c.name).toEqual({ checks: c.checks, env: c.env, active: c.active });
}

describe('k042-intentv2 (cases + mut): decideIntentV2, one case per distinct pinned outcome', () => {
  // testdata/k042-intentv2-r13-subset.json.gz: the full tables (~15k cases, minutes of Ed25519) reduced to one case per
  // distinct (checks, env, active) outcome plus the cases that revealed a hand-applied mutant, so a Stryker run can afford it
  const D = load('k042-intentv2-r13-subset.json.gz').cases as any[];
  it('the table is the expected size', () => expect(D.length).toBe(916));
  it('every check, reason, env and intentV2Active is exactly the pinned one', () => { for (const c of D) replayK042(c); });
});

describe('killV2 (Kotlin golden): decide / rev / shape / active', () => {
  const D = load('killV2.json.gz');
  it('decide: every check [name, ok, reason] and the strict canonical env', () => {
    for (const c of D.decide) {
      // the golden file lost this case's input: the generator's clone() turned the own "__proto__" member of acc.state into the
      // prototype before writing it out, so the stored text no longer carries it (the k042-intentv2 tables pin the vector with JSON semantics)
      if (c.name === 'corpus/acc-state-own-proto-key') continue;
      const d = decideIntentV2(toTs(c.p), toTs(c.grant), c.ctx === undefined ? undefined : toTs(c.ctx), c.now);
      expect({ checks: d.checks.map((k: any) => [k.name, k.ok, k.reason ?? null]), env: canonicalizeStrict((d.env ?? {}) as any) }, c.name).toEqual({ checks: c.checks, env: c.env });
    }
  });
  it('rev: checkSessionRevocation over the primitives.intent_revocation form', () => {
    const PARAMS = ['session', 'scope', 'authority', 'ids', 'now', 'max_age_ms', 'last'];
    for (const c of D.rev) {
      const t = toTs(c.input);
      let reason: string | null;
      if (t === null || typeof t !== 'object' || Array.isArray(t)) reason = 'NOT-OBJECT';
      else {
        const ev: any = {};
        for (const [k, v] of Object.entries(t)) if (!PARAMS.includes(k)) ev[k] = v;
        const r: any = checkSessionRevocation(ev, { session: t.session, authority: t.authority, ids: t.ids, now: t.now, maxAgeMs: t.max_age_ms, ...('last' in t ? { last: t.last } : {}) } as any);
        reason = r.ok ? null : r.reason;
      }
      expect(reason, c.name).toBe(c.reason);
    }
  });
  it('shape: revocationEpochShapeError', () => { for (const c of D.shape) expect(revocationEpochShapeError(toTs(c.ep)), c.name).toBe(c.want); });
  it('active: intentV2Active', () => { for (const c of D.active) expect(intentV2Active(toTs(c.p), c.ctx === undefined ? undefined : toTs(c.ctx)), c.name).toBe(c.want); });
});

describe('killSession (Kotlin golden): wire / caveat / grant / root', () => {
  const D = load('killSession.json.gz');
  it('wire: validateIntentSessionWire', () => { for (const c of D.wire) expect(validateIntentSessionWire(toTs(c.arg)), c.name).toBe(c.ts); });
  it('caveat: intentSessionCaveatError', () => { for (const c of D.caveat) expect(intentSessionCaveatError(toTs(c.arg)), c.name).toBe(c.ts); });
  it('grant: grantSessionCaveat returns the FIRST intent_session caveat (by identity)', () => {
    for (const c of D.grant) {
      const t = toTs(c.arg);
      const f = grantSessionCaveat(t);
      expect(f === undefined ? null : t.caveats.indexOf(f), c.name).toBe(c.want_index);
    }
  });
  it('root: sessionRootShapeError and verifySessionRoot (under the verifier pins)', () => {
    for (const c of D.root) {
      const t = toTs(c.arg);
      const v = verifySessionRoot(t, c.pins ? { pqPins: c.pins } : {});
      expect({ shape: sessionRootShapeError(t), verify: v.ok ? null : v.reason }, c.name).toEqual({ shape: c.shape, verify: c.verify });
    }
  });
});

describe('k042-sessrevoc-cases: wire / caveat / root / rev / prim', () => {
  const D = load('k042-sessrevoc-cases.json.gz');
  it('wire', () => { for (const c of D.wire) expect(validateIntentSessionWire(JSON.parse(c.v)), c.name).toBe(c.reason); });
  it('caveat', () => { for (const c of D.caveat) expect(intentSessionCaveatError(JSON.parse(c.c)), c.name).toBe(c.reason); });
  it('root', () => {
    for (const c of D.root) {
      const s = JSON.parse(c.s);
      const v = verifySessionRoot(s, c.pq_pins ? { pqPins: JSON.parse(c.pq_pins) } : {});
      expect({ shape: sessionRootShapeError(s), verify: v.ok ? null : v.reason }, c.name).toEqual({ shape: c.shape, verify: c.verify });
    }
  });
  it('rev', () => {
    for (const c of D.rev) {
      const r: any = checkSessionRevocation(c.ev === null ? undefined : JSON.parse(c.ev), {
        session: c.session, authority: JSON.parse(c.authority), ids: c.ids === null ? undefined : JSON.parse(c.ids), now: c.now, maxAgeMs: c.maxAge,
        ...(c.scope !== null ? { scope: c.scope } : {}), ...(c.last !== null ? { last: JSON.parse(c.last) } : {}),
      } as any);
      expect(r.ok ? null : cut(r.reason), c.name).toBe(c.reason);
    }
  });
  it('prim', () => {
    for (const c of D.prim) {
      const input = JSON.parse(c.text);
      let reason: string | null;
      if (input === null || typeof input !== 'object' || Array.isArray(input)) reason = 'session revocation check error (fail closed)';
      else {
        const ev: any = { ...input };
        for (const k of ['session', 'scope', 'authority', 'ids', 'now', 'max_age_ms', 'last']) delete ev[k];
        const r: any = checkSessionRevocation(ev, { session: input.session, authority: input.authority, ids: input.ids, now: input.now, maxAgeMs: input.max_age_ms, ...('last' in input ? { last: input.last } : {}) } as any);
        reason = r.ok ? null : cut(r.reason);
      }
      expect(reason, c.name).toBe(c.reason);
    }
  });
});
