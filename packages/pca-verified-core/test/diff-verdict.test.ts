import * as fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { mintGrant } from '../../pca/src/envelope';
import { intentGoal } from '../../pca/src/intent-binding';
import { encodeKey, generateKeyPair } from '../../pca/src/keys';
import { ARTIFACT_SIZE_REASON, MAX_ARTIFACT_BYTES, buildPCActn as buildLegacy, decodePCActn, type PCActn, type VerifyHooks } from '../../pca/src/pcactn';
import { verifyPCActnCore as coreWired } from '../../pca/src/pcactn-full';
import { DEFAULT_RISK_POLICY } from '../../pca/src/risk';
import { enforceRequired as enforceWired, verifyPCActn as verifyWired, type PcaVerdict } from '../../pca/src/server/verify';
import { verifyPCActnCore as coreLegacy } from './support/legacy/pcactn';
import { enforceRequired as enforceLegacy, verifyPCActn as verifyLegacy } from './support/legacy/verify';
import { Rng, carriesIntentSession, loadCorpus, overCaveatCap, vectorChain } from './support/corpus';

const NOW = 1_800_000_000_000;
/** A vector's intent policy: `intent_policy_json` (raw text) wins over `intent_policy` (conformance rule 12). */
const intentPolicyOf = (c: unknown): unknown => {
  const x = c as { intent_policy?: unknown; intent_policy_json?: string };
  return x.intent_policy_json !== undefined ? JSON.parse(x.intent_policy_json) : x.intent_policy;
};
const P = generateKeyPair();
const A = generateKeyPair();
const nodes = [
  { id: 'n1', verb: 'wire', resource: 'bank', reversibility_class: 'reversible' },
  { id: 'n2', verb: 'delete', resource: 'db', reversibility_class: 'irreversible' },
];
const mk = (agent_binding: Record<string, unknown>) =>
  mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'g',
    envelope: { predicates: [{ verb: '*' }], caveats: [], agent_binding, risk_policy: DEFAULT_RISK_POLICY },
  }).grant;
const GRANTS = [mk({}), mk({ model: 'm1' })];
const build = (grant: any, node: string, counter: number, extra: Record<string, unknown> = {}): PCActn =>
  buildLegacy({ aud: 'rs', now: NOW, grant, chain: [grant], plan: nodes, nodeId: node, counter, signerSecret: A.secretKey, riskClaim: { r: 0, inputs: {} }, ...extra } as never);
// Intent Layer M2: a grant minted for an intent goal and actions carrying the bound (or a mis-bound) `intent` member.
const IREF = encodeKey(new Uint8Array(32).fill(7));
const IMAP = encodeKey(new Uint8Array(32).fill(9));
const INTENT = { ref: IREF, map_digest: IMAP, goal_salt: 'salt-1', fidelity_ppm: 900_000, residual_risk_ppm: 1_000 };
const GI = mintGrant({
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: encodeKey(A.publicKey),
  goal: intentGoal(IREF, IMAP),
  salt: 'salt-1',
  envelope: { predicates: [{ verb: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
}).grant;
const BASES = [
  ...GRANTS.flatMap((g) => ['n1', 'n2'].map((n) => ({ grant: g, p: build(g, n, 3, { nonce: 'x1' }) }))),
  { grant: GI, p: build(GI, 'n1', 3, { intent: INTENT }) },
  { grant: GI, p: build(GI, 'n2', 3, { intent: { ...INTENT, goal_salt: 'other' } }) },
];

const JUNK: unknown[] = [undefined, null, 0, 1, -1, 1.5, NaN, '', 'x', [], {}, true, false, 2 ** 60, 'rs'];
function mutate(p: any, r: Rng): any {
  const x = structuredClone(p);
  for (let k = 0, n = r.next(3); k < n; k++) {
    switch (r.next(11)) {
      case 0:
        x[r.pick(['ver', 'grant_ref', 'counter', 'aud', 'iat', 'exp', 'sig', 'alg', 'pq_pk', 'pq_sig', 'nonce', 'tool_binding', 'caution'])] = r.pick(JUNK);
        break;
      case 1:
        x.action[r.pick(['verb', 'resource', 'params_digest', 'reversibility_class'])] = r.pick(['wire', 'bank', 'reversible', 'costly', 'irreversible', 'bogus', ...JUNK.map(String)]);
        break;
      case 2:
        x.plan[r.pick(['root', 'node_id', 'conditions_digest'])] = r.pick(JUNK);
        break;
      case 3:
        x.exp = x.iat + r.pick([0, 1, 3_600_000, 3_600_001]);
        break;
      case 4:
        x.iat = NOW + r.pick([0, 59_999, 60_000, 60_001, -3_000_000]);
        x.exp = x.iat + 1000;
        break;
      case 5:
        delete x[r.pick(['aud', 'counter', 'sig', 'grant_ref', 'nonce', 'freshness', 'provenance'])];
        break;
      case 6:
        x.cap_chain = r.pick([[], [x.cap_chain?.[0], x.cap_chain?.[0]], 'x', undefined, [JUNK[r.next(JUNK.length)]]]);
        break;
      case 7:
        // case 0 may already have replaced sig with a non-string JUNK value; only a string signature can be truncated
        if (typeof x.sig === 'string') x.sig = x.sig.slice(0, -3) + 'AAA';
        break;
      case 8:
        x.zk_compliance = r.pick(['proof', { a: 1 }]);
        break;
      case 9:
        x.bond_ref = 'bond';
        break;
      case 10:
        x.intent = r.pick([INTENT, { ...INTENT, fidelity_ppm: 1_000_001 }, { ...INTENT, extra: 1 }, { ...INTENT, ref: IMAP }, 'x', null, [], undefined]);
        break;
    }
  }
  return x;
}

const hookOf = (r: Rng, kind: 'att' | 'thr' | 'rev' | 'zk') => {
  const choice = r.next(8);
  if (choice === 0) return undefined;
  const t = kind === 'thr' ? r.pick([undefined, 1, 2, 3, 3, 2.5, NaN, Infinity, -1, '3' as unknown as number]) : undefined;
  switch (choice) {
    case 1:
      return () => ({ enforced: false as const });
    case 2:
      return () => ({ enforced: true as const, ok: true, ...(t !== undefined ? { t } : {}) });
    case 3: {
      const reason = r.pick(['nope', undefined as unknown as string]);
      return () => ({ enforced: true as const, ok: false, reason, ...(t !== undefined ? { t } : {}) });
    }
    case 4:
      return async () => ({ enforced: true as const, ok: true, ...(t !== undefined ? { t } : {}) });
    case 5:
      return () => {
        throw new Error('hook boom');
      };
    case 6:
      return async () => {
        throw new Error('hook reject');
      };
    default:
      return () => ({ enforced: true as const, ok: true, ...(t !== undefined ? { t } : {}) });
  }
};

function options(r: Rng, grant: any) {
  const hooks: VerifyHooks = {};
  for (const [k, kind] of [['attestation', 'att'], ['threshold', 'thr'], ['revocation', 'rev'], ['zk', 'zk']] as const) {
    const h = hookOf(r, kind);
    if (h) (hooks as any)[k] = h;
  }
  const risk = r.pick([{ semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 }, { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 }, {}, { semanticDistance: 0.4, reversibility: 0.5, blastRadius: 0.3, taint: 0.2, confidence: 0.7, age: 0.1 }]);
  const context: any = { risk };
  if (r.bool()) context.budget = r.pick([{ B: 1, tau: NOW }, { B: 0, tau: NOW }, { B: 0.3, tau: NOW - 1000, asOf: NOW - 500 }]);
  if (r.bool()) context.plan = r.pick([nodes, [nodes[0]], []]);
  if (r.bool()) context.planAuthorized = r.bool();
  if (r.bool()) context.reversibilityClass = r.pick(['reversible', 'costly', 'irreversible', 'bogus']);
  if (r.next(4) === 0) context.params = r.pick([{}, { a: 1 }]);
  const opts: any = {
    grant,
    audience: r.pick(['rs', 'rs', 'rs', 'other', undefined, null]),
    now: r.pick([NOW, NOW, NOW, NOW + 3_600_001, NOW + 60_001, NOW - 120_000, NOW + 1]),
    hooks,
    context,
  };
  if (r.next(4) === 0) opts.allowedSuites = r.pick([['ed25519'], [], ['ml-dsa-65']]);
  if (r.next(8) === 0) opts.allowUnboundPq = true;
  if (r.next(5) === 0) opts.intent = r.pick([{ require: true }, { min_fidelity_ppm: 900_000 }, { max_residual_risk_ppm: 999 }, { min_fidelity_ppm: -1 }, { require: false }]);
  if (r.next(3) === 0) opts.require = r.pick([['counter'], ['counter', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound'], ['threshold', 'attestation', 'nonexistent'], ['policy', 'budget']]);
  return opts;
}

function same(b: unknown, a: unknown, ctx = ''): void {
  const x = canon(a);
  const y = canon(b);
  if (x !== y) throw new Error(`MISMATCH ${ctx}\nLEGACY ${x.slice(0, 2500)}\nWIRED  ${y.slice(0, 2500)}`);
}
/**
 * Seed for the random properties: FIXED by default so the release suite is deterministic; PCA_FUZZ_SEED=random explores a
 * fresh seed per run (fast-check prints it on failure), PCA_FUZZ_SEED=<int> replays one.
 */
const fuzzSeed = (fixed: number): { seed?: number } => {
  const e = process.env['PCA_FUZZ_SEED'];
  if (e === 'random') return {};
  if (e !== undefined && e !== '' && Number.isSafeInteger(Number(e))) return { seed: Number(e) };
  return { seed: fixed };
};
// 0.5 (B6) split the verifier's `counter` check into `counter_format` (+ `replay` with a store); the frozen legacy still says `counter`.
// Both sides are compared under the old name, key order preserved.
// 0.5 defaults the verifier to DEFAULT_REQUIRED_CHECKS (default-deny) and reports a carried-but-unimplemented feature (bond_ref) as
// `unsupported` and denies it; the frozen legacy has neither. Pin both off (require: [], allowUnsupported: ['bond']) and compare
// `unsupported` as the legacy `not-enforced`, so every other difference still fails.
const verifyWiredOld = (p: unknown, o: Record<string, unknown>) => verifyWired(p as never, { require: [], allowUnsupported: ['bond'], ...o } as never);
const oldName = (k: string) => k.replace(/\bcounter_format\b/g, 'counter');
const canon = (v: unknown) =>
  JSON.stringify(v, (_k, x) =>
    x === undefined ? '__undef__'
    : typeof x === 'number' && !Number.isFinite(x) ? String(x)
    : x === 'unsupported' ? 'not-enforced'
    : typeof x === 'string' ? oldName(x)
    : x && typeof x === 'object' && !Array.isArray(x) ? Object.fromEntries(Object.entries(x).map(([k, y]) => [oldName(k), y]))
    : x);

describe('differential: verifyPCActnCore / verifyPCActn: frozen pre-wiring TypeScript (test/support/legacy) vs the PRODUCTION code that delegates to the verified core', () => {
  it('agrees (JSON-identical, key order included) on every conformance vector at the core level', async () => {
    const { core, adversarial } = loadCorpus();
    let n = 0;
    let overCap = 0;
    let intentV2 = 0;
    for (const v of [...core, ...adversarial]) {
      let p: any = v.pcactn;
      if (v.pcactn_json !== undefined) {
        try {
          p = decodePCActn(v.pcactn_json);
        } catch {
          continue;
        }
      }
      const ip = intentPolicyOf(v.context);
      const o = { grant: v.grant, nowEpoch: v.context.now, audience: v.context.aud, ...(ip !== undefined ? { intent: ip as never } : {}) };
      if (overCaveatCap(vectorChain(p))) {
        // legacy predates the caveat cap: production must deny on cap_chain with the cap reason
        const b: any = await coreWired(p, o);
        expect(b.allow, v.name).toBe(false);
        expect(b.checks.cap_chain, v.name).toBe('fail');
        expect(String(b.reason), v.name).toContain('chain exceeds caveat limit');
        overCap++;
        n++;
        continue;
      }
      if (carriesIntentSession(p)) {
        // Intent v2 (support/corpus.ts carriesIntentSession): without the verifier's v2 state production refuses
        const b: any = await coreWired(p, o);
        expect(b.allow, v.name).toBe(false);
        intentV2++;
        n++;
        continue;
      }
      const a = await coreLegacy(p, o);
      const b = await coreWired(p, o);
      expect(canon(b), v.name).toBe(canon(a));
      // and with a suite policy / no audience (fail-closed branch) / explicit null audience
      for (const extra of n % 6 === 0 ? [{ allowedSuites: ['ed25519'] as never }, { audience: undefined }, { audience: null }, { allowUnboundPq: true }] : []) {
        const o2 = { ...o, ...extra };
        expect(canon(await coreWired(p, o2)), v.name).toBe(canon(await coreLegacy(p, o2)));
      }
      n++;
    }
    expect(n).toBeGreaterThan(3000);
    expect(overCap).toBeGreaterThan(0);
    expect(intentV2).toBeGreaterThan(0);
  });

  it('agrees on every conformance vector at the full verifyPCActn level (default-deny context, with require lists)', async () => {
    const { core, adversarial } = loadCorpus();
    let n = 0;
    let allowed = 0;
    for (const v of [...core, ...adversarial]) {
      let p: any = v.pcactn;
      if (v.pcactn_json !== undefined) {
        try {
          p = decodePCActn(v.pcactn_json);
        } catch {
          continue;
        }
      }
      for (const extra of n % 3 === 0 ? [{}, { require: ['counter', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound'] }] : [{}]) {
        const ip = intentPolicyOf(v.context);
        const o = { grant: v.grant, now: v.context.now, audience: v.context.aud, ...(ip !== undefined ? { intent: ip } : {}), ...extra } as never;
        if (overCaveatCap(vectorChain(p))) {
          const b: any = await verifyWired(p, o);
          expect(b.allow, v.name).toBe(false);
          expect(JSON.stringify(b), v.name).toContain('chain exceeds caveat limit');
          continue;
        }
        if (carriesIntentSession(p)) {
          // Intent v2: out of the legacy oracle's scope (support/corpus.ts); production refuses without the v2 state
          expect((await verifyWired(p, o)).allow, v.name).toBe(false);
          continue;
        }
        const a = await verifyLegacy(p, o);
        const b = await verifyWiredOld(p, o);
        expect(canon(b), v.name).toBe(canon(a));
        if (a.allow) allowed++;
      }
      n++;
    }
    expect(n).toBeGreaterThan(3000);
    expect(allowed).toBeGreaterThanOrEqual(0);
  });

  it('agrees on the vectors that are rejected at parse time (raw pcactn_json strings through verifyPCActn)', async () => {
    const { core, adversarial } = loadCorpus();
    let n = 0;
    for (const v of [...core, ...adversarial]) {
      if (v.pcactn_json === undefined) continue;
      try {
        decodePCActn(v.pcactn_json);
        continue;
      } catch {
        /* parse failure: the interesting case */
      }
      const ip = intentPolicyOf(v.context);
      const o = { grant: v.grant, now: v.context.now, audience: v.context.aud, ...(ip !== undefined ? { intent: ip } : {}) } as never;
      if (overCaveatCap(vectorChain(undefined, v.pcactn_json))) {
        const b: any = await verifyWired(v.pcactn_json, o);
        expect(b.allow, v.name).toBe(false);
        n++;
        continue;
      }
      if (new TextEncoder().encode(v.pcactn_json).length > MAX_ARTIFACT_BYTES) {
        // legacy predates the artifact size cap: production refuses before decoding
        const b: any = await verifyWired(v.pcactn_json, o);
        expect(b.allow, v.name).toBe(false);
        expect(b.checks, v.name).toEqual({ malformed: 'fail' });
        expect(String(b.reasons?.[0]), v.name).toContain(ARTIFACT_SIZE_REASON);
        n++;
        continue;
      }
      same(await verifyWiredOld(v.pcactn_json, o), await verifyLegacy(v.pcactn_json, o), v.name);
      n++;
    }
    expect(n).toBeGreaterThan(1000);
  });

  // The property runs under a FIXED seed (the one that exposed the former generator bug); see fuzzSeed for exploration.
  const randomAgreement = async (seed: number) => {
    let allowed = 0;
    let denied = 0;
    await fc.assert(
      fc.asyncProperty(fc.array(fc.nat(), { minLength: 8, maxLength: 40 }), async (pool) => {
        const r = new Rng(pool);
        const base = r.pick(BASES);
        const p = r.next(3) === 0 ? mutate(base.p, r) : base.p;
        const opts = options(r, base.grant);
        const a = await verifyLegacy(p, opts);
        const b = await verifyWiredOld(p, opts);
        same(b, a);
        if (a.allow) allowed++; else denied++;
      }),
      { numRuns: 4000, ...fuzzSeed(seed) },
    );
    expect(allowed).toBeGreaterThan(20);
    expect(denied).toBeGreaterThan(500);
  };
  it('agrees on 4000 random PCActn x options x hooks x context combinations (verifyPCActn)', async () => {
    await randomAgreement(-1694244596);
  });
  it('the mutator never throws: a non-string sig (set by a JUNK mutation) is not truncated', () => {
    // counterexample of the former flake (seed -1694244596): JUNK sig, then the truncate-sig mutation
    const r = new Rng([0, 0, 528464843, 0, 2098737413, 271911700, 474440717, 0, 0, 0, 0]);
    const base = r.pick(BASES);
    expect(r.next(3)).toBe(0); // the property mutates this draw
    expect(() => mutate(base.p, r)).not.toThrow();
    const x = structuredClone(BASES[0]!.p) as any;
    for (const junk of JUNK) {
      x.sig = junk;
      expect(() => mutate(x, new Rng([2, 7, 7]))).not.toThrow(); // two mutations, both 'truncate sig'
    }
  });

  it('agrees on the core with the opt-in gates (attestation gate required/optional, freshness gate)', async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(fc.nat(), { minLength: 6, maxLength: 24 }), async (pool) => {
        const r = new Rng(pool);
        const base = r.pick(BASES);
        const p = r.next(3) === 0 ? mutate(base.p, r) : base.p;
        const o: any = { grant: base.grant, nowEpoch: NOW, audience: 'rs', hooks: { threshold: hookOf(r, 'thr'), revocation: hookOf(r, 'rev'), zk: hookOf(r, 'zk') } };
        const enforce: any = {};
        if (r.bool()) enforce.attestation = { verifier: hookOf(r, 'att') ?? (() => ({ enforced: false })), ...(r.bool() ? { required: r.bool() } : {}) };
        if (r.bool()) enforce.freshness = r.pick([{ maxAgeMs: 1000 }, { maxAgeMs: -1 }, { maxAgeMs: 1e12, epochMs: 0 }, { maxAgeMs: 5, clockSkewMs: 3 }, { maxAgeMs: 1e15 }]);
        if (Object.keys(enforce).length) o.enforce = enforce;
        same(await coreWired(p, o), await coreLegacy(p, o));
      }),
      { numRuns: 1500, ...fuzzSeed(20261011) },
    );
  });

  it('enforceRequired (mutating, exported) agrees', () => {
    const mkV = (): PcaVerdict => ({ allow: true, r: 0, requiredThreshold: { t: 1, proof: 'optimistic', optimisticAllowed: true } as never, checks: { a: 'pass', b: 'not-enforced', c: 'fail' }, reasons: ['x'] });
    for (const req of [[], ['a'], ['b'], ['c'], ['d'], ['a', 'b', 'c', 'd'], ['b', 'b'], ['d', 'd', 'a']]) {
      const v1 = enforceLegacy(mkV(), req);
      const v2 = enforceWired(mkV(), req);
      expect(canon(v2)).toBe(canon(v1));
    }
  });
});
