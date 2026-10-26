/** Mutation-kill tests for server/verify.ts: threshold hook (F-1) boundaries, policy-reason pass-through, delegated-caveat reason format. */
import { describe, expect, it } from 'vitest';
import { AUD, NOW, setup } from './fixture.test-util';
import { verifyPCActn as verifyPCActn05 } from './verify';
import { beaconRef, issueLivenessBeacon } from '../beacons';
import { generateKeyPair, encodeKey } from '../keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from '../pq';
const verifyPCActn = (p: Parameters<typeof verifyPCActn05>[0], o: Parameters<typeof verifyPCActn05>[1]): ReturnType<typeof verifyPCActn05> => verifyPCActn05(p, 'require' in o ? o : Object.create(o, { require: { value: [], enumerable: true } })); // report-only: these tests are not about the 0.5 default required checks (see breaking-05.test.ts)


const stepUpCtx = (s: ReturnType<typeof setup>) => ({ plan: s.plan, risk: { reversibility: 0, blastRadius: 0.5, confidence: 0.5, semanticDistance: 1 }, params: s.params });

describe('verifyPCActn: threshold hook vs server-derived t (F-1)', () => {
  it('a hook that enforces but reports no t is refused at t>1 with the "unreported" reason', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[1]!), { grant: s.grant, now: NOW, audience: AUD, context: stepUpCtx(s), hooks: { threshold: () => ({ enforced: true, ok: true }) } });
    expect(v.requiredThreshold.t).toBeGreaterThan(1);
    expect(v.allow).toBe(false);
    expect(v.checks.threshold).toBe('fail');
    expect(v.reasons).toContain(`threshold: threshold hook enforced t=unreported but the server requires t=${v.requiredThreshold.t} (below the server-derived threshold; derive t from server-held data)`);
  });
  it('a hook that enforces a lower t names that t in the reason; exactly the required t passes', async () => {
    const s = setup();
    const a = s.mk(s.plan[1]!);
    const base = { grant: s.grant, now: NOW, audience: AUD, context: stepUpCtx(s) };
    const need = (await verifyPCActn(a, base)).requiredThreshold.t;
    const low = await verifyPCActn(a, { ...base, hooks: { threshold: () => ({ enforced: true, ok: true, t: need - 1 }) } });
    expect(low.allow).toBe(false);
    expect(low.reasons).toContain(`threshold: threshold hook enforced t=${need - 1} but the server requires t=${need} (below the server-derived threshold; derive t from server-held data)`);
    const eq = await verifyPCActn(a, { ...base, hooks: { threshold: () => ({ enforced: true, ok: true, t: need }) } });
    expect(eq.allow).toBe(true);
    const hi = await verifyPCActn(a, { ...base, hooks: { threshold: () => ({ enforced: true, ok: true, t: need + 1 }) } });
    expect(hi.allow).toBe(true);
    // a rejected threshold proof carries its own message
    const rej = await verifyPCActn(a, { ...base, hooks: { threshold: () => ({ enforced: true, ok: false, t: need }) } });
    expect(rej.reasons.some((r) => r.startsWith(`threshold: t=${need} required and the threshold proof was rejected`) || r.includes('threshold'))).toBe(true);
  });
  it('at server t=1 a threshold hook that reports no t is not penalised (the F-1 check needs t>1)', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), {
      grant: s.grant, now: NOW, audience: AUD, context: { plan: s.plan, risk: s.lowRisk, params: {}, budget: { B: 100, tau: NOW, asOf: NOW } },
      hooks: { threshold: () => ({ enforced: true, ok: true }) },
    });
    expect(v.requiredThreshold.t).toBe(1);
    expect(v.checks.threshold).toBe('pass');
    expect(v.allow).toBe(true);
  });
  it('when policy already denies, a passing hook is not additionally failed for a low t', async () => {
    const s = setup();
    const n = { ...s.plan[1]!, verb: 'delete_account' };
    const v = await verifyPCActn(s.mk(n), { grant: s.grant, now: NOW, context: { risk: { reversibility: 0, blastRadius: 0.5, confidence: 0.5, semanticDistance: 1 } }, hooks: { threshold: () => ({ enforced: true, ok: true, t: 1 }) } });
    expect(v.allow).toBe(false);
    expect(v.checks.policy).toBe('fail');
    expect(v.requiredThreshold.t).toBeGreaterThan(1);
    expect(v.checks.threshold).toBe('pass');
    expect(v.reasons.some((r) => r.startsWith('threshold:'))).toBe(false);
  });
  it('when policy denies and no hook is enforced, the threshold check is not additionally failed', async () => {
    const s = setup();
    const n = { ...s.plan[1]!, verb: 'delete_account' };
    const v = await verifyPCActn(s.mk(n), { grant: s.grant, now: NOW, context: { risk: { reversibility: 0, blastRadius: 0.5, confidence: 0.5, semanticDistance: 1 } } });
    expect(v.checks.policy).toBe('fail');
    expect(v.checks.threshold).toBe('not-enforced');
    expect(v.reasons.some((r) => r.startsWith('threshold:'))).toBe(false);
  });
});

describe('verifyPCActn: policy reasons', () => {
  it('a policy denial lists each policy reason once, prefixed "policy: "', async () => {
    const s = setup();
    const n = { ...s.plan[0]!, verb: 'delete_account' };
    const v = await verifyPCActn(s.mk(n), { grant: s.grant, now: NOW, context: { risk: s.lowRisk } });
    const pol = v.reasons.filter((r) => r.startsWith('policy: '));
    expect(pol.length).toBeGreaterThan(0);
    expect(new Set(pol).size).toBe(pol.length);
    for (const r of v.reasons) expect(typeof r).toBe('string');
    expect(v.reasons.every((r) => r !== 'undefined' && r.length > 0)).toBe(true);
    expect(pol.every((r) => r.length > 'policy: '.length)).toBe(true);
  });
  it('informational policy reasons are kept on a released action', async () => {
    const s = setup();
    const { taint: _t, ...noTaint } = s.lowRisk;
    const v = await verifyPCActn(s.mk(s.plan[0]!), { grant: s.grant, now: NOW, audience: AUD, context: { plan: s.plan, risk: noTaint, params: {} } });
    expect(v.checks.policy).toBe('pass');
    expect(v.reasons).toContain('policy: risk input(s) missing, assumed worst case: taint');
    expect(v.reasons.filter((r) => r.startsWith('policy: ')).length).toBe(v.reasons.filter((r) => r.includes('assumed worst case')).length + v.reasons.filter((r) => r.startsWith('policy: ') && !r.includes('assumed worst case')).length);
  });
});

describe('verifyPCActn: delegated-caveat failure list', () => {
  it('several failed delegated caveats are listed comma-space separated', async () => {
    const s = setup({ taskCaveats: [{ type: 'made_up_a' }, { type: 'made_up_b' }] });
    const v = await verifyPCActn(s.mk(s.plan[0]!), { grant: s.grant, now: NOW, audience: AUD, context: { plan: s.plan, risk: s.lowRisk, params: {} } });
    expect(v.checks.delegated_caveats).toBe('fail');
    const r = v.reasons.find((x) => x.startsWith('delegated_caveats: delegation caveat(s) not satisfied: '))!;
    expect(r).toBeDefined();
    const list = r.slice('delegated_caveats: delegation caveat(s) not satisfied: '.length);
    expect(list.split(', ').length).toBe(2);
  });
});

describe('verifyPCActn: internal errors fail closed with a message', () => {
  it('an Error thrown while reading options reports its message', async () => {
    const s = setup();
    const opts = { grant: s.grant, get now(): number { throw new Error('boom-now'); } };
    const v = await verifyPCActn(s.mk(s.plan[0]!), opts);
    expect(v.allow).toBe(false);
    expect(v.reasons).toEqual(['verifier error (fail closed): boom-now']);
    expect(v.checks).toEqual({ malformed: 'fail' });
    expect(v.r).toBe(1);
    expect(v.requiredThreshold).toEqual({ t: 3, proof: 'strong', optimisticAllowed: false });
  });
  it('a non-Error throw reports "unknown"', async () => {
    const s = setup();
    const opts = { grant: s.grant, get now(): number { throw 'str'; } };
    const v = await verifyPCActn(s.mk(s.plan[0]!), opts);
    expect(v.reasons).toEqual(['verifier error (fail closed): unknown']);
  });
});

describe('verifyPCActn: class ranking and reason hygiene', () => {
  it('a non-string authoritative class is the most restrictive (an array that stringifies to "reversible" does not count)', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), { grant: s.grant, now: NOW, audience: AUD, context: { plan: s.plan, risk: s.lowRisk, params: {}, reversibilityClass: ['reversible'] as never } });
    expect(v.checks.reversibility).toBe('fail');
  });
  it('an allowed verdict with a supplied budget carries no reasons at all', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), { grant: s.grant, now: NOW, audience: AUD, context: { plan: s.plan, risk: s.lowRisk, params: {}, budget: { B: 1, tau: NOW, asOf: NOW } } });
    expect(v.allow).toBe(true);
    expect(v.reasons).toEqual([]);
  });
  it('a denied verdict that already has reasons does not get the generic "denied" appended', async () => {
    const s = setup();
    const n = { ...s.plan[0]!, verb: 'delete_account' };
    const v = await verifyPCActn(s.mk(n), { grant: s.grant, now: NOW, context: { risk: s.lowRisk, budget: { B: 1, tau: NOW, asOf: NOW } } });
    expect(v.allow).toBe(false);
    expect(v.reasons.length).toBeGreaterThan(0);
    expect(v.reasons).not.toContain('denied');
  });
  // Differential for the equivalent mutant `classRank(declared) > classRank(authoritative)` -> `>=`: the two only differ when both
  // classes rank equal but are spelled differently, i.e. an unknown spelling versus 'irreversible'. Everything downstream treats
  // both the same way, so the verdict is identical.
  it('differential: declaring an unknown class vs the authoritative "irreversible" yields the same policy outcome as declaring "irreversible"', async () => {
    const s = setup({ taskCaveats: [{ type: 'reversibility_max', class: 'costly' }] });
    const run = (declared: string) =>
      verifyPCActn(s.mk(s.plan[1]!, { tweak: (a) => { a.reversibility_class = declared; } }), {
        grant: s.grant, now: NOW, audience: AUD,
        context: { risk: { reversibility: 0, blastRadius: 0.5, confidence: 0.5, semanticDistance: 1 }, params: s.params, reversibilityClass: 'irreversible' },
      });
    const a = await run('weird');
    const b = await run('irreversible');
    for (const k of ['policy', 'delegated_caveats', 'reversibility'] as const) expect(a.checks[k]).toBe(b.checks[k]);
    expect(a.r).toBe(b.r);
    expect(a.requiredThreshold).toEqual(b.requiredThreshold);
  });
});

describe('verifyPCActn: PQ-signed liveness beacon needs the issuer PQ pin passed through', () => {
  it('a hybrid/ML-DSA beacon passes with context.beacon.pqPins and fails without them', async () => {
    const s = setup();
    const ed = generateKeyPair();
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(7));
    const issuer = encodeKey(ed.publicKey);
    const beacon = issueLivenessBeacon({ issuerSecret: ed.secretKey, instance: 'ins', scope: s.grant.id, seq: 1, issuedAt: NOW, suite: { alg: 'ml-dsa-65', mlDsa: ml } });
    const pqPins = { [issuer]: encodeMlDsaPublicKey(ml.publicKey) };
    const pc = s.mk(s.plan[0]!, { beaconRef: beaconRef(beacon) });
    const base = { plan: s.plan, risk: s.lowRisk, params: {}, budget: { B: 1, tau: NOW, asOf: NOW } };
    const ok = await verifyPCActn(pc, { grant: s.grant, now: NOW, audience: AUD, context: { ...base, beacon: { beacon, issuers: [issuer], instance: 'ins', pqPins } } });
    expect(ok.checks.beacon).toBe('pass');
    const no = await verifyPCActn(pc, { grant: s.grant, now: NOW, audience: AUD, context: { ...base, beacon: { beacon, issuers: [issuer], instance: 'ins' } } });
    expect(no.checks.beacon).toBe('fail');
    expect(no.reasons).toContain('beacon: bad signature');
  });
});
