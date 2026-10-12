/**
 * One reversibility-class resolver for every reversibility_max evaluation (decide()'s envelope caveats, its delegated
 * caveats, and verifyPCActn's delegated_caveats check): the action's own class, else the class of the plan node named by
 * the signed node id, else undefined (no reversibility_max caveat accepts it). Before this, verifyPCActn evaluated delegated
 * caveats against the action's class only, without the node fallback decide() applies.
 */
import { describe, expect, it } from 'vitest';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import type { PlanNode } from './merkle';
import { decide, resolveReversibilityClass, type DecideInput } from './policy-vm';
import { DEFAULT_RISK_POLICY } from './risk';
import { validateWireV2 } from './wire';
import { setup } from './server/fixture.test-util';

const PLAN: PlanNode[] = [
  { id: 'n1', verb: 'op', resource: '/r', reversibility_class: 'reversible' },
  { id: 'n2', verb: 'op', resource: '/r', reversibility_class: 'irreversible' },
];

describe('resolveReversibilityClass', () => {
  it("the action's own class wins; null/undefined falls back to the node named by id (never by verb/resource); else undefined", () => {
    const a = (cls?: unknown) => ({ action: { verb: 'op', resource: '/r', ...(cls === undefined ? {} : { reversibility_class: cls }) } }) as never;
    expect(resolveReversibilityClass(a('costly'), PLAN, 'n2')).toBe('costly');
    expect(resolveReversibilityClass(a(), PLAN, 'n2')).toBe('irreversible');
    expect(resolveReversibilityClass(a(null), PLAN, 'n2')).toBe('irreversible');
    expect(resolveReversibilityClass(a(), PLAN, 'n1')).toBe('reversible');
    expect(resolveReversibilityClass(a(), PLAN, undefined)).toBeUndefined();
    expect(resolveReversibilityClass(a(), PLAN, 'zz')).toBeUndefined();
    expect(resolveReversibilityClass(a(), undefined, 'n2')).toBeUndefined();
    expect(resolveReversibilityClass(undefined, PLAN, 'n2')).toBe('irreversible');
    // no node id never matches a plan node that itself lacks an id
    expect(resolveReversibilityClass(a(), [{ verb: 'op', resource: '/r', reversibility_class: 'reversible' } as never], undefined)).toBeUndefined();
  });
});

describe('envelope and delegated reversibility_max reach the same verdict for a class-less action on an irreversible signed node', () => {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const grant = (caveats: Record<string, unknown>[]) =>
    mintGrant({
      principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), goal: 'g',
      envelope: { predicates: [{ verb: 'op', resource: '/r' }], caveats: caveats as never, agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
    }).grant;
  const lowRisk = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
  const base = (g: ReturnType<typeof grant>, extra: Partial<DecideInput> = {}): DecideInput => ({
    grant: g, action: { action: { verb: 'op', resource: '/r' } }, plan: PLAN, nodeId: 'n2', risk: lowRisk, budget: { B: 1, tau: 0, asOf: 0 }, now: 0, chainVerified: true, ...extra,
  });
  it('envelope caveat: denied', () => {
    const d = decide(base(grant([{ type: 'reversibility_max', class: 'reversible' }])));
    expect(d.reasons).toContain('caveat(s) not satisfied: reversibility_max');
    expect(d.releaseGuardianShare).toBe(false);
  });
  it('delegated caveat (leaf hop beyond the grant): denied the same way', () => {
    const g = grant([]);
    const leaf = { ...g, caveats: [...g.caveats, { type: 'reversibility_max', class: 'reversible' }] };
    const d = decide(base(g, { chain: [g, leaf] as never }));
    expect(d.reasons).toContain('delegated caveat(s) not satisfied: reversibility_max');
    expect(d.releaseGuardianShare).toBe(false);
  });
  it('the same node, reversible: both pass', () => {
    const d = decide(base(grant([{ type: 'reversibility_max', class: 'reversible' }]), { nodeId: 'n1' }));
    expect(d.reasons).toEqual([]);
  });
  it('the server path cannot receive a class-less action (wire v2 requires the class), so both paths see the same input there', () => {
    const s = setup();
    const p = JSON.parse(JSON.stringify(s.mk(s.plan[0]!)));
    delete p.action.reversibility_class;
    expect(validateWireV2(p)).toBe('action.verb/resource/reversibility_class must be strings');
  });
});
