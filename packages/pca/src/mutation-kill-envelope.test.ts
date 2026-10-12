/** Mutation-kill tests for envelope.ts: mintGrant argument checks and optional-field inclusion, readEnvelope structural guards. */
import { describe, expect, it } from 'vitest';
import { mintRoot, type Capability } from './capability';
import { ENVELOPE_CAVEAT, mintGrant, readEnvelope, type Envelope } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY, validateRiskPolicy } from './risk';

const P = generateKeyPair();
const A = generateKeyPair();
const principalPublic = encodeKey(P.publicKey);
const holder = encodeKey(A.publicKey);
const env = (over: Record<string, unknown> = {}): Omit<Envelope, 'goal_commit'> =>
  ({ predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY, ...over }) as never;
const mint = (e: Omit<Envelope, 'goal_commit'>, over: Record<string, unknown> = {}) =>
  mintGrant({ principalSecret: P.secretKey, principalPublic, holder, envelope: e, goal: 'g', salt: 's', ...over } as never);
/** A grant whose caveats list is exactly `caveats` (for readEnvelope's structural guards). */
const raw = (caveats: unknown[]): Capability => mintRoot({ principalSecret: P.secretKey, principalPublic, holder, caveats: caveats as never });
const okEnv = { goal_commit: 'c', predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY };

describe('mintGrant', () => {
  it('requires a non-empty string goal', () => {
    for (const goal of ['', 5, undefined, null]) expect(() => mint(env(), { goal })).toThrow(new Error('mintGrant: goal required'));
  });
  it('rejects an invalid risk policy with the validator message', () => {
    const rp = { ...DEFAULT_RISK_POLICY, kappa: -1 };
    const msg = validateRiskPolicy(rp);
    expect(msg).toBeTruthy();
    expect(() => mint(env({ risk_policy: rp }))).toThrow(new Error(`mintGrant: ${msg}`));
  });
  it('includes objective_risk and progress in the signed envelope exactly when given', () => {
    const none = readEnvelope(mint(env()).grant)!;
    expect('objective_risk' in none).toBe(false);
    expect('progress' in none).toBe(false);
    const both = readEnvelope(mint(env({ objective_risk: { a: 1 }, progress: { v: 1 } })).grant)!;
    expect(both.objective_risk).toEqual({ a: 1 });
    expect(both.progress).toEqual({ v: 1 });
    const onlyProgress = readEnvelope(mint(env({ progress: { v: 1 } })).grant)!;
    expect('objective_risk' in onlyProgress).toBe(false);
    expect(onlyProgress.progress).toEqual({ v: 1 });
    const onlyRisk = readEnvelope(mint(env({ objective_risk: { a: 1 } })).grant)!;
    expect('progress' in onlyRisk).toBe(false);
  });
  it('defaults a missing agent_binding to {}', () => {
    expect(readEnvelope(mint(env({ agent_binding: undefined })).grant)!.agent_binding).toEqual({});
  });
  it('refuses an envelope that is not strict-canonical-encodable', () => {
    expect(() => mint(env({ progress: { x: 1e-7 } }))).toThrow(TypeError);
    expect(() => mint(env({ caveats: [{ type: 'rate', max: 2 ** 60 }] }))).toThrow(TypeError);
  });
  it('commits the holder PQ key only when given', () => {
    expect(mint(env()).grant).not.toHaveProperty('holder_pq');
    expect(mint(env(), { holderPq: 'PQKEY' }).grant).toHaveProperty('holder_pq');
  });
});

describe('readEnvelope', () => {
  const cv = (o: Record<string, unknown> = {}) => JSON.parse(JSON.stringify({ type: ENVELOPE_CAVEAT, ...okEnv, ...o })) as Record<string, unknown>;
  it('reads the first envelope caveat, skipping other caveat types and null entries', () => {
    expect(readEnvelope(raw([{ type: 'expires', at: 1 }, cv()]))).toEqual(okEnv);
    expect(readEnvelope(raw([null, cv()]))).toEqual(okEnv);
    expect(readEnvelope(raw([cv({ goal_commit: 'first' }), cv({ goal_commit: 'second' })]))!.goal_commit).toBe('first');
  });
  it('returns null for absent / unusable grants and caveats', () => {
    expect(readEnvelope(null as never)).toBeNull();
    expect(readEnvelope(undefined as never)).toBeNull();
    expect(readEnvelope({} as never)).toBeNull();
    expect(readEnvelope(raw([]))).toBeNull();
    expect(readEnvelope(raw([{ type: 'expires', at: 1 }]))).toBeNull();
  });
  it('a grant whose caveats cannot be read yields null instead of throwing', () => {
    const g = {} as Capability;
    Object.defineProperty(g, 'caveats', {
      get() {
        throw new Error('boom');
      },
    });
    expect(readEnvelope(g)).toBeNull();
  });
  it('each structural guard rejects on its own', () => {
    expect(readEnvelope(raw([cv({ goal_commit: 5 })]))).toBeNull();
    expect(readEnvelope(raw([cv({ goal_commit: undefined })]))).toBeNull();
    expect(readEnvelope(raw([cv({ predicates: 'x' })]))).toBeNull();
    expect(readEnvelope(raw([cv({ caveats: 'x' })]))).toBeNull();
    expect(readEnvelope(raw([cv({ agent_binding: null })]))).toBeNull();
    expect(readEnvelope(raw([cv({ agent_binding: 'x' })]))).toBeNull();
    expect(readEnvelope(raw([cv({ agent_binding: undefined })]))).toBeNull();
    expect(readEnvelope(raw([cv({ risk_policy: { ...DEFAULT_RISK_POLICY, kappa: -1 } })]))).toBeNull();
    expect(readEnvelope(raw([cv({ risk_policy: undefined })]))).toBeNull();
    expect(readEnvelope(raw([cv({ goal_commit: '' })]))).not.toBeNull();
  });
});
