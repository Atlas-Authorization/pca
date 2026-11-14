import { describe, expect, it } from 'vitest';
import { DEFAULT_RISK_POLICY, type Capability, type Caveat, type Predicate } from '@atlasauth/pca';
import { fromGrant, isCapability, isEnvelope, normalizeChain, normalizePolicyInput } from './normalize';

const PRED: Predicate = { verb: 'docs.read', resource: '/docs/*' };
const EXP: Caveat = { type: 'expires', at: 4_000_000_000_000 };
const RATE: Caveat = { type: 'rate', max: 5, per_secs: 60 };

const envelope = (predicates: Predicate[] = [PRED], caveats: Caveat[] = [EXP]) => ({
  goal_commit: 'commit',
  predicates,
  caveats,
  agent_binding: {},
  risk_policy: DEFAULT_RISK_POLICY,
});
const envCaveat = (predicates?: Predicate[], caveats?: Caveat[]): Caveat => ({ type: 'envelope', ...envelope(predicates, caveats) }) as Caveat;
const grant = (caveats: Caveat[]): Capability => ({ id: 'i', issuer: 'p', holder: 'h', body_digest: 'b', sig: 's', caveats });

describe('isCapability', () => {
  it('accepts the full shape and rejects each missing or mistyped member', () => {
    const ok = grant([]);
    expect(isCapability(ok)).toBe(true);
    for (const k of ['id', 'issuer', 'holder', 'body_digest', 'sig'] as const) {
      expect(isCapability({ ...ok, [k]: 5 })).toBe(false);
      const { [k]: _gone, ...rest } = ok;
      void _gone;
      expect(isCapability(rest)).toBe(false);
    }
    expect(isCapability({ ...ok, caveats: 'x' })).toBe(false);
    expect(isCapability({ ...ok, caveats: undefined })).toBe(false);
  });
  it('rejects non-records', () => {
    expect(isCapability(null)).toBe(false);
    expect(isCapability(5)).toBe(false);
    expect(isCapability('x')).toBe(false);
    expect(isCapability([])).toBe(false);
    expect(isCapability(undefined)).toBe(false);
  });
});

describe('isEnvelope', () => {
  it('accepts the full shape and rejects each missing or mistyped member', () => {
    const ok = envelope();
    expect(isEnvelope(ok)).toBe(true);
    for (const k of ['goal_commit', 'predicates', 'caveats', 'agent_binding', 'risk_policy'] as const) {
      expect(isEnvelope({ ...ok, [k]: 5 })).toBe(false);
      const { [k]: _gone, ...rest } = ok;
      void _gone;
      expect(isEnvelope(rest)).toBe(false);
    }
    expect(isEnvelope({ ...ok, agent_binding: [] })).toBe(false);
    expect(isEnvelope({ ...ok, risk_policy: null })).toBe(false);
  });
  it('rejects non-records', () => {
    expect(isEnvelope(null)).toBe(false);
    expect(isEnvelope('x')).toBe(false);
    expect(isEnvelope([])).toBe(false);
    expect(isEnvelope(undefined)).toBe(false);
  });
});

describe('normalizePolicyInput kinds', () => {
  it('an envelope is read as an envelope', () => {
    const e = envelope();
    expect(normalizePolicyInput(e)).toEqual({ ok: true, policy: { predicates: e.predicates, caveats: e.caveats, riskPolicy: DEFAULT_RISK_POLICY, kind: 'envelope' } });
  });
  it('a compiled policy needs predicates, caveats, riskPolicy and actions', () => {
    const c = { predicates: [PRED], caveats: [EXP], riskPolicy: DEFAULT_RISK_POLICY, actions: [] };
    expect(normalizePolicyInput(c)).toEqual({ ok: true, policy: { predicates: [PRED], caveats: [EXP], riskPolicy: DEFAULT_RISK_POLICY, kind: 'compiled' } });
    for (const k of ['actions', 'riskPolicy', 'caveats'] as const) {
      const { [k]: _gone, ...rest } = c;
      void _gone;
      const r = normalizePolicyInput(rest);
      expect(r).toMatchObject({ ok: true, policy: { kind: 'bare' } });
    }
    expect(normalizePolicyInput({ ...c, actions: 'x' })).toMatchObject({ ok: true, policy: { kind: 'bare' } });
    expect(normalizePolicyInput({ ...c, riskPolicy: 'x' })).toMatchObject({ ok: true, policy: { kind: 'bare' } });
    expect(normalizePolicyInput({ ...c, caveats: 'x' })).toMatchObject({ ok: true, policy: { kind: 'bare', caveats: [] } });
    expect(normalizePolicyInput({ predicates: [PRED], caveats: [EXP], actions: [] })).toMatchObject({ policy: { kind: 'bare' } });
    expect(normalizePolicyInput([PRED])).toMatchObject({ ok: false });
  });
  it('a bare policy defaults its caveats to empty', () => {
    expect(normalizePolicyInput({ predicates: [PRED] })).toEqual({ ok: true, policy: { predicates: [PRED], caveats: [], kind: 'bare' } });
    expect(normalizePolicyInput({ predicates: [PRED], caveats: [EXP] })).toEqual({ ok: true, policy: { predicates: [PRED], caveats: [EXP], kind: 'bare' } });
  });
  it('anything else is refused with the shape message', () => {
    expect(normalizePolicyInput({})).toEqual({ ok: false, reason: 'unrecognized policy shape (expected an envelope, grant, compiled policy, or { predicates, caveats })' });
  });
});

describe('fromGrant', () => {
  it('combines the envelope caveats with the appended gate caveats and drops envelopes and non-objects', () => {
    const g = grant([envCaveat(), RATE, null as never, 'x' as never, envCaveat([{ verb: 'other' }])]);
    expect(fromGrant(g)).toEqual({ ok: true, policy: { predicates: [PRED], caveats: [EXP, RATE], riskPolicy: DEFAULT_RISK_POLICY, kind: 'grant' } });
  });
  it('a grant with no readable envelope is refused with the exact reason', () => {
    expect(fromGrant(grant([]))).toEqual({ ok: false, reason: 'grant has no readable `envelope` caveat (malformed or unsigned payload)' });
    expect(normalizePolicyInput(grant([RATE]))).toEqual({ ok: false, reason: 'grant has no readable `envelope` caveat (malformed or unsigned payload)' });
  });
  it('a grant input is read as a grant, ahead of the envelope shape', () => {
    expect(normalizePolicyInput(grant([envCaveat(), RATE]))).toMatchObject({ ok: true, policy: { kind: 'grant', caveats: [EXP, RATE] } });
  });
});

describe('normalizeChain', () => {
  it('an empty chain and a chain of holes are refused', () => {
    expect(normalizeChain([])).toEqual({ ok: false, reason: 'empty chain' });
    expect(normalizeChain(new Array(1))).toEqual({ ok: false, reason: 'empty chain' });
  });
  it('a chain of grants shares the ROOT envelope predicates and appends each hop’s own gate caveats', () => {
    const root = grant([envCaveat([PRED], [EXP])]);
    const child = grant([envCaveat([{ verb: 'ignored' }], []), RATE, null as never]);
    expect(normalizeChain([root, child])).toEqual({
      ok: true,
      hops: [
        { predicates: [PRED], caveats: [EXP], riskPolicy: DEFAULT_RISK_POLICY, kind: 'chain-hop' },
        { predicates: [PRED], caveats: [EXP, RATE], riskPolicy: DEFAULT_RISK_POLICY, kind: 'chain-hop' },
      ],
    });
  });
  it('a chain whose root grant has no readable envelope is refused', () => {
    expect(normalizeChain([grant([RATE])])).toEqual({ ok: false, reason: 'root grant has no readable `envelope` caveat' });
  });
  it('a mixed chain takes each hop as-is (a grant keeps its own envelope)', () => {
    const r = normalizeChain([grant([envCaveat([PRED], [EXP])]), { predicates: [], caveats: [RATE] }]);
    expect(r).toEqual({
      ok: true,
      hops: [
        { predicates: [PRED], caveats: [EXP], riskPolicy: DEFAULT_RISK_POLICY, kind: 'chain-hop' },
        { predicates: [], caveats: [RATE], kind: 'chain-hop' },
      ],
    });
  });
  it('a chain of effective hops is taken as-is, with chain-hop kind', () => {
    const r = normalizeChain([{ predicates: [PRED] }, { predicates: [PRED], caveats: [EXP] }]);
    expect(r).toEqual({
      ok: true,
      hops: [
        { predicates: [PRED], caveats: [], kind: 'chain-hop' },
        { predicates: [PRED], caveats: [EXP], kind: 'chain-hop' },
      ],
    });
  });
  it('an unusable hop is reported with its index', () => {
    expect(normalizeChain([{ predicates: [] }, 5])).toEqual({
      ok: false,
      reason: 'hop 1: unrecognized policy shape (expected an envelope, grant, compiled policy, or { predicates, caveats })',
    });
    expect(normalizeChain([7])).toMatchObject({ ok: false, reason: expect.stringMatching(/^hop 0: /) });
  });
});
