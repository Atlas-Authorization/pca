/* eslint-disable @typescript-eslint/no-explicit-any */
// Mutation-kill tests for src/ext-attest.ts. Deterministic cases, each checked against the production implementation
// (packages/pca/src/attestation.ts) AND against literal expected values so that a drift in both cannot hide.
import { describe, expect, it } from 'vitest';
import { createMultiRootVerifier, matchAgentBinding, memoryNonceStore, requiresAttestation } from './support/legacy/attestation';
import {
  VerifiedMemoryNonceStore,
  allowlistGate,
  createMultiRootVerifierVerified,
  matchAgentBindingVerified,
  requiresAttestationVerified,
  type AllowlistGateFacts,
} from '../src/ext-attest';

const id = (o: Record<string, unknown> = {}): any => ({
  model_id: 'm', weights_digest: 'w', weights_measured: true, runtime_measurement: '7', operator: 'op', system_prompt_digest: 'sp', tool_manifest_digest: 'tm', ...o,
});

describe('matchAgentBindingVerified', () => {
  const same = (identity: any, binding: any, expected: string | null) => {
    expect(matchAgentBindingVerified(identity, binding)).toBe(expected);
    expect(matchAgentBinding(identity, binding)).toBe(expected);
  };
  it('each failure reason, byte for byte', () => {
    same(id(), undefined, null);
    same(id(), {}, null);
    same(id({ model_id: 'x' }), { model_allowlist: ['m2'] }, 'model_id x not in model_allowlist');
    same(id({ runtime_measurement: 'a' }), { min_measurement: 'b' }, 'runtime_measurement does not match required min_measurement');
    same(id({ runtime_measurement: 'abc' }), { min_measurement: { svn: 5 } }, 'runtime_measurement abc is not an integer SVN (required min svn 5)');
    same(id({ runtime_measurement: '3' }), { min_measurement: { svn: 5 } }, 'runtime_measurement svn 3 is below required min svn 5');
    same(id({ operator: 'zz' }), { operator: 'op2' }, 'operator zz is not the bound operator');
    same(id({ weights_measured: false }), { require_measured_weights: true }, 'weights_digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)');
    same(id({ weights_digest: 'w9' }), { weights_allowlist: ['w'] }, 'weights_digest not in weights_allowlist (model swap / fine-tune?)');
    same(id({ system_prompt_digest: 'x' }), { system_prompt_allowlist: ['sp'] }, 'system_prompt_digest not in system_prompt_allowlist (instructions changed / prompt injection?)');
    same(id({ tool_manifest_digest: 'x' }), { tool_manifest_allowlist: ['tm'] }, 'tool_manifest_digest not in tool_manifest_allowlist (tools changed?)');
  });
  it('acceptance paths and edge shapes', () => {
    same(id(), { model_allowlist: ['m'], min_measurement: '7', operator: 'op', weights_allowlist: ['w'], system_prompt_allowlist: ['sp'], tool_manifest_allowlist: ['tm'], require_measured_weights: true }, null);
    same(id({ runtime_measurement: '9' }), { min_measurement: { svn: 9 } }, null);
    same(id({ runtime_measurement: '12' }), { min_measurement: { svn: 9 } }, null);
    same(id({ runtime_measurement: '' }), { min_measurement: { svn: 0 } }, 'runtime_measurement  is not an integer SVN (required min svn 0)');
    same(id({ runtime_measurement: ' ' }), { min_measurement: { svn: 0 } }, 'runtime_measurement   is not an integer SVN (required min svn 0)');
    same(id({ runtime_measurement: '7.5' }), { min_measurement: { svn: 1 } }, 'runtime_measurement 7.5 is not an integer SVN (required min svn 1)');
    same(id({ runtime_measurement: 'anything' }), { min_measurement: '' }, null);
    same(id({ operator: 'anything' }), { operator: '' }, null);
    same(id({ operator: 'anything' }), { operator: 5 }, null);
    same(id({ weights_measured: false }), { require_measured_weights: false }, null);
    same(id({ weights_measured: undefined }), { require_measured_weights: 'yes' }, null);
    same(id({ weights_measured: 'true' }), { require_measured_weights: true }, 'weights_digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)');
    // empty / non-array allowlists constrain nothing
    same(id({ model_id: 'x' }), { model_allowlist: [] }, null);
    same(id({ model_id: 'x' }), { model_allowlist: 'm' }, null);
    // pinned prompt digest but the identity omits it -> fail closed
    const noSp = id();
    delete noSp.system_prompt_digest;
    same(noSp, { system_prompt_allowlist: ['sp'] }, 'system_prompt_digest not in system_prompt_allowlist (instructions changed / prompt injection?)');
    const noTm = id();
    delete noTm.tool_manifest_digest;
    same(noTm, { tool_manifest_allowlist: ['tm'] }, 'tool_manifest_digest not in tool_manifest_allowlist (tools changed?)');
    same(noSp, {}, null);
  });
  it('check order: model, min, operator, measured, weights, prompt, tools', () => {
    const bad = id({ model_id: 'x', runtime_measurement: 'a', operator: 'o2', weights_measured: false, weights_digest: 'w2', system_prompt_digest: 's2', tool_manifest_digest: 't2' });
    const b: any = { model_allowlist: ['m'], min_measurement: 'b', operator: 'op', require_measured_weights: true, weights_allowlist: ['w'], system_prompt_allowlist: ['sp'], tool_manifest_allowlist: ['tm'] };
    const steps: Array<[string, string]> = [
      ['model_allowlist', 'model_id x not in model_allowlist'],
      ['min_measurement', 'runtime_measurement does not match required min_measurement'],
      ['operator', 'operator o2 is not the bound operator'],
      ['require_measured_weights', 'weights_digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)'],
      ['weights_allowlist', 'weights_digest not in weights_allowlist (model swap / fine-tune?)'],
      ['system_prompt_allowlist', 'system_prompt_digest not in system_prompt_allowlist (instructions changed / prompt injection?)'],
      ['tool_manifest_allowlist', 'tool_manifest_digest not in tool_manifest_allowlist (tools changed?)'],
    ];
    const cur: any = { ...b };
    for (const [k, msg] of steps) {
      same(bad, cur, msg);
      delete cur[k];
    }
    same(bad, cur, null);
  });
  it('a non-string runtime type never throws: it is a non-integer SVN (the oracle threw a TypeError there)', () => {
    const idBad = id({ runtime_measurement: undefined });
    expect(matchAgentBindingVerified(idBad, { min_measurement: { svn: 3 } })).toBe('runtime_measurement undefined is not an integer SVN (required min svn 3)');
    expect(() => matchAgentBinding(idBad, { min_measurement: { svn: 3 } })).toThrow(TypeError);
    expect(matchAgentBindingVerified(id({ model_id: 'x', runtime_measurement: undefined }), { model_allowlist: ['m'], min_measurement: { svn: 3 } })).toBe('model_id x not in model_allowlist');
    expect(matchAgentBindingVerified(idBad, { min_measurement: 'x' })).toBe('runtime_measurement does not match required min_measurement');
    expect(matchAgentBindingVerified(idBad, {})).toBeNull();
  });
});

// 0.4.2 (JS-semantics audit): min_measurement / SVN are STRICT. The hand-written code (frozen oracle) parsed the runtime SVN with Number()
// ("0x10", "1e1", " 8 " counted) and silently ignored a malformed min_measurement ({svn: "5"} enforced nothing: fail OPEN). The proved
// MatchBinding has a MinBad case that fails closed; these cases pin the new behaviour and that the oracle really differed.
describe('matchAgentBindingVerified: strict SVN (fail closed)', () => {
  const BAD = 'min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)';
  const notInt = (rt: unknown, svn: number) => `runtime_measurement ${rt} is not an integer SVN (required min svn ${svn})`;
  it('a malformed min_measurement fails closed (the hand-written oracle accepted these)', () => {
    const malformed: unknown[] = [
      { svn: '5' }, { svn: Number.NaN }, { svn: Number.POSITIVE_INFINITY }, { svn: -1 }, { svn: 1.5 }, { svn: -0 }, { svn: 2 ** 53 },
      {}, { svn: 5, extra: 1 }, { svn: null }, null, 5, true, ['x'], Object.assign(Object.create({ inherited: 1 }), { svn: 5 }),
    ];
    for (const mm of malformed) {
      expect(matchAgentBindingVerified(id({ runtime_measurement: '9' }), { min_measurement: mm } as any), JSON.stringify(mm)).toBe(BAD);
      expect(requiresAttestationVerified({ min_measurement: mm } as any)).toBe(true);
    }
    // what the oracle used to do (enforced nothing), kept to prove the change is real
    expect(matchAgentBinding(id({ runtime_measurement: 'anything' }), { min_measurement: { svn: '5' } } as any)).toBeNull();
    expect(requiresAttestation({ min_measurement: { svn: '5' } } as any)).toBe(false);
  });
  it('the model allowlist still decides first; well-formed shapes still work', () => {
    expect(matchAgentBindingVerified(id({ model_id: 'x' }), { model_allowlist: ['m'], min_measurement: { svn: '5' } } as any)).toBe('model_id x not in model_allowlist');
    expect(matchAgentBindingVerified(id({ runtime_measurement: '5' }), { min_measurement: Object.assign(Object.create(null), { svn: 5 }) } as any)).toBeNull();
    expect(matchAgentBindingVerified(id({ runtime_measurement: '0' }), { min_measurement: { svn: 0 } })).toBeNull();
    expect(matchAgentBindingVerified(id({ runtime_measurement: '9007199254740991' }), { min_measurement: { svn: 9007199254740991 } })).toBeNull();
    expect(matchAgentBindingVerified(id({ runtime_measurement: 'anything' }), { min_measurement: '' })).toBeNull();
    expect(matchAgentBindingVerified(id({ runtime_measurement: 'anything' }), { min_measurement: undefined })).toBeNull();
    expect(requiresAttestationVerified({ min_measurement: '' })).toBe(false);
    expect(requiresAttestationVerified({ min_measurement: undefined })).toBe(false);
  });
  it('the runtime SVN must be canonical decimal text of a safe integer (Number() spellings are refused)', () => {
    for (const rt of ['0x10', '1e1', ' 8 ', '8 ', ' 8', '08', '+8', '-1', '7.0', '1_0', '９', '9007199254740993', '', ' ']) {
      expect(matchAgentBindingVerified(id({ runtime_measurement: rt }), { min_measurement: { svn: 1 } }), rt).toBe(notInt(rt, 1));
    }
    for (const rt of [undefined, 8, null, ['8']]) {
      expect(matchAgentBindingVerified(id({ runtime_measurement: rt }), { min_measurement: { svn: 1 } }), String(rt)).toBe(notInt(rt, 1));
    }
    // the oracle accepted these as SVN 16 / 10 / 8 (or threw on a non-string)
    expect(matchAgentBinding(id({ runtime_measurement: '0x10' }), { min_measurement: { svn: 1 } })).toBeNull();
    expect(matchAgentBinding(id({ runtime_measurement: '1e1' }), { min_measurement: { svn: 1 } })).toBeNull();
    expect(matchAgentBinding(id({ runtime_measurement: ' 8 ' }), { min_measurement: { svn: 1 } })).toBeNull();
    expect(matchAgentBindingVerified(id({ runtime_measurement: '10' }), { min_measurement: { svn: 11 } })).toBe('runtime_measurement svn 10 is below required min svn 11');
    expect(matchAgentBindingVerified(id({ runtime_measurement: '11' }), { min_measurement: { svn: 11 } })).toBeNull();
  });
});

describe('requiresAttestationVerified', () => {
  const cases: Array<[any, boolean]> = [
    [undefined, false], [{}, false], [null, false],
    [{ model_allowlist: [] }, false], [{ model_allowlist: ['a'] }, true], [{ model_allowlist: 'a' }, false],
    [{ min_measurement: '' }, false], [{ min_measurement: 'a' }, true], [{ min_measurement: { svn: 1 } }, true], [{ min_measurement: { svn: 0 } }, true],
    [{ operator: '' }, false], [{ operator: 'o' }, true], [{ operator: 5 }, false],
    [{ weights_allowlist: [] }, false], [{ weights_allowlist: ['w'] }, true],
    [{ system_prompt_allowlist: [] }, false], [{ system_prompt_allowlist: ['s'] }, true],
    [{ tool_manifest_allowlist: [] }, false], [{ tool_manifest_allowlist: ['t'] }, true],
    [{ require_hardware: true }, true], [{ require_hardware: false }, false], [{ require_hardware: 1 }, false],
    [{ require_measured_weights: true }, true], [{ require_measured_weights: false }, false], [{ require_measured_weights: 'true' }, false],
  ];
  it.each(cases.map((c, i) => [i, c[0], c[1]] as const))('case %i %j -> %s', (_i, b, exp) => {
    expect(requiresAttestationVerified(b)).toBe(exp);
    expect(requiresAttestation(b)).toBe(exp);
  });
});

describe('VerifiedMemoryNonceStore', () => {
  it('single use within retention, refuses when full of live entries, default capacity 100000 (identical to memoryNonceStore)', () => {
    for (const max of [1, 2, 3]) {
      let t = 0;
      const a = new VerifiedMemoryNonceStore(max, { retentionMs: 4, now: () => t });
      const b = memoryNonceStore(max, { retentionMs: 4, now: () => t });
      const seq = ['a', 'b', 'a', 'c', 'a', 'd', 'b', 'c', 'c', 'e', 'a'];
      for (const n of seq) { t++; expect(a.consume(n), `max=${max} ${n} t=${t}`).toBe(b.consume(n) as boolean); }
    }
    {
      const a = new VerifiedMemoryNonceStore(1);
      expect([a.consume('a'), a.consume('b'), a.consume('a')]).toEqual([true, false, false]); // full of a live nonce: refused, 'a' kept
    }
    const s = new VerifiedMemoryNonceStore();
    expect(s.consume('x')).toBe(true);
    expect(s.consume('x')).toBe(false);
    expect(s.consume('y')).toBe(true);
    expect(s.consume('x')).toBe(false);
    const big = new VerifiedMemoryNonceStore(100_000);
    for (let i = 0; i < 1000; i++) expect(big.consume(`n${i}`)).toBe(true);
    for (let i = 0; i < 1000; i++) expect(big.consume(`n${i}`)).toBe(false);
  });
  it('aged-out entries are dropped (only those), at exactly the retention boundary', () => {
    let t = 0;
    const s = new VerifiedMemoryNonceStore(2, { retentionMs: 100, now: () => t });
    expect(s.consume('a')).toBe(true);
    t = 50;
    expect(s.consume('b')).toBe(true);
    t = 99;
    expect(s.consume('c')).toBe(false);
    expect(s.consume('a')).toBe(false);
    t = 100;
    expect(s.consume('c')).toBe(true);
    expect(s.consume('b')).toBe(false);
    expect(s.consume('a')).toBe(false); // full of live entries (b, c)
    expect(s.consume(5 as never)).toBe(false);
  });
  it('construction checks', () => {
    for (const m of [0, -1, 1.5, Number.NaN]) expect(() => new VerifiedMemoryNonceStore(m)).toThrow(TypeError);
    expect(() => new VerifiedMemoryNonceStore(1, { retentionMs: 0 })).toThrow(TypeError);
    expect(() => new VerifiedMemoryNonceStore(1, { retentionMs: 2.5, now: () => 0 })).toThrow(new TypeError('memoryNonceStore: retentionMs must be a positive integer (ms)')); // same as production
    expect(() => memoryNonceStore(1, { retentionMs: 2.5 })).toThrow(new TypeError('memoryNonceStore: retentionMs must be a positive integer (ms)'));
  });
});

describe('allowlistGate', () => {
  const base: AllowlistGateFacts = {
    shapeOk: true, issuerKnown: true, algMatches: true, issuerLive: true, sigOk: true,
    nowMs: 1000, skew: 0, notBefore: 500, expiresAt: 2000, version: 5, digest: 'd',
  };
  const g = (o: Partial<AllowlistGateFacts>) => allowlistGate({ ...base, ...o });
  it('accepts the base facts and reports each rule with its precedence', () => {
    expect(g({})).toBeUndefined();
    expect(g({ shapeOk: false })).toBe('shape');
    expect(g({ issuerKnown: false })).toBe('unknown-issuer');
    expect(g({ algMatches: false })).toBe('alg-mismatch');
    expect(g({ issuerLive: false })).toBe('issuer-expired');
    expect(g({ sigOk: false })).toBe('bad-signature');
    expect(g({ nowMs: 499 })).toBe('not-yet-valid');
    expect(g({ nowMs: 500 })).toBeUndefined();
    expect(g({ nowMs: 2001 })).toBe('expired');
    expect(g({ nowMs: 2000 })).toBeUndefined();
    const all = { shapeOk: false, issuerKnown: false, algMatches: false, issuerLive: false, sigOk: false };
    const order: Array<[Partial<AllowlistGateFacts>, string]> = [
      [{}, 'shape'], [{ shapeOk: true }, 'unknown-issuer'], [{ shapeOk: true, issuerKnown: true }, 'alg-mismatch'],
      [{ shapeOk: true, issuerKnown: true, algMatches: true }, 'issuer-expired'], [{ shapeOk: true, issuerKnown: true, algMatches: true, issuerLive: true }, 'bad-signature'],
    ];
    for (const [o, k] of order) expect(g({ ...all, ...o })).toBe(k);
  });
  it('validity window honours skew (floored) on both sides', () => {
    expect(g({ nowMs: 495, skew: 5 })).toBeUndefined();
    expect(g({ nowMs: 494, skew: 5 })).toBe('not-yet-valid');
    expect(g({ nowMs: 2005, skew: 5 })).toBeUndefined();
    expect(g({ nowMs: 2006, skew: 5 })).toBe('expired');
    expect(g({ nowMs: 495, skew: 5.9 })).toBeUndefined();
    expect(g({ nowMs: 494, skew: 5.9 })).toBe('not-yet-valid');
    expect(g({ nowMs: 2006, skew: 5.9 })).toBe('expired');
  });
  it('invalid numeric options are the proved `options` reject, right after the signature; a negative skew clamps to 0', () => {
    expect(g({ skew: -1 })).toBeUndefined();
    expect(g({ nowMs: 499, skew: -1 })).toBe('not-yet-valid');
    expect(g({ skew: Number.NaN })).toBe('options');
    expect(g({ skew: Number.POSITIVE_INFINITY })).toBe('options');
    expect(g({ maxLifetimeMs: Number.NaN })).toBe('options');
    expect(g({ minVersion: Number.NaN })).toBe('options');
    expect(g({ lastSeenVersion: 2.5 })).toBe('options');
    expect(g({ skew: Number.NaN, sigOk: false })).toBe('bad-signature');
    expect(g({ skew: 0 })).toBeUndefined();
  });
  it('lifetime cap, minimum version, rollback and same-version conflict', () => {
    expect(g({ maxLifetimeMs: 1500 })).toBeUndefined();
    expect(g({ maxLifetimeMs: 1499 })).toBe('lifetime-too-long');
    expect(g({ maxLifetimeMs: 0 })).toBe('lifetime-too-long');
    expect(g({ maxLifetimeMs: undefined })).toBeUndefined();
    expect(g({ minVersion: 5 })).toBeUndefined();
    expect(g({ minVersion: 6 })).toBe('below-min-version');
    expect(g({ minVersion: 0 })).toBeUndefined();
    expect(g({ version: -1, minVersion: 0 })).toBe('below-min-version');
    expect(g({ lastSeenVersion: 5 })).toBeUndefined();
    expect(g({ lastSeenVersion: 4 })).toBeUndefined();
    expect(g({ lastSeenVersion: 6 })).toBe('rollback');
    expect(g({ version: -1, lastSeenVersion: 0 })).toBe('rollback');
    expect(g({ lastSeenVersion: undefined })).toBeUndefined();
    expect(g({ lastSeenVersion: 5, lastSeenDigest: 'd' })).toBeUndefined();
    expect(g({ lastSeenVersion: 5, lastSeenDigest: 'other' })).toBe('conflict');
    expect(g({ lastSeenVersion: 4, lastSeenDigest: 'other' })).toBeUndefined();
    expect(g({ lastSeenDigest: 'other' })).toBeUndefined(); // no last-seen version: the digest alone is not compared
    expect(g({ lastSeenVersion: 0, lastSeenDigest: 'other', version: 0 })).toBe('conflict');
    expect(g({ lastSeenVersion: 0, version: 0 })).toBeUndefined();
    // rule precedence among the tail
    expect(g({ maxLifetimeMs: 1, minVersion: 99, lastSeenVersion: 99, lastSeenDigest: 'o' })).toBe('lifetime-too-long');
    expect(g({ minVersion: 99, lastSeenVersion: 99, lastSeenDigest: 'o' })).toBe('below-min-version');
    expect(g({ lastSeenVersion: 6, lastSeenDigest: 'o' })).toBe('rollback');
  });
});

describe('createMultiRootVerifierVerified', () => {
  const ident = (o: Record<string, unknown> = {}) => ({ model_id: 'm', weights_digest: 'w', weights_measured: true, runtime_measurement: 'r', operator: 'op', ...o });
  const okRoot = (m: any, extra: Record<string, unknown> = {}) => ({ verify: async () => ({ ok: true, bound: true, measured: m, ...extra }) });
  const both = async (roots: any[], threshold: number, input: any = {}) => {
    const a = await createMultiRootVerifier({ roots, threshold } as any).verify(input);
    const b = await createMultiRootVerifierVerified({ roots, threshold } as any).verify(input);
    expect(JSON.stringify(b)).toBe(JSON.stringify(a));
    return b;
  };
  it('success shape: measured identity, optional digests present only when non-empty, hostAsserted prefixed by root id', async () => {
    const r = await both([{ id: 'a', verifier: okRoot(ident({ system_prompt_digest: 'sp', tool_manifest_digest: 'tm' }), { hostAsserted: { k: 'v' } }) }, { id: 'b', verifier: okRoot(ident({ system_prompt_digest: 'sp', tool_manifest_digest: 'tm' }), { hostAsserted: { z: 'q' } }) }], 2);
    expect(r).toEqual({
      ok: true, bound: true,
      measured: { model_id: 'm', weights_digest: 'w', weights_measured: true, runtime_measurement: 'r', operator: 'op', system_prompt_digest: 'sp', tool_manifest_digest: 'tm' },
      hostAsserted: { 'a.k': 'v', 'b.z': 'q' },
    });
    const r2 = await both([{ id: 'a', verifier: okRoot(ident()) }], 1);
    expect(r2).toEqual({ ok: true, bound: true, measured: { model_id: 'm', weights_digest: 'w', weights_measured: true, runtime_measurement: 'r', operator: 'op' } });
    expect(Object.keys(r2)).toEqual(['ok', 'bound', 'measured']);
    const r3 = await both([{ id: 'a', verifier: okRoot(ident({ weights_measured: false })) }], 1);
    expect((r3 as any).measured.weights_measured).toBe(false);
  });
  it('failure reasons: threshold, required root, identity conflict on each field, thrown root, malformed result', async () => {
    const conflict = async (field: string) => {
      const r = await both([{ id: 'a', verifier: okRoot(ident({ [field]: 'x' })) }, { id: 'b', verifier: okRoot(ident({ [field]: 'y' })) }], 2);
      expect((r as any).reason).toBe(`multi-root attestation identity conflict: roots 'a' and 'b' disagree on ${field}`);
    };
    for (const f of ['model_id', 'weights_digest', 'runtime_measurement', 'operator', 'system_prompt_digest', 'tool_manifest_digest']) await conflict(f);
    const below = await both([{ id: 'a', verifier: okRoot(ident()) }, { id: 'b', verifier: { verify: async () => ({ ok: false, reason: 'nope' }) } }], 2);
    expect(below).toEqual({ ok: false, reason: 'multi-root attestation below threshold (1/2 independent roots corroborated)' });
    const req = await both([{ id: 'a', verifier: okRoot(ident()) }, { id: 'b', required: true, verifier: { verify: async () => ({ ok: false, reason: 'nope' }) } }], 1);
    expect(req).toEqual({ ok: false, reason: "required attestation root 'b' failed: nope" });
    const req2 = await both([{ id: 'b', required: true, verifier: { verify: async () => ({ ok: false }) } }], 1);
    expect(req2).toEqual({ ok: false, reason: "required attestation root 'b' failed: invalid" });
    const thrown = await both([{ id: 't', required: true, verifier: { verify: async () => { throw new Error('boom'); } } }], 1);
    expect(thrown).toEqual({ ok: false, reason: "required attestation root 't' failed: root 't' threw (fail closed): boom" });
    const thrownNonError = await both([{ id: 't', required: true, verifier: { verify: async () => { throw 'str'; } } }], 1);
    expect(thrownNonError).toEqual({ ok: false, reason: "required attestation root 't' failed: root 't' threw (fail closed): unknown" });
    // an unbound or measured-less "ok" does not count toward the threshold
    const unbound = await both([{ id: 'a', verifier: { verify: async () => ({ ok: true, bound: false, measured: ident() }) } }], 1);
    expect(unbound).toEqual({ ok: false, reason: 'multi-root attestation below threshold (0/1 independent roots corroborated)' });
    const noMeasured = await both([{ id: 'a', verifier: { verify: async () => ({ ok: true, bound: true }) } }], 1);
    expect((noMeasured as any).ok).toBe(false);
    const notOk = await both([{ id: 'a', verifier: { verify: async () => ({ ok: false, bound: true, measured: ident() }) } }], 1);
    expect((notOk as any).ok).toBe(false);
  });
  it('a null / undefined result never corroborates, whether or not the root is required (verdict equal to production)', async () => {
    for (const required of [false, true, undefined]) {
      for (const v of [null, undefined]) {
        const r = await both([{ id: 'a', required, verifier: { verify: async () => v } }], 1);
        expect((r as any).ok).toBe(false);
        expect((r as any).reason).toBe(required === true
          ? "required attestation root 'a' failed: root 'a' returned a malformed result (fail closed)"
          : 'multi-root attestation below threshold (0/1 independent roots corroborated)');
      }
    }
    // a null optional root is skipped: 1-of-2 still accepts on the good root (Attest.dfy NullIsFailedRoot / NullNeverAborts)
    const ok = await both([{ id: 'a', verifier: { verify: async () => null } }, { id: 'b', verifier: okRoot(ident()) }], 1);
    expect((ok as any).ok).toBe(true);
  });
  it('a verifier that is missing throws inside the loop and is reported as a root failure', async () => {
    const r = await both([{ id: 'a', verifier: {} }, { id: 'b', verifier: okRoot(ident()) }], 1);
    expect((r as any).ok).toBe(true);
  });
  it('threshold short-circuits: roots after the decision are not called', async () => {
    const calls: string[] = [];
    const mk = (n: string) => ({ id: n, verifier: { verify: async () => { calls.push(n); return { ok: true, bound: true, measured: ident() }; } } });
    await createMultiRootVerifierVerified({ roots: [mk('a'), mk('b'), mk('c')], threshold: 1 } as any).verify({});
    const verifiedCalls = [...calls];
    calls.length = 0;
    await createMultiRootVerifier({ roots: [mk('a'), mk('b'), mk('c')], threshold: 1 } as any).verify({});
    expect(verifiedCalls).toEqual(calls);
  });
  it('hostAsserted from a non-passing root is dropped; empty hostAsserted is omitted', async () => {
    const r = await both([
      { id: 'bad', verifier: { verify: async () => ({ ok: false, hostAsserted: { x: 'y' } }) } },
      { id: 'good', verifier: okRoot(ident(), { hostAsserted: {} }) },
    ], 1);
    expect(r).toEqual({ ok: true, bound: true, measured: { model_id: 'm', weights_digest: 'w', weights_measured: true, runtime_measurement: 'r', operator: 'op' } });
  });
  it('construction errors have the production messages', () => {
    const v = { verify: async () => ({ ok: true }) };
    const msg = (p: any) => { try { createMultiRootVerifierVerified(p); return 'ok'; } catch (e) { return `${(e as Error).name}: ${(e as Error).message}`; } };
    expect(msg(undefined)).toBe('TypeError: createMultiRootVerifier: at least one attestation root is required');
    expect(msg({ roots: 'x', threshold: 1 })).toBe('TypeError: createMultiRootVerifier: at least one attestation root is required');
    expect(msg({ roots: [], threshold: 1 })).toBe('TypeError: createMultiRootVerifier: at least one attestation root is required');
    expect(msg({ roots: [{ id: 'a', verifier: v }], threshold: 0 })).toBe('TypeError: createMultiRootVerifier: threshold must be an integer in [1, roots.length]');
    expect(msg({ roots: [{ id: 'a', verifier: v }], threshold: 2 })).toBe('TypeError: createMultiRootVerifier: threshold must be an integer in [1, roots.length]');
    expect(msg({ roots: [{ id: 'a', verifier: v }], threshold: 1.5 })).toBe('TypeError: createMultiRootVerifier: threshold must be an integer in [1, roots.length]');
    expect(msg({ roots: [{ id: 'a', verifier: v }], threshold: Number.NaN })).toBe('TypeError: createMultiRootVerifier: threshold must be an integer in [1, roots.length]');
    expect(msg({ roots: [{ id: '', verifier: v }], threshold: 1 })).toBe('TypeError: createMultiRootVerifier: each root needs a non-empty id');
    expect(msg({ roots: [{ id: 5, verifier: v }], threshold: 1 })).toBe('TypeError: createMultiRootVerifier: each root needs a non-empty id');
    expect(msg({ roots: [null], threshold: 1 })).toBe('TypeError: createMultiRootVerifier: each root needs a non-empty id');
    expect(msg({ roots: [{ id: 'a', verifier: v }, { id: 'a', verifier: v }], threshold: 1 })).toBe("TypeError: createMultiRootVerifier: duplicate root id 'a'");
    expect(msg({ roots: [{ id: 'a', verifier: v }, { id: 'b', verifier: v }], threshold: 2 })).toBe('ok');
  });

  it('a getter that throws on the result is a whole-verification error for the root (required or not), message preserved', async () => {
    const ident = { model_id: 'm', weights_digest: 'w', weights_measured: true, runtime_measurement: 'r', operator: 'op' };
    const throwing = (which: 'ok' | 'bound' | 'measured', err: unknown) => {
      const o: any = { ok: true, bound: true, measured: ident };
      Object.defineProperty(o, which, { get() { throw err; } });
      return o;
    };
    for (const required of [true, false, undefined]) {
      for (const err of [new Error('getter-boom'), 'plain-string']) {
        for (const which of ['ok', 'measured'] as const) {
          const r: any = await both([{ id: 'a', required, verifier: { verify: async () => throwing(which, err) } }], 1);
          expect(r.ok).toBe(false);
          expect(typeof r.reason).toBe('string');
        }
      }
    }
    const r1: any = await both([{ id: 'a', required: true, verifier: { verify: async () => throwing('ok', new Error('getter-boom')) } }], 1);
    expect(r1.reason).toBe('multi-root attestation error (fail closed): getter-boom');
    const r2: any = await both([{ id: 'a', required: true, verifier: { verify: async () => throwing('ok', 'plain-string') } }], 1);
    expect(r2.reason).toBe('multi-root attestation error (fail closed): unknown');
    // a throwing getter inside the measured identity
    const inner: any = { ...ident };
    Object.defineProperty(inner, 'model_id', { get() { throw new Error('inner-boom'); } });
    const r3: any = await both([{ id: 'a', verifier: { verify: async () => ({ ok: true, bound: true, measured: inner }) } }], 1);
    expect(r3).toEqual({ ok: false, reason: 'multi-root attestation error (fail closed): inner-boom' });
    // an earlier root's failure is not masked: the later root's error still wins as "error"
    const r4: any = await both([{ id: 'a', verifier: { verify: async () => ({ ok: false }) } }, { id: 'b', verifier: { verify: async () => throwing('ok', new Error('late')) } }], 1);
    expect(r4.reason).toBe('multi-root attestation error (fail closed): late');
  });
  it('an exception outside the per-root handling (hostAsserted proxy) is reported as an error of the verification', async () => {
    const ident = { model_id: 'm', weights_digest: 'w', weights_measured: true, runtime_measurement: 'r', operator: 'op' };
    const mkHost = (err: unknown) => new Proxy({ k: 'v' }, { ownKeys() { throw err; } });
    const r: any = await both([{ id: 'a', verifier: { verify: async () => ({ ok: true, bound: true, measured: ident, hostAsserted: mkHost(new Error('host-boom')) }) } }], 1);
    expect(r).toEqual({ ok: false, reason: 'multi-root attestation error (fail closed): host-boom' });
    const r2: any = await both([{ id: 'a', verifier: { verify: async () => ({ ok: true, bound: true, measured: ident, hostAsserted: mkHost('x') }) } }], 1);
    expect(r2).toEqual({ ok: false, reason: 'multi-root attestation error (fail closed): unknown' });
  });
});

describe('typeof guards on structured min_measurement / pinned digests', () => {
  it('a function carrying an svn property is not an { svn } bound: it is MinBad (fail closed, 0.4.2 strict SVN)', () => {
    const fn: any = Object.assign(() => 0, { svn: 5 });
    expect(matchAgentBindingVerified(id({ runtime_measurement: '3' }), { min_measurement: fn } as any)).toBe(
      'min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)',
    );
    expect(requiresAttestationVerified({ min_measurement: fn } as any)).toBe(true);
    // the frozen oracle ignored it (fail open), kept to prove the change is real
    expect(matchAgentBinding(id({ runtime_measurement: '3' }), { min_measurement: fn } as any)).toBeNull();
    expect(requiresAttestation({ min_measurement: fn } as any)).toBe(false);
  });
  it('an allowlist containing undefined does not admit an identity that omits the digest', () => {
    const noTm: any = id();
    delete noTm.tool_manifest_digest;
    const b: any = { tool_manifest_allowlist: [undefined] };
    expect(matchAgentBinding(noTm, b)).toBe('tool_manifest_digest not in tool_manifest_allowlist (tools changed?)');
    expect(matchAgentBindingVerified(noTm, b)).toBe('tool_manifest_digest not in tool_manifest_allowlist (tools changed?)');
    const noSp: any = id();
    delete noSp.system_prompt_digest;
    const b2: any = { system_prompt_allowlist: [undefined] };
    expect(matchAgentBindingVerified(noSp, b2)).toBe(matchAgentBinding(noSp, b2));
    expect(matchAgentBindingVerified(noSp, b2)).toBe('system_prompt_digest not in system_prompt_allowlist (instructions changed / prompt injection?)');
  });
  it('allowlistGate: an absent lastSeenVersion means no rollback / conflict check', () => {
    const base: AllowlistGateFacts = { shapeOk: true, issuerKnown: true, algMatches: true, issuerLive: true, sigOk: true, nowMs: 1000, skew: 0, notBefore: 500, expiresAt: 2000, version: -1, digest: 'd' };
    expect(allowlistGate(base)).toBeUndefined();
    expect(allowlistGate({ ...base, version: 0, lastSeenDigest: 'o' })).toBeUndefined();
  });
});

describe('ext-attest glue: read order, integer guard, nonce type, rethrown message', () => {
  it('each root result is probed ok -> bound -> measured (short-circuit, production order) before the fact is built', async () => {
    const ident = { model_id: 'm', weights_digest: 'w', weights_measured: true, runtime_measurement: 'r', operator: 'op' };
    const KEYS = new Set(['ok', 'bound', 'measured', 'hostAsserted']);
    const probe = async (target: Record<string, unknown>) => {
      const log: string[] = [];
      const p = new Proxy(target, { get(t, k, r) { if (typeof k === 'string' && KEYS.has(k)) log.push(k); return Reflect.get(t, k, r); } });
      await createMultiRootVerifierVerified({ roots: [{ id: 'a', verifier: { verify: async () => p as any } }], threshold: 1 } as any).verify({});
      return log;
    };
    const cases: Array<[Record<string, unknown>, string[]]> = [
      [{ ok: true, bound: true, measured: ident }, ['ok', 'bound', 'measured']],
      [{ ok: true, bound: true }, ['ok', 'bound', 'measured']],
      [{ ok: true, bound: false, measured: ident }, ['ok', 'bound']],
      [{ ok: false, bound: true, measured: ident }, ['ok']],
      [{ ok: 'true', bound: true, measured: ident }, ['ok']],
      [{ ok: true, bound: 1, measured: ident }, ['ok', 'bound']],
    ];
    for (const [t, prefix] of cases) {
      const log = await probe(t);
      expect(log.slice(0, prefix.length), JSON.stringify(t)).toEqual(prefix);
      expect(log[prefix.length], JSON.stringify(t)).toBe('ok'); // the fact construction starts right after the probe
    }
  });
  it('allowlistGate numerics must be safe integers (RangeError names the value)', () => {
    const base: AllowlistGateFacts = { shapeOk: true, issuerKnown: true, algMatches: true, issuerLive: true, sigOk: true, nowMs: 1000, skew: 0, notBefore: 500, expiresAt: 2000, version: 5, digest: 'd' };
    expect(() => allowlistGate({ ...base, nowMs: 1.5 })).toThrow(new RangeError('pca-verified-core/attest: expected a safe integer, got 1.5'));
    expect(() => allowlistGate({ ...base, version: 2 ** 60 })).toThrow('pca-verified-core/attest: expected a safe integer, got 1152921504606847000');
  });
  it('the nonce store refuses non-string nonces without consuming anything', () => {
    let now = 1000;
    const s = new VerifiedMemoryNonceStore(10, { now: () => now });
    for (const n of [5, {}, null, undefined, ['a']]) expect(s.consume(n as any)).toBe(false);
    expect(s.consume('5')).toBe(true);
    now++;
    expect(s.consume('5')).toBe(false);
  });
  it('a non-string runtime SVN no longer throws: it is refused as not an integer SVN (0.4.2 strict SVN)', () => {
    const idBad = id({ runtime_measurement: undefined });
    const msg = (f: any) => { try { return f(idBad, { min_measurement: { svn: 3 } }) ?? 'null'; } catch (e) { return `${(e as Error).name}: ${(e as Error).message}`; } };
    expect(msg(matchAgentBindingVerified)).toBe('runtime_measurement undefined is not an integer SVN (required min svn 3)');
    // the frozen oracle threw a TypeError (.trim on undefined), kept to prove the change is real
    expect(msg(matchAgentBinding)).toMatch(/^TypeError: .*trim/);
  });
});
