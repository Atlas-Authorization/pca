/* eslint-disable @typescript-eslint/no-explicit-any */
// Production wiring of the Dafny-proved extension components (docs/pca/security/verified-core.md, "Production wiring of the
// extension components"): every default-wired decision CALLS the proved code, every opt-in module calls it only when
// PCA_VERIFIED_CORE enables it, and the glue around the proved calls (DoS bound, fail-closed fallbacks, error rendering) behaves.
// The verified-core module is wrapped with spies (same implementation), so the results are the real proved results.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// every Policy VM the code under test builds (decide() caches one at module level, so mock.results is gone after clearAllMocks)
const builtVms = vi.hoisted(() => [] as any[]);
vi.mock('@atlasauth/pca-verified-core', async (importOriginal) => {
  const m: any = await importOriginal();
  const out: any = { ...m };
  for (const k of [
    'computeTaintVerified',
    'taintGateVerified',
    'verifyInclusionVerified',
    'matchAgentBindingVerified',
    'requiresAttestationVerified',
    'createMultiRootVerifierVerified',
    'requiredThresholdVerified',
    'admitVerified',
    'decideCoreVerified',
    'safeRegexFullMatchVerified',
    'isSafeRegexSourceVerified',
    'wireAcceptsText',
    'wireCanonicalizeStrict',
    'verifyConsistencyVerified',
    'verifyMembershipVerified',
    'createPolicyVm',
  ]) {
    out[k] = vi.fn(m[k]);
  }
  out.createPolicyVm = vi.fn((...a: unknown[]) => {
    const v = m.createPolicyVm(...a);
    builtVms.push(v);
    return v;
  });
  out.VerifiedMemoryNonceStore = vi.fn(function (this: unknown, ...a: unknown[]) {
    return new m.VerifiedMemoryNonceStore(...a);
  });
  return out;
});

import * as vc from '@atlasauth/pca-verified-core';
import { __setVerifiedCoreModeForTests, parseVerifiedCoreMode, verifiedCoreOptIn, VERIFIED_CORE_OPT_IN_MODULES } from './verified-core-mode';
import { InMemoryTrustedInputRegistry, computeTaint } from './taint';
import { merkleProof, merkleRoot, verifyInclusion, type InclusionProof } from './merkle';
import { b64u, canonicalBytes, canonicalizeStrict, sha256 } from './hash';
import { MAX_JSON_BYTES, strictParse, StrictJsonError } from './strict-json';
import { safeRegexFullMatch } from './safe-regex';
import { isSafeRegexSource } from './predicates';
import { createMultiRootVerifier, matchAgentBinding, memoryNonceStore, requiresAttestation } from './attestation';
import { EMPTY_TREE_ROOT, verifyLedgerConsistency } from './ledger';
import { RevocationSet, verifyMembership } from './revocation';
import { decide, type DecideInput } from './policy-vm';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY, type TrustBudget } from './risk';
import { verifyPCActnCore, type PCActn } from './pcactn';
import { AUD, NOW as FX_NOW, setup } from './server/fixture.test-util';

const spy = (k: string): any => (vc as any)[k];

beforeEach(() => {
  vi.clearAllMocks();
  __setVerifiedCoreModeForTests('');
});
afterEach(() => __setVerifiedCoreModeForTests(undefined));

// --------------------------------------------------------------------------------------------- mode parsing
describe('PCA_VERIFIED_CORE parsing', () => {
  it('1 / all / true (any case, padded) enable every opt-in module', () => {
    for (const v of ['1', 'all', 'true', ' ALL ', 'True']) expect([...parseVerifiedCoreMode(v)].sort()).toEqual([...VERIFIED_CORE_OPT_IN_MODULES].sort());
  });
  it('a comma list enables exactly the named modules; unknown names are ignored', () => {
    expect([...parseVerifiedCoreMode('wire, regex ,bogus')].sort()).toEqual(['regex', 'wire']);
    expect([...parseVerifiedCoreMode('merkle-strict')]).toEqual(['merkle-strict']);
    expect([...parseVerifiedCoreMode('noncestore,policyvm')].sort()).toEqual(['noncestore', 'policyvm']);
  });
  it('unset, empty, 0, false, none and non-strings enable nothing', () => {
    for (const v of [undefined, '', '0', 'false', 'none', 'yes', 2, null]) expect(parseVerifiedCoreMode(v).size).toBe(0);
  });
  it('the environment is read on first use and cached until reset', () => {
    const prev = process.env.PCA_VERIFIED_CORE;
    try {
      process.env.PCA_VERIFIED_CORE = 'regex';
      __setVerifiedCoreModeForTests(undefined);
      expect(verifiedCoreOptIn('regex')).toBe(true);
      expect(verifiedCoreOptIn('wire')).toBe(false);
      process.env.PCA_VERIFIED_CORE = 'wire';
      expect(verifiedCoreOptIn('wire')).toBe(false); // cached
      __setVerifiedCoreModeForTests(undefined);
      expect(verifiedCoreOptIn('wire')).toBe(true);
      delete process.env.PCA_VERIFIED_CORE;
      __setVerifiedCoreModeForTests(undefined);
      expect(verifiedCoreOptIn('wire')).toBe(false);
    } finally {
      if (prev === undefined) delete process.env.PCA_VERIFIED_CORE;
      else process.env.PCA_VERIFIED_CORE = prev;
    }
  });
  it('a missing process.env (browser bundle) enables nothing', () => {
    const g = globalThis as any;
    const saved = g.process;
    try {
      g.process = undefined;
      __setVerifiedCoreModeForTests(undefined);
      expect(verifiedCoreOptIn('wire')).toBe(false);
      g.process = { get env(): never { throw new Error('no env'); } };
      __setVerifiedCoreModeForTests(undefined);
      expect(verifiedCoreOptIn('regex')).toBe(false);
    } finally {
      g.process = saved;
    }
  });
});

// --------------------------------------------------------------------------------------------- default-wired decisions
describe('default production path = proved code', () => {
  it('computeTaint forwards to computeTaintVerified (result unchanged)', () => {
    const reg = new InMemoryTrustedInputRegistry().recordTrusted('d1').recordWeb('d2');
    const r = computeTaint({ trusted_refs: ['d1', 'd2'] }, { registry: reg });
    expect(spy('computeTaintVerified')).toHaveBeenCalledTimes(1);
    expect(r).toEqual({ taint: 0.75, label: { kind: 'web' }, refs: [{ ref: 'd1', label: { kind: 'trusted' } }, { ref: 'd2', label: { kind: 'web' } }], valid: true });
  });

  it('verifyInclusion forwards to verifyInclusionVerified with the canonical leaf bytes', () => {
    const leaves = ['a', 'b', 'c', { x: 1 }];
    const root = merkleRoot(leaves);
    const p = merkleProof(leaves, 3);
    expect(verifyInclusion(root, p, { x: 1 })).toBe(true);
    expect(spy('verifyInclusionVerified')).toHaveBeenCalledWith(root, p, canonicalBytes({ x: 1 }));
    expect(verifyInclusion(root, p, { x: 2 })).toBe(false);
  });

  it('the attestation decisions forward to the proved code', () => {
    const id = { model_id: 'm', weights_digest: 'w', runtime_measurement: '3', operator: 'op' } as any;
    expect(matchAgentBinding(id, { model_allowlist: ['m'] })).toBeNull();
    expect(matchAgentBinding(id, { model_allowlist: ['n'] })).toBe('model_id m not in model_allowlist');
    expect(spy('matchAgentBindingVerified')).toHaveBeenCalledTimes(2);
    expect(requiresAttestation({ model_allowlist: ['m'] })).toBe(true);
    expect(requiresAttestation({})).toBe(false);
    expect(spy('requiresAttestationVerified')).toHaveBeenCalledTimes(2);
    const v = createMultiRootVerifier({ threshold: 1, roots: [{ id: 'r', verifier: { verify: async () => ({ ok: true }) as any } }] });
    expect(typeof v.verify).toBe('function');
    expect(spy('createMultiRootVerifierVerified')).toHaveBeenCalledTimes(1);
    expect(() => createMultiRootVerifier({ threshold: 2, roots: [{ id: 'r', verifier: { verify: async () => ({ ok: true }) as any } }] })).toThrow(
      'createMultiRootVerifier: threshold must be an integer in [1, roots.length]',
    );
  });

  it('decide() takes its threshold, admission and release from the proved kernels', () => {
    const d = decide(policyInput());
    expect(d).toMatchObject({ releaseGuardianShare: true, admit: true, needStepUp: false, r: 0 });
    expect(spy('requiredThresholdVerified')).toHaveBeenCalledTimes(2);
    expect(spy('admitVerified')).toHaveBeenCalledTimes(1);
    expect(spy('decideCoreVerified')).toHaveBeenCalledTimes(1);
    expect(spy('createPolicyVm')).not.toHaveBeenCalled(); // the proved evaluator is opt-in
  });

  it('the enforce.taint gate of verifyPCActnCore is the proved gate', async () => {
    const s = setup();
    const p = s.mk(s.plan[0]!, { extra: { provenance: { causal_hash: '', taint_level: 0, trusted_refs: ['d1'] } } }) as PCActn;
    const core = (taint: unknown) => verifyPCActnCore(p, { insecureSkipPlanRootCheck: true, grant: s.grant, nowEpoch: FX_NOW, audience: AUD, enforce: { taint } } as never);
    const reg = new InMemoryTrustedInputRegistry().recordTrusted('d1');
    const ok = await core({ ctx: { registry: reg }, maxTaint: 0 });
    expect(spy('taintGateVerified')).toHaveBeenCalledTimes(1);
    expect(ok.checks.taint_gate).toBe('pass');
    const bad = await core({ ctx: { registry: new InMemoryTrustedInputRegistry() }, maxTaint: 0 });
    expect(bad.checks.taint_gate).toBe('fail');
    expect(bad.reason).toBe('taint_gate: information-flow taint 1 exceeds policy max 0');
    const misconf = await core({ ctx: { registry: reg }, maxTaint: Number.NaN });
    expect(misconf.reason).toBe('taint_gate: taint gate misconfigured: maxTaint must be a non-negative number (fail closed)');
    const invalid = await core({ ctx: {}, maxTaint: 1 });
    expect(invalid.reason).toBe('taint_gate: taint: no trusted-input registry');
    // a throwing option getter is a fail-closed gate error, not an exception
    const thrown = await core({ get ctx(): never { throw new Error('boom'); }, maxTaint: 1 });
    expect(thrown.checks.taint_gate).toBe('fail');
    expect(thrown.reason).toBe('taint_gate: taint gate error (fail closed): boom');
    expect((await core(undefined)).checks.taint_gate).toBe('not-enforced');
  });

  it('opt-in modules stay on the hand-written code by default', () => {
    safeRegexFullMatch('a+', 'aa');
    isSafeRegexSource('a+');
    strictParse('{"a":1}');
    canonicalizeStrict({ a: 1 });
    verifyLedgerConsistency(EMPTY_TREE_ROOT, EMPTY_TREE_ROOT, { oldSize: 0, newSize: 0, path: [] });
    const rs = new RevocationSet(['x']);
    verifyMembership(rs.root, rs.membershipProof('x'), 'x');
    memoryNonceStore(10).consume('n');
    for (const k of ['safeRegexFullMatchVerified', 'isSafeRegexSourceVerified', 'wireAcceptsText', 'wireCanonicalizeStrict', 'verifyConsistencyVerified', 'verifyMembershipVerified', 'VerifiedMemoryNonceStore']) {
      expect(spy(k), k).not.toHaveBeenCalled();
    }
  });
});

// --------------------------------------------------------------------------------------------- inclusion glue
// Expected sibling sides (leaf -> root) for (index, size), RFC 6962 split: an independent transcription for building proofs.
function sides(index: number, size: number): ('L' | 'R')[] {
  const out: ('L' | 'R')[] = [];
  let idx = index;
  let n = size;
  while (n > 1) {
    let k = 1;
    while (k * 2 < n) k *= 2;
    if (idx < k) {
      out.push('R');
      n = k;
    } else {
      out.push('L');
      idx -= k;
      n -= k;
    }
  }
  return out.reverse();
}
const node = (l: Uint8Array, r: Uint8Array) => sha256(new Uint8Array([1, ...l, ...r]));
function syntheticProof(index: number, size: number, leaf: unknown): { root: string; proof: InclusionProof } {
  let h = sha256(new Uint8Array([0, ...canonicalBytes(leaf)]));
  const path = sides(index, size).map((side, i) => {
    const sib = sha256(new Uint8Array([7, i]));
    h = side === 'L' ? node(sib, h) : node(h, sib);
    return { side, hash: b64u(sib) };
  });
  return { root: b64u(h), proof: { index, size, path } };
}

describe('verifyInclusion glue', () => {
  it('accepts a 53-step path (the longest a safe-integer size allows) and the bound never decides', () => {
    const size = Number.MAX_SAFE_INTEGER;
    const index = size - 5;
    const { root, proof } = syntheticProof(index, size, 'leaf');
    expect(proof.path.length).toBe(53);
    expect(verifyInclusion(root, proof, 'leaf')).toBe(true);
    const small = syntheticProof(5, 2 ** 52 + 1, 'leaf');
    expect(small.proof.path.length).toBe(53);
    expect(verifyInclusion(small.root, small.proof, 'leaf')).toBe(true);
  });
  it('refuses a path longer than 53 steps without calling the decoder', () => {
    const { root, proof } = syntheticProof(3, 10, 'leaf');
    const long = { ...proof, path: Array.from({ length: 54 }, () => proof.path[0]!) };
    expect(verifyInclusion(root, long, 'leaf')).toBe(false);
    expect(spy('verifyInclusionVerified')).not.toHaveBeenCalled();
    const fiftyThree = { ...proof, path: Array.from({ length: 53 }, () => proof.path[0]!) };
    expect(verifyInclusion(root, fiftyThree, 'leaf')).toBe(false);
    expect(spy('verifyInclusionVerified')).toHaveBeenCalledTimes(1); // 53 is handed to the proved verifier, which decides
  });
  it('a leaf that cannot be canonicalised, a hostile proof and junk never throw', () => {
    const { root, proof } = syntheticProof(0, 1, 'leaf');
    const cyc: any = {};
    cyc.self = cyc;
    expect(verifyInclusion(root, proof, cyc)).toBe(false);
    expect(verifyInclusion(root, proof, () => 1)).toBe(false);
    const hostile = { get path(): never { throw new Error('x'); } };
    expect(verifyInclusion(root, hostile as any, 'leaf')).toBe(false);
    expect(verifyInclusion(root, null as any, 'leaf')).toBe(false);
    expect(verifyInclusion(root, { index: 0, size: 1, path: 'x' } as any, 'leaf')).toBe(false);
    expect(verifyInclusion(root, proof, 'leaf')).toBe(true);
  });
});

// --------------------------------------------------------------------------------------------- opt-in modules
describe('opt-in modules route to the proved code only when enabled', () => {
  it('regex: safeRegexFullMatch and isSafeRegexSource', () => {
    __setVerifiedCoreModeForTests('regex');
    expect(safeRegexFullMatch('[a-z]+/[0-9]{1,4}', 'docs/42')).toBe(true);
    expect(safeRegexFullMatch('(a', 'a')).toBeNull();
    expect(isSafeRegexSource('[a-z]+')).toBe(true);
    expect(isSafeRegexSource('(a)\\1')).toBe(false);
    expect(spy('safeRegexFullMatchVerified')).toHaveBeenCalledTimes(2);
    expect(spy('isSafeRegexSourceVerified')).toHaveBeenCalledTimes(2);
  });

  it('wire: strictParse accepts what the proved profile accepts and keeps the hand-written error message', () => {
    __setVerifiedCoreModeForTests('wire');
    expect(strictParse('{"b":[1,2.5,"x"],"a":null}')).toEqual({ b: [1, 2.5, 'x'], a: null });
    expect(() => strictParse('{"a":1,"a":2}')).toThrow(StrictJsonError);
    expect(() => strictParse('{"a":1,"a":2}')).toThrow(/duplicate/i);
    expect(() => strictParse(42 as any)).toThrow('strict JSON: input is not a string (at offset 0)');
    expect(spy('wireAcceptsText')).toHaveBeenCalledTimes(3);
  });
  it('wire: an over-cap text is refused before the compiled parser materialises it (64 MiB was a heap OOM)', () => {
    __setVerifiedCoreModeForTests('wire');
    expect(() => strictParse('x'.repeat(MAX_JSON_BYTES + 1))).toThrow('strict JSON: input too large (at offset 0)');
    expect(() => strictParse(' '.repeat(64 << 20))).toThrow('strict JSON: input too large (at offset 0)');
    expect(spy('wireAcceptsText')).not.toHaveBeenCalled();
    // within the cap the proved code still decides
    expect(strictParse('"ab"')).toBe('ab');
    expect(spy('wireAcceptsText')).toHaveBeenCalledTimes(1);
  });
  it('wire: a proved rejection the hand-written parser does not share still fails closed', () => {
    __setVerifiedCoreModeForTests('wire');
    spy('wireAcceptsText').mockReturnValueOnce(false);
    expect(() => strictParse('{"a":1}')).toThrow('strict JSON: rejected by the verified strict-JSON profile (at offset 0)');
  });
  it('wire: a proved acceptance the hand-written parser does not share fails closed', () => {
    __setVerifiedCoreModeForTests('wire');
    spy('wireAcceptsText').mockReturnValueOnce(true);
    expect(() => strictParse('{"a":01}')).toThrow(StrictJsonError);
  });
  it('wire: an exception from the compiled proved parser is a rejection; a RangeError (resource exhaustion) defers to the hand-written parser', () => {
    __setVerifiedCoreModeForTests('wire');
    spy('wireAcceptsText').mockImplementationOnce(() => {
      throw new Error('boom');
    });
    expect(() => strictParse('{"a":1}')).toThrow('strict JSON: rejected by the verified strict-JSON profile (at offset 0)');
    spy('wireAcceptsText').mockImplementationOnce(() => {
      throw new RangeError('Maximum call stack size exceeded');
    });
    expect(strictParse('{"a":1}')).toEqual({ a: 1 });
    spy('wireAcceptsText').mockImplementationOnce(() => {
      throw new RangeError('Maximum call stack size exceeded');
    });
    expect(() => strictParse('{"a":1,"a":2}')).toThrow(/duplicate/i);
  });
  it('wire: a document whose member count exhausts the compiled parser and printer is decided exactly as with the opt-in off', () => {
    const doc = { ledger: Array.from({ length: 10_000 }, (_, i) => ({ t: i, amount: 1 })) };
    __setVerifiedCoreModeForTests('none');
    const hand = canonicalizeStrict(doc);
    __setVerifiedCoreModeForTests('wire');
    expect(canonicalizeStrict(doc)).toBe(hand);
    expect(strictParse(hand)).toEqual(doc);
    expect(() => strictParse(hand.slice(0, -1))).toThrow(StrictJsonError);
  }, 120_000);
  it('wire: a maximum-size (1 MiB) string is decided by the proved parser without exhausting the stack', () => {
    __setVerifiedCoreModeForTests('wire');
    const big = '"' + 'a'.repeat((1 << 20) - 2) + '"';
    expect(strictParse(big)).toHaveLength((1 << 20) - 2);
    expect(spy('wireAcceptsText')).toHaveBeenCalledTimes(1);
    expect(spy('wireAcceptsText').mock.results[0]).toEqual({ type: 'return', value: true });
  }, 60_000);
  it('wire: canonicalizeStrict returns the proved encoding; refusals keep the hand-written TypeError', () => {
    __setVerifiedCoreModeForTests('wire');
    expect(canonicalizeStrict({ b: 1, a: [true, null, 'é'] })).toBe('{"a":[true,null,"é"],"b":1}');
    spy('wireCanonicalizeStrict').mockReturnValueOnce('PROVED');
    expect(canonicalizeStrict({ z: 1 })).toBe('PROVED');
    expect(() => canonicalizeStrict({ a: -0 })).toThrow(TypeError);
    expect(() => canonicalizeStrict({ a: 1e300 })).toThrow(TypeError);
    spy('wireCanonicalizeStrict').mockImplementationOnce(() => {
      throw new TypeError('x');
    });
    expect(() => canonicalizeStrict({ a: 1 })).toThrow('canonicalize: rejected by the verified canonical encoder');
    spy('wireCanonicalizeStrict').mockImplementationOnce(() => {
      throw new RangeError('Maximum call stack size exceeded');
    });
    expect(canonicalizeStrict({ b: 1, a: 2 })).toBe('{"a":2,"b":1}'); // resource exhaustion: the hand-written encoding
    spy('wireCanonicalizeStrict').mockImplementationOnce(() => {
      throw new RangeError('Maximum call stack size exceeded');
    });
    expect(() => canonicalizeStrict({ a: -0 })).toThrow(TypeError); // ...with the hand-written refusals
  });

  it('merkle-strict: consistency and revocation membership', () => {
    __setVerifiedCoreModeForTests('merkle-strict');
    expect(verifyLedgerConsistency(EMPTY_TREE_ROOT, EMPTY_TREE_ROOT, { oldSize: 0, newSize: 0, path: [] })).toBe(true);
    expect(spy('verifyConsistencyVerified')).toHaveBeenCalledTimes(1);
    const rs = new RevocationSet(['a', 'b', 'c']);
    expect(verifyMembership(rs.root, rs.membershipProof('b'), 'b')).toBe(true);
    expect(verifyMembership(rs.root, rs.membershipProof('b'), 'c')).toBe(false);
    expect(verifyMembership(rs.root, rs.membershipProof('b'), 7 as any)).toBe(false);
    const cyc: any = {};
    cyc.c = cyc;
    expect(verifyMembership(rs.root, rs.membershipProof('b'), cyc)).toBe(false);
    expect(spy('verifyMembershipVerified')).toHaveBeenCalledTimes(3);
  });
  it('merkle-strict: a non-canonical sibling encoding is refused by the default AND the proved verifier', () => {
    const rs = new RevocationSet(['a', 'b']);
    const p = rs.membershipProof('a');
    const h = p.path[0]!.hash;
    // flip the unused trailing bits of the last base64url character: same 32 bytes, non-canonical text
    const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alpha.indexOf(h[h.length - 1]!);
    const nonCanon = { ...p, path: [{ ...p.path[0]!, hash: h.slice(0, -1) + alpha[last | 1] }] };
    expect(nonCanon.path[0]!.hash).not.toBe(h);
    // 0.4.2: the hand-written leafOk is strict too (decodeB64uStrict, exactly 32 bytes), so both paths agree here
    expect(verifyMembership(rs.root, nonCanon, 'a')).toBe(false);
    expect(verifyMembership(rs.root, p, 'a')).toBe(true);
    expect(spy('verifyMembershipVerified')).not.toHaveBeenCalled();
    __setVerifiedCoreModeForTests('merkle-strict');
    expect(verifyMembership(rs.root, nonCanon, 'a')).toBe(false);
    expect(verifyMembership(rs.root, p, 'a')).toBe(true);
    expect(spy('verifyMembershipVerified')).toHaveBeenCalledTimes(2);
  });

  it('noncestore: memoryNonceStore is the proved store model', () => {
    __setVerifiedCoreModeForTests('noncestore');
    let t = 1000;
    const s = memoryNonceStore(2, { retentionMs: 10, now: () => t });
    expect(spy('VerifiedMemoryNonceStore')).toHaveBeenCalledTimes(1);
    expect(s.consume('a')).toBe(true);
    expect(s.consume('a')).toBe(false);
    expect(s.consume('b')).toBe(true);
    expect(s.consume('c')).toBe(false); // full of live entries: refuse, never evict
    t += 10;
    expect(s.consume('c')).toBe(true); // aged out
    expect(() => memoryNonceStore(0)).toThrow('memoryNonceStore: max must be a positive integer');
  });

  it('policyvm: decide() evaluates predicates and caveats with the proved evaluator, same decision', () => {
    const ref = decide(policyInput());
    __setVerifiedCoreModeForTests('policyvm');
    expect(decide(policyInput())).toEqual(ref);
    expect(spy('createPolicyVm')).toHaveBeenCalledTimes(1); // built once, reused
    decide(policyInput());
    expect(spy('createPolicyVm')).toHaveBeenCalledTimes(1);
    const deny = policyInput({ action: { action: { verb: 'transfer', resource: '/acct/1' } } as any });
    __setVerifiedCoreModeForTests('');
    const refDeny = decide(deny);
    __setVerifiedCoreModeForTests('policyvm');
    expect(decide(deny)).toEqual(refDeny);
    expect(refDeny.releaseGuardianShare).toBe(false);
  });
  it('policyvm: a value the converter cannot represent falls back to the hand-written evaluator', () => {
    const live = { get device() { return 'laptop'; } };
    const input = policyInput({ action: { action: { verb: 'revoke_session', resource: '/acct/1/s', params: live }, env: { current_device: 'phone' } } as any });
    const ref = decide(input);
    __setVerifiedCoreModeForTests('policyvm');
    expect(decide(input)).toEqual(ref);
  });
  it('policyvm: any other evaluator error is a fail-closed policy error', () => {
    __setVerifiedCoreModeForTests('policyvm');
    decide(policyInput()); // builds the VM
    const vm = builtVms[builtVms.length - 1];
    expect(vm).toBeDefined();
    const orig = vm.evaluatePredicates;
    vm.evaluatePredicates = () => {
      throw new Error('kaput');
    };
    try {
      const d = decide(policyInput());
      expect(d.releaseGuardianShare).toBe(false);
      expect(d.reasons).toEqual(['policy evaluation error (fail closed): kaput']);
    } finally {
      vm.evaluatePredicates = orig;
    }
  });
  it('policyvm: the regex oracle is charged against the decision regex budget', () => {
    const preds = Array.from({ length: 80 }, (_, i) => ({ verb: 'read', resource: `re:/doc/${i}x` }));
    const g = mintGrant({
      principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), goal: 'g',
      envelope: { predicates: [...preds, { verb: 'read', resource: 're:/doc/[0-9]+' }] as any, caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
    }).grant;
    const input = policyInput({ grant: g, action: { action: { verb: 'read', resource: '/doc/7' } } as any });
    const ref = decide(input);
    expect(ref.releaseGuardianShare).toBe(false); // the 81st evaluation is over the per-document budget: fail closed
    __setVerifiedCoreModeForTests('policyvm');
    expect(decide(input)).toEqual(ref);
  });
});

// --------------------------------------------------------------------------------------------- fixtures
const P = generateKeyPair();
const A = generateKeyPair();
const NOW = 1_800_000_000_000;
function policyInput(over: Partial<DecideInput> = {}): DecideInput {
  const grant = mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'secure my account',
    envelope: {
      predicates: [{ verb: 'revoke_session', resource: '/acct/*', where: [{ field: 'action.params.device', op: 'ne', ref: 'env.current_device' }] }] as any,
      caveats: [{ type: 'expires', at: 9e15 }] as any,
      agent_binding: {},
      risk_policy: DEFAULT_RISK_POLICY,
    },
  }).grant;
  const fresh: TrustBudget = { B: 1, tau: NOW, asOf: NOW };
  return {
    grant,
    action: { action: { verb: 'revoke_session', resource: '/acct/1/s', params: { device: 'laptop' } }, env: { current_device: 'phone' } } as any,
    risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 },
    budget: fresh,
    now: NOW,
    ...over,
  };
}
