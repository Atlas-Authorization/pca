/** Mutation-kill tests for the signed-claim layer (origin.ts). Needs no SEAL: claims carry opaque ciphertext strings. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { PCActn } from '@atlasauth/pca';
import { DEFAULT_RISK_POLICY, b64u, canonicalBytes, generateKeyPair, hashCanonical, sha256, utf8, verify } from '@atlasauth/pca';
import {
  type ClaimExpectations,
  type EncryptedGate,
  type EncryptedRiskClaim,
  type NonceGuard,
  type SignedRiskClaim,
  attestVerdict,
  decryptVerdict,
  encryptedRiskClaim,
  keygen,
  evalSignedRiskClaim,
  fheRiskPolicy,
  memoryNonceGuard,
  signRiskClaim,
  signedClaimDigest,
  verifySignedRiskClaim,
  verifyVerdictAttestation,
} from './index';

afterEach(() => vi.restoreAllMocks());

const signer = generateKeyPair();
const SIGNER = b64u(signer.publicKey);
const policy = fheRiskPolicy(DEFAULT_RISK_POLICY, 0.6);
const binding = { aud: 'rs.example', actionRef: 'pd-1', counter: 7, nonce: 'n-1' };
const claim: EncryptedRiskClaim = { binding, encInputs: 'OPAQUE-CIPHERTEXT', policy };
const mk = (over: Partial<EncryptedRiskClaim> = {}, ctx = 'grant-1'): SignedRiskClaim =>
  signRiskClaim({ claim: { ...claim, ...over }, signerSecretKey: signer.secretKey, context: ctx });
const exp = (over: Partial<ClaimExpectations> = {}): ClaimExpectations => ({
  trustedSigners: [SIGNER],
  context: 'grant-1',
  binding,
  policy,
  nonces: memoryNonceGuard(),
  ...over,
});
const verdict = (s: unknown, e: ClaimExpectations = exp()) => verifySignedRiskClaim(s, e);
const reason = (r: { ok: boolean; reason?: string }) => (r.ok ? 'OK' : r.reason);
const cat = (a: Uint8Array, b: Uint8Array) => {
  const o = new Uint8Array(a.length + b.length);
  o.set(a);
  o.set(b, a.length);
  return o;
};
const MALFORMED = 'claim is not signed: malformed envelope';

describe('signRiskClaim', () => {
  it('context must be a 1..512 char string (messages exact, 512 allowed)', () => {
    const m = 'context must be a non-empty string of at most 512 characters';
    for (const bad of ['', 'x'.repeat(513), 5 as never, undefined as never]) {
      expect(() => signRiskClaim({ claim, signerSecretKey: signer.secretKey, context: bad })).toThrow(new Error(m));
    }
    expect(mk({}, 'x'.repeat(512)).context.length).toBe(512);
    expect(mk({}, 'x').context).toBe('x');
  });
  it('refuses an all-zero RNG but accepts a single zero byte', () => {
    const spy = vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation((a) => a);
    expect(() => mk()).toThrow(new Error('signRiskClaim: random source returned all zeros (RNG failure)'));
    spy.mockImplementation(((a: Uint8Array) => { a.fill(3); a[0] = 0; return a; }) as never);
    const s = mk();
    expect(Array.from(Buffer.from(s.nonce, 'base64url'))).toEqual([0, ...new Array(15).fill(3)]);
    spy.mockImplementation(((a: Uint8Array) => { a.fill(0); a[15] = 1; return a; }) as never);
    expect(mk().nonce.length).toBe(22);
  });
  it('signing key must be a 32-byte Uint8Array', () => {
    const m = 'signing key must be a 32-byte Ed25519 secret key';
    for (const k of [new Uint8Array(31), new Uint8Array(33), [...signer.secretKey] as never, 'k' as never]) {
      expect(() => signRiskClaim({ claim, signerSecretKey: k, context: 'c' })).toThrow(new Error(m));
    }
  });
  it('emits exactly {claim, context, nonce, signer, sig}; fresh 16-byte nonce each time', () => {
    const a = mk(), b = mk();
    expect(Object.keys(a).sort()).toEqual(['claim', 'context', 'nonce', 'sig', 'signer']);
    expect(a.claim).toEqual(claim);
    expect(a.signer).toBe(SIGNER);
    expect(Buffer.from(a.nonce, 'base64url').length).toBe(16);
    expect(a.nonce).not.toBe(b.nonce);
  });
  it('signature covers domain || canonical{v,context,nonce,signer,binding,policy hash,enc_inputs digest}', () => {
    const s = mk();
    const body = canonicalBytes({
      v: 1, context: s.context, nonce: s.nonce, signer: s.signer, binding,
      policy: hashCanonical(policy), enc_inputs: b64u(sha256(utf8('OPAQUE-CIPHERTEXT'))),
    });
    const msg = cat(utf8('atlas-pca-fhe/signed-claim/v1\0'), body);
    expect(verify(signer.publicKey, msg, Buffer.from(s.sig, 'base64url'))).toBe(true);
    expect(Buffer.from(s.sig, 'base64url').length).toBe(64);
  });
  it('signedClaimDigest is the content hash including the signature', () => {
    const s = mk();
    expect(signedClaimDigest(s)).toBe(hashCanonical(s));
    expect(signedClaimDigest({ ...s, sig: b64u(new Uint8Array(64)) })).not.toBe(signedClaimDigest(s));
  });
});

describe('memoryNonceGuard', () => {
  it('single use, and fail-closed (never evict) at capacity', () => {
    const g = memoryNonceGuard(2);
    expect(g.claim('a')).toBe(true);
    expect(g.claim('a')).toBe(false);
    expect(g.claim('b')).toBe(true);
    expect(g.claim('c')).toBe(false); // full
    expect(g.claim('a')).toBe(false);
    const one = memoryNonceGuard(1);
    expect(one.claim('x')).toBe(true);
    expect(one.claim('y')).toBe(false);
    expect(memoryNonceGuard().claim('k')).toBe(true);
  });
});

describe('verifySignedRiskClaim envelope', () => {
  const good = mk();
  const bad: Array<[string, unknown]> = [
    ['null', null], ['number', 5], ['string', 'x'], ['array', []], ['undefined', undefined],
    ['no context', { ...good, context: undefined }], ['ctx number', { ...good, context: 1 }],
    ['no nonce', { ...good, nonce: undefined }], ['nonce number', { ...good, nonce: 1 }],
    ['no signer', { ...good, signer: undefined }], ['signer number', { ...good, signer: 1 }],
    ['no sig', { ...good, sig: undefined }], ['sig number', { ...good, sig: 1 }],
    ['claim undefined', { ...good, claim: undefined }], ['claim null', { ...good, claim: null }],
    ['claim string', { ...good, claim: 'x' }],
    ['encInputs missing', { ...good, claim: { ...good.claim, encInputs: undefined } }],
    ['encInputs number', { ...good, claim: { ...good.claim, encInputs: 9 } }],
    ['binding missing', { ...good, claim: { ...good.claim, binding: undefined } }],
    ['binding null', { ...good, claim: { ...good.claim, binding: null } }],
    ['binding string', { ...good, claim: { ...good.claim, binding: 's' } }],
    ['policy missing', { ...good, claim: { ...good.claim, policy: undefined } }],
    ['policy null', { ...good, claim: { ...good.claim, policy: null } }],
    ['policy string', { ...good, claim: { ...good.claim, policy: 's' } }],
  ];
  for (const [name, v] of bad) {
    it(`rejects ${name} as a malformed envelope`, () => {
      const g = { claim: vi.fn(() => true) };
      expect(reason(verdict(v, exp({ nonces: g })))).toBe(MALFORMED);
      expect(g.claim).not.toHaveBeenCalled();
    });
  }
  it('accepts the good one, returns the SAME claim object and the content digest', () => {
    const r = verdict(good);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.claim).toBe(good.claim);
      expect(r.digest).toBe(signedClaimDigest(good));
    }
  });
});

describe('verifySignedRiskClaim ordering and reasons', () => {
  it('malformed nonce', () => {
    for (const nonce of ['abc', b64u(new Uint8Array(15)), b64u(new Uint8Array(17)), '!'.repeat(22)]) {
      expect(reason(verdict({ ...mk(), nonce }))).toBe('malformed nonce');
    }
  });
  it('malformed signer key or signature (either one alone is enough)', () => {
    const s = mk();
    const m = 'malformed signer key or signature';
    expect(reason(verdict({ ...s, signer: b64u(new Uint8Array(31)) }))).toBe(m);
    expect(reason(verdict({ ...s, sig: b64u(new Uint8Array(63)) }))).toBe(m);
    expect(reason(verdict({ ...s, sig: 'AAAA' }))).toBe(m);
    // short signer is rejected as malformed even when it is "trusted"
    const short = b64u(new Uint8Array(31));
    expect(reason(verdict({ ...s, signer: short }, exp({ trustedSigners: [short] })))).toBe(m);
  });
  it('untrusted signer', () => {
    const other = b64u(generateKeyPair().publicKey);
    expect(reason(verdict(mk(), exp({ trustedSigners: [other] })))).toBe('signer is not a trusted encryptor');
    expect(reason(verdict(mk(), exp({ trustedSigners: [] })))).toBe('signer is not a trusted encryptor');
  });
  const SIGBAD = 'signature does not verify (ciphertext, binding, policy, context or nonce was altered, or wrong signer)';
  it('any altered signed field breaks the signature', () => {
    const s = mk();
    expect(reason(verdict({ ...s, claim: { ...s.claim, encInputs: 'OTHER' } }))).toBe(SIGBAD);
    expect(reason(verdict({ ...s, claim: { ...s.claim, binding: { ...binding, counter: 8 } } }, exp({ binding: { ...binding, counter: 8 } })))).toBe(SIGBAD);
    const p2 = { ...policy, budgetScaled: policy.budgetScaled + 1 };
    expect(reason(verdict({ ...s, claim: { ...s.claim, policy: p2 } }, exp({ policy: p2 })))).toBe(SIGBAD);
    expect(reason(verdict({ ...s, context: 'grant-2' }, exp({ context: 'grant-2' })))).toBe(SIGBAD);
    expect(reason(verdict({ ...s, nonce: b64u(new Uint8Array(16).fill(9)) }))).toBe(SIGBAD);
    // signed by a key that is not the claimed signer
    const imposter = generateKeyPair();
    const forged = signRiskClaim({ claim, signerSecretKey: imposter.secretKey, context: 'grant-1' });
    expect(reason(verdict({ ...forged, signer: SIGNER }))).toBe(SIGBAD);
  });
  it('context, binding and policy mismatches are distinct refusals', () => {
    const s = mk();
    expect(reason(verdict(s, exp({ context: 'grant-2' })))).toBe('context mismatch: claim was signed for a different grant/policy');
    expect(reason(verdict(s, exp({ binding: { ...binding, aud: 'other' } })))).toBe('binding mismatch: claim is bound to a different action');
    expect(reason(verdict(s, exp({ policy: { ...policy, scale: 999 } })))).toBe('policy mismatch: claim was signed for a different gate policy');
  });
  it('the nonce is consumed only after everything else passes, keyed signer:nonce, and a replay is refused', () => {
    const keys: string[] = [];
    const g: NonceGuard = { claim: (k) => { keys.push(k); return keys.length === 1; } };
    const s = mk();
    verdict({ ...s, context: 'x' }, exp({ nonces: g }));
    verdict(s, exp({ nonces: g, context: 'other' }));
    verdict({ ...s, sig: b64u(new Uint8Array(64)) }, exp({ nonces: g }));
    expect(keys).toEqual([]);
    expect(verdict(s, exp({ nonces: g })).ok).toBe(true);
    expect(keys).toEqual([`${SIGNER}:${s.nonce}`]);
    expect(reason(verdict(s, exp({ nonces: g })))).toBe('replay: nonce already used (or the replay window is full)');
    const real = memoryNonceGuard();
    expect(verdict(s, exp({ nonces: real })).ok).toBe(true);
    expect(verdict(s, exp({ nonces: real })).ok).toBe(false);
  });
  it('a throwing guard or expectation is reported as malformed, never thrown', () => {
    const s = mk();
    expect(reason(verdict(s, exp({ nonces: { claim: () => { throw new Error('x'); } } })))).toBe('claim could not be verified (malformed)');
    expect(reason(verdict(s, exp({ trustedSigners: undefined as never })))).toBe('claim could not be verified (malformed)');
  });
});

describe('evalSignedRiskClaim (failure paths, no SEAL)', () => {
  it('passes the verification refusal through unchanged', async () => {
    expect(await evalSignedRiskClaim({} as never, null, exp())).toEqual({ ok: false, reason: MALFORMED });
  });
  it('reports an evaluation failure with the error message', async () => {
    const r = await evalSignedRiskClaim({ publicKey: 'x', relinKeys: 'x', galoisKeys: 'x' }, mk(), exp());
    expect(r).toEqual({ ok: false, reason: 'evaluation failed: galoisKeys: not a serialized SEAL object (bad encoding)' });
  });
  it('reports "unknown error" for a non-Error throw', async () => {
    const keys = { get galoisKeys(): string { throw 'str'; }, publicKey: 'x', relinKeys: 'x' };
    const r = await evalSignedRiskClaim(keys as never, mk(), exp());
    expect(r).toEqual({ ok: false, reason: 'evaluation failed: unknown error' });
  });
});

describe('encryptedRiskClaim guard', () => {
  it('policy must be an object', async () => {
    for (const p of [null, 'p', 5, undefined]) {
      await expect(encryptedRiskClaim({ actn: {} as never, publicKey: 'x', policy: p as never, signerSecretKey: signer.secretKey, context: 'c' })).rejects.toThrow(new Error('policy must be an object'));
    }
  });
});

describe('verdict attestation', () => {
  const holder = generateKeyPair();
  const HOLDER = b64u(holder.publicKey);
  const signed = mk();
  const gate: EncryptedGate = { encRiskRaw: 'RAW-CT', encSlack: 'SLACK-CT' };
  const att = (admit = true) => attestVerdict({ holderSecretKey: holder.secretKey, signed, gate, verdict: { rScaled: 1, slack: admit ? 1 : -1, admit } });
  const E = (over: Record<string, unknown> = {}) => ({ trustedHolders: [HOLDER], claimDigest: signedClaimDigest(signed), ...over });
  const v = (a: unknown, e: ReturnType<typeof E> = E()) => verifyVerdictAttestation(a, e as never);
  const r = (x: { ok: boolean; reason?: string }) => (x.ok ? 'OK' : x.reason);

  it('attestVerdict output and signed bytes', () => {
    const a = att(false);
    expect(Object.keys(a).sort()).toEqual(['admit', 'claimDigest', 'gateDigest', 'holder', 'sig']);
    expect(a.admit).toBe(false);
    expect(a.holder).toBe(HOLDER);
    expect(a.claimDigest).toBe(signedClaimDigest(signed));
    expect(a.gateDigest).toEqual({ encRiskRaw: b64u(sha256(utf8('RAW-CT'))), encSlack: b64u(sha256(utf8('SLACK-CT'))) });
    const body = canonicalBytes({ v: 1, claim: a.claimDigest, gate: a.gateDigest, admit: false, holder: HOLDER });
    const msg = cat(utf8('atlas-pca-fhe/verdict-attestation/v1\0'), body);
    expect(verify(holder.publicKey, msg, Buffer.from(a.sig, 'base64url'))).toBe(true);
    expect(() => attestVerdict({ holderSecretKey: new Uint8Array(5), signed, gate, verdict: { rScaled: 0, slack: 0, admit: true } })).toThrow(new Error('signing key must be a 32-byte Ed25519 secret key'));
  });
  it('accepts a good attestation (with and without a gate to check) and returns the signed bit', () => {
    expect(v(att(true))).toEqual({ ok: true, admit: true });
    expect(v(att(false))).toEqual({ ok: true, admit: false });
    expect(v(att(true), E({ gate }))).toEqual({ ok: true, admit: true });
  });
  it('malformed shapes', () => {
    const a = att();
    const M = 'malformed attestation';
    const cases: unknown[] = [
      null, 5, 'x', undefined,
      { ...a, claimDigest: 1 }, { ...a, holder: 1 }, { ...a, sig: 1 }, { ...a, admit: 'yes' }, { ...a, admit: undefined },
      { ...a, gateDigest: undefined }, { ...a, gateDigest: null }, { ...a, gateDigest: 'g' },
      { ...a, gateDigest: { ...a.gateDigest, encRiskRaw: 1 } }, { ...a, gateDigest: { ...a.gateDigest, encSlack: undefined } },
    ];
    for (const c of cases) expect(r(v(c))).toBe(M);
  });
  it('untrusted holder, bad key/signature encodings', () => {
    const a = att();
    expect(r(v(a, E({ trustedHolders: [] })))).toBe('attestation holder is not trusted');
    const short = b64u(new Uint8Array(31));
    expect(r(v({ ...a, holder: short }, E({ trustedHolders: [short] })))).toBe('malformed holder key or signature');
    expect(r(v({ ...a, sig: b64u(new Uint8Array(63)) }))).toBe('malformed holder key or signature');
    expect(r(v({ ...a, sig: 'AAAA' }))).toBe('malformed holder key or signature');
  });
  it('signature must verify over every signed field', () => {
    const a = att();
    const S = 'attestation signature does not verify';
    expect(r(v({ ...a, admit: !a.admit }))).toBe(S);
    expect(r(v({ ...a, claimDigest: 'zzz' }, E({ claimDigest: 'zzz' })))).toBe(S);
    expect(r(v({ ...a, gateDigest: { ...a.gateDigest, encSlack: 'q' } }))).toBe(S);
    expect(r(v({ ...a, gateDigest: { ...a.gateDigest, encRiskRaw: 'q' } }))).toBe(S);
    expect(r(v({ ...a, sig: b64u(new Uint8Array(64)) }))).toBe(S);
    const other = generateKeyPair();
    expect(r(v({ ...a, holder: b64u(other.publicKey) }, E({ trustedHolders: [b64u(other.publicKey)] })))).toBe(S);
  });
  it('claim digest and gate output are checked, each field separately', () => {
    const a = att();
    expect(r(v(a, E({ claimDigest: 'other' })))).toBe('attestation is for a different claim');
    const G = 'attestation is for a different gate output';
    expect(r(v(a, E({ gate: { ...gate, encRiskRaw: 'X' } })))).toBe(G);
    expect(r(v(a, E({ gate: { ...gate, encSlack: 'X' } })))).toBe(G);
    expect(r(v(a, E({ gate: { encRiskRaw: 'X', encSlack: 'Y' } })))).toBe(G);
  });
  it('never throws on a broken expectation', () => {
    expect(r(v(att(), { claimDigest: 'x' } as never))).toBe('attestation could not be verified (malformed)');
  });
});

describe('encryptedRiskClaim + evalSignedRiskClaim happy path (real SEAL)', () => {
  it('builds a signed claim bound to the action and evaluates it', async () => {
    const keys = await keygen();
    const actn = {
      aud: 'rs.example', counter: 7, nonce: 'n-1', action: { params_digest: 'pd-1' },
      risk_claim: { inputs: { semanticDistance: 0.8, reversibility: 0.5, blastRadius: 0.3, taint: 0.9, confidence: 0.4, age: 0.2 } },
    } as unknown as PCActn;
    const sc = await encryptedRiskClaim({ actn, publicKey: keys.publicKey, policy, signerSecretKey: signer.secretKey, context: 'grant-1' });
    expect(sc.claim.binding).toEqual({ aud: 'rs.example', actionRef: 'pd-1', counter: 7, nonce: 'n-1' });
    expect(sc.claim.policy).toBe(policy);
    expect(sc.context).toBe('grant-1');
    expect(sc.signer).toBe(SIGNER);
    expect(sc.claim.encInputs.length).toBeGreaterThan(24);
    const e = exp({ binding: sc.claim.binding });
    const out = await evalSignedRiskClaim({ publicKey: keys.publicKey, relinKeys: keys.relinKeys, galoisKeys: keys.galoisKeys }, sc, e);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.claimDigest).toBe(signedClaimDigest(sc));
    expect(Object.keys(out).sort()).toEqual(['claimDigest', 'gate', 'ok']);
    const v = await decryptVerdict(keys.secretKey, out.gate.encRiskRaw, out.gate.encSlack, policy);
    expect(v.admit).toBe(typeof v.slack === 'number' && v.slack >= 0);
  }, 120_000);
});
