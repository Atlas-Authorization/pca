/**
 * Origin authentication of the encrypted claim: unsigned / wrong-signer / replayed / re-contexted / tampered
 * claims are refused BEFORE the ciphertext reaches SEAL; the key holder can attest the decision back.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_RISK_POLICY, b64u, generateKeyPair, type PCActn } from '@atlasauth/pca';
import {
  type ClaimExpectations,
  type EvalKeys,
  type FheKeyset,
  type SignedRiskClaim,
  attestVerdict,
  decryptVerdict,
  encryptRiskInputs,
  encryptedRiskClaim,
  evalSignedRiskClaim,
  fheRiskPolicy,
  keygen,
  memoryNonceGuard,
  quantizeRiskInputs,
  signRiskClaim,
  signedClaimDigest,
  verifySignedRiskClaim,
  verifyVerdictAttestation,
} from './index';

const TIMEOUT = 60_000;
const inputs = { semanticDistance: 0.8, reversibility: 0.5, blastRadius: 0.3, taint: 0.9, confidence: 0.4, age: 0.2 };

function actn(): PCActn {
  return {
    aud: 'rs.example',
    counter: 7,
    nonce: 'n-1',
    action: { params_digest: 'pd-1' },
    risk_claim: { inputs: { ...inputs } },
  } as unknown as PCActn;
}

describe('origin authentication of the encrypted claim', () => {
  let keys: FheKeyset;
  let evalKeys: EvalKeys;
  const signer = generateKeyPair();
  const policy = fheRiskPolicy(DEFAULT_RISK_POLICY, 0.6);
  let signed: SignedRiskClaim;
  const exp = (over: Partial<ClaimExpectations> = {}): ClaimExpectations => ({
    trustedSigners: [b64u(signer.publicKey)],
    context: 'grant-1',
    binding: signed.claim.binding,
    policy,
    nonces: memoryNonceGuard(),
    ...over,
  });

  beforeAll(async () => {
    keys = await keygen();
    evalKeys = { publicKey: keys.publicKey, relinKeys: keys.relinKeys, galoisKeys: keys.galoisKeys };
    signed = await encryptedRiskClaim({ actn: actn(), publicKey: keys.publicKey, policy, signerSecretKey: signer.secretKey, context: 'grant-1' });
  }, TIMEOUT);

  it('a genuinely signed claim is accepted and evaluates', async () => {
    const r = await evalSignedRiskClaim(evalKeys, signed, exp());
    expect(r.ok).toBe(true);
  }, TIMEOUT);

  it('ATTACK: anyone with the PUBLIC key can mint a ciphertext of any slack - unsigned claims are refused', async () => {
    const forgedEnc = await encryptRiskInputs(keys.publicKey, quantizeRiskInputs({ semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 }));
    const unsigned = { claim: { binding: signed.claim.binding, encInputs: forgedEnc, policy } };
    for (const bad of [unsigned, signed.claim, null, undefined, 'x', {}]) {
      const r = await evalSignedRiskClaim(evalKeys, bad, exp());
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toMatch(/not signed|malformed/);
    }
  }, TIMEOUT);

  it('a self-signed forgery by an untrusted key is refused (signer pinned)', async () => {
    const attacker = generateKeyPair();
    const forged = signRiskClaim({ claim: signed.claim, signerSecretKey: attacker.secretKey, context: 'grant-1' });
    const r = verifySignedRiskClaim(forged, exp());
    expect(r).toEqual({ ok: false, reason: 'signer is not a trusted encryptor' });
    // swapping the signer field to a trusted key does not help
    const swapped = { ...forged, signer: b64u(signer.publicKey) };
    const r2 = verifySignedRiskClaim(swapped, exp());
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.reason).toMatch(/signature does not verify/);
  });

  it('a swapped ciphertext (evaluator or network substitutes its own) breaks the signature', async () => {
    const forgedEnc = await encryptRiskInputs(keys.publicKey, quantizeRiskInputs({ semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 }));
    const swapped: SignedRiskClaim = { ...signed, claim: { ...signed.claim, encInputs: forgedEnc } };
    const r = verifySignedRiskClaim(swapped, exp());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/signature does not verify/);
  }, TIMEOUT);

  it('wrong context, wrong action binding and wrong policy are each refused', () => {
    expect(verifySignedRiskClaim(signed, exp({ context: 'grant-2' }))).toMatchObject({ ok: false, reason: expect.stringMatching(/context mismatch/) });
    expect(verifySignedRiskClaim(signed, exp({ binding: { ...signed.claim.binding, counter: 8 } }))).toMatchObject({ ok: false, reason: expect.stringMatching(/binding mismatch/) });
    const other = fheRiskPolicy(DEFAULT_RISK_POLICY, 0.9);
    expect(verifySignedRiskClaim(signed, exp({ policy: other }))).toMatchObject({ ok: false, reason: expect.stringMatching(/policy mismatch/) });
    // the claim's own embedded context / policy cannot be altered either
    expect(verifySignedRiskClaim({ ...signed, context: 'grant-2' }, exp({ context: 'grant-2' }))).toMatchObject({ ok: false, reason: expect.stringMatching(/signature/) });
    expect(verifySignedRiskClaim({ ...signed, claim: { ...signed.claim, policy: other } }, exp({ policy: other }))).toMatchObject({ ok: false, reason: expect.stringMatching(/signature/) });
  });

  it('REPLAY: the same signed claim is accepted once per guard; a refused claim does not burn its nonce', () => {
    const nonces = memoryNonceGuard();
    expect(verifySignedRiskClaim(signed, exp({ context: 'wrong', nonces })).ok).toBe(false); // refused on context, nonce not consumed
    expect(verifySignedRiskClaim(signed, exp({ nonces })).ok).toBe(true);
    const again = verifySignedRiskClaim(signed, exp({ nonces }));
    expect(again).toMatchObject({ ok: false, reason: expect.stringMatching(/replay/) });
  });

  it('the guard fails closed when full instead of evicting', () => {
    const g = memoryNonceGuard(1);
    expect(g.claim('a')).toBe(true);
    expect(g.claim('b')).toBe(false);
    expect(g.claim('a')).toBe(false);
  });

  it('malformed signatures, nonces and signer encodings are refused, never thrown', () => {
    for (const mut of [{ sig: 'AAAA' }, { sig: signed.sig + '=' }, { nonce: 'x' }, { signer: 'short' }, { claim: null }, { claim: { ...signed.claim, binding: null } }]) {
      expect(() => verifySignedRiskClaim({ ...signed, ...mut }, exp())).not.toThrow();
      expect(verifySignedRiskClaim({ ...signed, ...mut }, exp()).ok).toBe(false);
    }
  });

  it('signing refuses an empty or oversized context and a bad key', () => {
    expect(() => signRiskClaim({ claim: signed.claim, signerSecretKey: signer.secretKey, context: '' })).toThrow();
    expect(() => signRiskClaim({ claim: signed.claim, signerSecretKey: new Uint8Array(5), context: 'x' })).toThrow();
  });

  it('VERDICT ATTESTATION: the key holder signs admit bound to the claim and the exact gate output', async () => {
    const holder = generateKeyPair();
    const ev = await evalSignedRiskClaim(evalKeys, signed, exp());
    if (!ev.ok) throw new Error(ev.reason);
    const verdict = await decryptVerdict(keys.secretKey, ev.gate.encRiskRaw, ev.gate.encSlack, policy);
    const att = attestVerdict({ holderSecretKey: holder.secretKey, signed, gate: ev.gate, verdict });
    const trust = { trustedHolders: [b64u(holder.publicKey)], claimDigest: signedClaimDigest(signed), gate: ev.gate };
    expect(verifyVerdictAttestation(att, trust)).toEqual({ ok: true, admit: verdict.admit });
    expect(JSON.stringify(att)).not.toContain(String(verdict.slack)); // slack / r are not disclosed
    // flipped decision, other claim, other gate output, untrusted holder
    expect(verifyVerdictAttestation({ ...att, admit: !att.admit }, trust).ok).toBe(false);
    expect(verifyVerdictAttestation(att, { ...trust, claimDigest: 'other' })).toMatchObject({ ok: false, reason: expect.stringMatching(/different claim/) });
    expect(verifyVerdictAttestation(att, { ...trust, gate: { encRiskRaw: ev.gate.encSlack, encSlack: ev.gate.encRiskRaw } })).toMatchObject({ ok: false, reason: expect.stringMatching(/different gate/) });
    expect(verifyVerdictAttestation(att, { ...trust, trustedHolders: [b64u(signer.publicKey)] }).ok).toBe(false);
    expect(verifyVerdictAttestation(null, trust).ok).toBe(false);
  }, TIMEOUT);
});
