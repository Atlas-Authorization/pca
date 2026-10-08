import { describe, expect, it } from 'vitest';
import { mintRoot } from './capability';
import { b64u, unb64u, utf8 } from './hash';
import { generateKeyPair } from './keys';
import { paramsDigest } from './merkle';
import {
  type PCActn,
  type PCActnBody,
  buildPCActn,
  signPCActn,
  signPCActnSuite,
  thresholdMessage,
  verifyPCActnCore,
} from './pcactn';
import {
  DEFAULT_SIG_ALG,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  ML_DSA_65_SIGNATURE_BYTES,
  isKnownSigAlg,
  mlDsa65Keygen,
  mlDsa65Sign,
  mlDsa65Verify,
  mlDsa65VerifyB64u,
  resolveSigAlg,
  verifyLeafSuite,
} from './pq';
import { validateWireV2 } from './wire';

const NOW = 1_800_000_000_000;
const AUD = 'rs-pq';

function fixture() {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const root = mintRoot({ principalSecret: P.secretKey, principalPublic: b64u(P.publicKey), holder: b64u(A.publicKey), caveats: [{ type: 'ttl', secs: 60 }] });
  const plan = [
    { id: 'n1', verb: 'read', resource: 'db/users' },
    { id: 'n2', verb: 'write', resource: 'db/orders', params_digest: paramsDigest({ qty: 3 }), reversibility_class: 'reversible' },
  ];
  const base = buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root], plan, nodeId: 'n2', params: { qty: 3 }, counter: 7, signerSecret: A.secretKey });
  const { sig: _s, ...body } = base;
  void _s;
  const mlDsa = mlDsa65Keygen(new Uint8Array(32).fill(7));
  return { root, agent: A, base, body: body as PCActnBody, mlDsa };
}

const flip = (s: string): string => {
  const b = unb64u(s);
  b[0] = b[0]! ^ 0x01;
  return b64u(b);
};

describe('B4 suite registry', () => {
  it('ed25519 is the default when alg is absent', () => {
    expect(DEFAULT_SIG_ALG).toBe('ed25519');
    expect(resolveSigAlg(undefined)?.alg).toBe('ed25519');
  });
  it('known algs resolve; unknown / non-string resolve to null (fail-closed)', () => {
    for (const a of ['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65']) {
      expect(isKnownSigAlg(a)).toBe(true);
      expect(resolveSigAlg(a)?.alg).toBe(a);
    }
    for (const bad of ['rsa-3072', 'ed448', '', 7, null, {}]) {
      expect(isKnownSigAlg(bad)).toBe(false);
      expect(resolveSigAlg(bad)).toBeNull();
    }
  });
});

describe('ML-DSA-65 primitive', () => {
  it('sign/verify roundtrip; sizes are FIPS-204 category 3', () => {
    const kp = mlDsa65Keygen(new Uint8Array(32).fill(3));
    expect(kp.publicKey.length).toBe(ML_DSA_65_PUBLIC_KEY_BYTES);
    const msg = utf8('post-quantum hello');
    const sig = mlDsa65Sign(kp.secretKey, msg);
    expect(sig.length).toBe(ML_DSA_65_SIGNATURE_BYTES);
    expect(mlDsa65Verify(kp.publicKey, msg, sig)).toBe(true);
    expect(mlDsa65VerifyB64u(b64u(kp.publicKey), msg, b64u(sig))).toBe(true);
  });
  it('wrong key, tampered message/sig, wrong lengths all fail (never throw)', () => {
    const kp = mlDsa65Keygen(new Uint8Array(32).fill(3));
    const other = mlDsa65Keygen(new Uint8Array(32).fill(4));
    const msg = utf8('m');
    const sig = mlDsa65Sign(kp.secretKey, msg);
    expect(mlDsa65Verify(other.publicKey, msg, sig)).toBe(false);
    expect(mlDsa65Verify(kp.publicKey, utf8('m2'), sig)).toBe(false);
    const bad = Uint8Array.from(sig); bad[0] = bad[0]! ^ 1;
    expect(mlDsa65Verify(kp.publicKey, msg, bad)).toBe(false);
    expect(mlDsa65Verify(kp.publicKey.subarray(0, 100), msg, sig)).toBe(false);
    expect(mlDsa65Verify(kp.publicKey, msg, sig.subarray(0, 100))).toBe(false);
    expect(mlDsa65VerifyB64u('!!', msg, b64u(sig))).toBe(false);
  });
});

describe('B4 backward compatibility (HARD CONSTRAINT: ed25519 / absent alg is unchanged)', () => {
  it('signPCActnSuite ed25519 is BYTE-IDENTICAL to signPCActn and carries no alg/pq fields', () => {
    const { body, agent } = fixture();
    const legacy = signPCActn(body, agent.secretKey);
    const viaSuite = signPCActnSuite(body, { alg: 'ed25519', edLeafSecret: agent.secretKey });
    expect(viaSuite).toEqual(legacy);
    expect('alg' in viaSuite).toBe(false);
    expect('pq_pk' in viaSuite).toBe(false);
    expect('pq_sig' in viaSuite).toBe(false);
  });
  it('an absent-alg PCActn still verifies, and verifyLeafSuite(absent) == the ed25519 leaf check', () => {
    const { base, root } = fixture();
    const msg = thresholdMessage(base);
    expect(verifyLeafSuite({ alg: undefined, holder: root.holder, message: msg, sig: base.sig })).toBe(true);
    // tamper -> false
    expect(verifyLeafSuite({ alg: undefined, holder: root.holder, message: msg, sig: flip(base.sig) })).toBe(false);
  });
  it('a pre-B4 object passes wire validation unchanged', () => {
    const { base } = fixture();
    expect(validateWireV2(base)).toBeNull();
  });
});

describe('B4 hybrid verify (both signatures REQUIRED, fail-closed)', () => {
  it('a valid hybrid PCActn is allowed end-to-end', async () => {
    const { body, agent, mlDsa, root } = fixture();
    const p = signPCActnSuite(body, { alg: 'hybrid-ed25519-ml-dsa-65', edLeafSecret: agent.secretKey, mlDsa });
    expect(p.alg).toBe('hybrid-ed25519-ml-dsa-65');
    expect(validateWireV2(p)).toBeNull();
    const r = await verifyPCActnCore(p, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r.allow).toBe(true);
    expect(r.checks.leaf_signature).toBe('pass');
  });
  it('valid Ed25519 but INVALID ML-DSA => fail (both required)', async () => {
    const { body, agent, mlDsa, root } = fixture();
    const p = signPCActnSuite(body, { alg: 'hybrid-ed25519-ml-dsa-65', edLeafSecret: agent.secretKey, mlDsa });
    const bad: PCActn = { ...p, pq_sig: flip(p.pq_sig!) };
    expect(validateWireV2(bad)).toBeNull(); // still well-formed; the failure is cryptographic
    const r = await verifyPCActnCore(bad, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r.allow).toBe(false);
    expect(r.checks.leaf_signature).toBe('fail');
  });
  it('INVALID Ed25519 but valid ML-DSA => fail (both required)', async () => {
    const { body, agent, mlDsa, root } = fixture();
    const p = signPCActnSuite(body, { alg: 'hybrid-ed25519-ml-dsa-65', edLeafSecret: agent.secretKey, mlDsa });
    const bad: PCActn = { ...p, sig: flip(p.sig) };
    const r = await verifyPCActnCore(bad, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r.allow).toBe(false);
    expect(r.checks.leaf_signature).toBe('fail');
  });
  it('DROPPING the ML-DSA component => wire fail (pq_sig required for hybrid)', async () => {
    const { body, agent, mlDsa, root } = fixture();
    const p = signPCActnSuite(body, { alg: 'hybrid-ed25519-ml-dsa-65', edLeafSecret: agent.secretKey, mlDsa });
    const dropped: Record<string, unknown> = { ...p };
    delete dropped.pq_sig;
    expect(validateWireV2(dropped)).not.toBeNull();
    const r = await verifyPCActnCore(dropped as unknown as PCActn, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r.allow).toBe(false);
    expect(r.checks.wire).toBe('fail');
    expect(Object.keys(r.checks)).toEqual(['wire']); // wire failure is terminal
  });
  it('verifyLeafSuite hybrid: both-valid=true, either-missing/invalid=false', () => {
    const { body, agent, mlDsa, root } = fixture();
    const p = signPCActnSuite(body, { alg: 'hybrid-ed25519-ml-dsa-65', edLeafSecret: agent.secretKey, mlDsa });
    const msg = thresholdMessage(p);
    const base = { alg: p.alg, holder: root.holder, pqPublicKey: p.pq_pk, message: msg } as const;
    expect(verifyLeafSuite({ ...base, sig: p.sig, pqSig: p.pq_sig })).toBe(true);
    expect(verifyLeafSuite({ ...base, sig: p.sig, pqSig: undefined })).toBe(false); // missing pq
    expect(verifyLeafSuite({ ...base, sig: undefined as unknown as string, pqSig: p.pq_sig })).toBe(false); // missing ed
    expect(verifyLeafSuite({ ...base, sig: flip(p.sig), pqSig: p.pq_sig })).toBe(false);
    expect(verifyLeafSuite({ ...base, sig: p.sig, pqSig: flip(p.pq_sig!) })).toBe(false);
  });
});

describe('B4 pure ml-dsa-65 verify', () => {
  it('a valid ml-dsa-65 PCActn is allowed; a corrupted one fails', async () => {
    const { body, mlDsa, root } = fixture();
    const p = signPCActnSuite(body, { alg: 'ml-dsa-65', mlDsa });
    expect(p.alg).toBe('ml-dsa-65');
    expect('pq_sig' in p).toBe(false);
    expect(validateWireV2(p)).toBeNull();
    const r = await verifyPCActnCore(p, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r.allow).toBe(true);
    expect(r.checks.leaf_signature).toBe('pass');

    const bad: PCActn = { ...p, sig: flip(p.sig) };
    const r2 = await verifyPCActnCore(bad, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r2.checks.leaf_signature).toBe('fail');
  });
});

describe('B4 unknown alg + stray fields fail closed on the wire', () => {
  it('unknown alg => wire fail (terminal)', async () => {
    const { body, agent, mlDsa, root } = fixture();
    const p = signPCActnSuite(body, { alg: 'hybrid-ed25519-ml-dsa-65', edLeafSecret: agent.secretKey, mlDsa });
    const bad = { ...p, alg: 'rsa-3072' } as unknown as PCActn;
    expect(validateWireV2(bad)).not.toBeNull();
    const r = await verifyPCActnCore(bad, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r.allow).toBe(false);
    expect(Object.keys(r.checks)).toEqual(['wire']);
    expect(verifyLeafSuite({ alg: 'rsa-3072', holder: root.holder, message: thresholdMessage(bad), sig: p.sig })).toBe(false);
  });
  it('ed25519 (absent alg) with a stray pq_pk / pq_sig => wire fail', () => {
    const { base, mlDsa } = fixture();
    expect(validateWireV2({ ...base, pq_pk: b64u(mlDsa.publicKey) })).not.toBeNull();
    expect(validateWireV2({ ...base, pq_sig: b64u(mlDsa65Sign(mlDsa.secretKey, utf8('x'))) })).not.toBeNull();
  });
  it('non-string alg => wire fail', () => {
    const { base } = fixture();
    expect(validateWireV2({ ...base, alg: 7 })).not.toBeNull();
  });
});
