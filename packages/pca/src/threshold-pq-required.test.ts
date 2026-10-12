// R6-02: a role whose signer-set entry registers a `pq_pk` must be satisfied by a PQ (pure or hybrid) share.
// Before the fix an Ed25519-only share for a hybrid-registered role verified, so an Ed25519 break still
// forged that role. The registered PQ key now makes PQ mandatory for that role, for explicit shares and
// for the agent-leaf baseline alike. Roles WITHOUT a registered pq_pk keep accepting Ed25519 shares.
import { describe, expect, it } from 'vitest';
import { b64u, utf8 } from './hash';
import { encodeKey, generateKeyPair, sign } from './keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen, signWithSuite } from './pq';
import { type Signer, signShare, verifyThreshold } from './threshold';

const MSG = utf8('r6-02 threshold message');
const enc = (kp: { publicKey: Uint8Array }) => encodeKey(kp.publicKey);
const HYBRID = 'hybrid-ed25519-ml-dsa-65' as const;
const ML = 'ml-dsa-65' as const;

function setup() {
  const agent = generateKeyPair();
  const guardian = generateKeyPair();
  const principal = generateKeyPair();
  const agentMl = mlDsa65Keygen(new Uint8Array(32).fill(0x61));
  const guardianMl = mlDsa65Keygen(new Uint8Array(32).fill(0x67));
  const set: Signer[] = [
    { role: 'agent', publicKey: enc(agent), pq_pk: encodeMlDsaPublicKey(agentMl.publicKey) },
    { role: 'guardian', publicKey: enc(guardian), pq_pk: encodeMlDsaPublicKey(guardianMl.publicKey) },
    { role: 'principal', publicKey: enc(principal) },
  ];
  return { agent, guardian, principal, agentMl, guardianMl, set };
}

describe('R6-02: a registered pq_pk makes a PQ share mandatory for that role', () => {
  it('an Ed25519-only share for a role with a registered pq_pk is REJECTED', () => {
    const s = setup();
    const edAgent = signShare('agent', s.agent.secretKey, MSG, { signerSet: s.set, t: 1 });
    expect(verifyThreshold({ shares: [edAgent] }, MSG, s.set, 1)).toEqual({
      ok: false, count: 0, roles: [], reason: 'invalid signature for role agent',
    });
    const edGuardian = signShare('guardian', s.guardian.secretKey, MSG, { signerSet: s.set, t: 1 });
    expect(verifyThreshold({ shares: [edGuardian] }, MSG, s.set, 1).ok).toBe(false);
    // the same shape with suite 'ed25519' spelled out is equally refused
    const edExplicit = { ...edAgent, alg: 'ed25519' as const };
    expect(verifyThreshold({ shares: [edExplicit] }, MSG, s.set, 1).ok).toBe(false);
  });

  it('a hybrid or pure ML-DSA share under the registered pq_pk is accepted', () => {
    const s = setup();
    const hy = signShare('agent', s.agent.secretKey, MSG, { signerSet: s.set, t: 1 }, { alg: HYBRID, mlDsa: s.agentMl });
    expect(verifyThreshold({ shares: [hy] }, MSG, s.set, 1)).toEqual({ ok: true, count: 1, roles: ['agent'] });
    const ml = signShare('guardian', s.guardian.secretKey, MSG, { signerSet: s.set, t: 1 }, { alg: ML, mlDsa: s.guardianMl });
    expect(verifyThreshold({ shares: [ml] }, MSG, s.set, 1)).toEqual({ ok: true, count: 1, roles: ['guardian'] });
  });

  it('a role WITHOUT a registered pq_pk still accepts an Ed25519 share (additive)', () => {
    const s = setup();
    const p = signShare('principal', s.principal.secretKey, MSG, { signerSet: s.set, t: 1 });
    expect(verifyThreshold({ shares: [p] }, MSG, s.set, 1)).toEqual({ ok: true, count: 1, roles: ['principal'] });
  });

  it('t=3: an Ed25519 guardian share does not count toward the threshold when the guardian registered a pq_pk', () => {
    const s = setup();
    const a = signShare('agent', s.agent.secretKey, MSG, { signerSet: s.set, t: 3 }, { alg: HYBRID, mlDsa: s.agentMl });
    const gEd = signShare('guardian', s.guardian.secretKey, MSG, { signerSet: s.set, t: 3 });
    const gHy = signShare('guardian', s.guardian.secretKey, MSG, { signerSet: s.set, t: 3 }, { alg: HYBRID, mlDsa: s.guardianMl });
    const p = signShare('principal', s.principal.secretKey, MSG, { signerSet: s.set, t: 3 });
    expect(verifyThreshold({ shares: [a, gEd, p] }, MSG, s.set, 3).ok).toBe(false);
    expect(verifyThreshold({ shares: [a, gHy, p] }, MSG, s.set, 3)).toEqual({ ok: true, count: 3, roles: ['agent', 'guardian', 'principal'] });
  });

  it('agent-leaf baseline: an Ed25519 leaf is not admitted for an agent with a registered pq_pk; a hybrid leaf is', () => {
    const s = setup();
    const edBaseline = { holder: enc(s.agent), sig: b64u(sign(s.agent.secretKey, MSG)) };
    expect(verifyThreshold({ shares: [] }, MSG, s.set, 1, edBaseline).ok).toBe(false);
    expect(verifyThreshold({ shares: [] }, MSG, s.set, 1, { ...edBaseline, alg: 'ed25519' }).ok).toBe(false);
    const parts = signWithSuite(HYBRID, { edSecret: s.agent.secretKey, mlDsa: s.agentMl }, MSG);
    const hyBaseline = { holder: enc(s.agent), sig: parts.sig, alg: HYBRID, pqSig: parts.pq_sig };
    expect(verifyThreshold({ shares: [] }, MSG, s.set, 1, hyBaseline)).toEqual({ ok: true, count: 1, roles: ['agent'] });
  });

  it('agent-leaf baseline without a registered pq_pk: an Ed25519 leaf is still admitted', () => {
    const s = setup();
    const set: Signer[] = s.set.map((x) => (x.role === 'agent' ? { role: x.role, publicKey: x.publicKey } : x));
    const edBaseline = { holder: enc(s.agent), sig: b64u(sign(s.agent.secretKey, MSG)) };
    expect(verifyThreshold({ shares: [] }, MSG, set, 1, edBaseline)).toEqual({ ok: true, count: 1, roles: ['agent'] });
  });
});
