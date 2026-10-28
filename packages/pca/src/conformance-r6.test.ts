import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { b64u, decodeB64uStrict, publicKeyOf, strictParse, verifyChain, verifyPCActnCore, type Capability, type PCActn } from './index';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';
import { signShare, signerSetHash, verifyThreshold, type Signer, type ThresholdShare } from './threshold';

/**
 * Round-6 natives coverage (gen-conformance-r6.mjs): the reference re-checks every threshold_set / signer_set_hash /
 * malformed primitive it wrote, exactly as the nine language verifiers must.
 */
type Entry = { name: string; role: string; t: number; signer_set: Signer[]; threshold_message: string; share: ThresholdShare; valid: boolean };
const file = JSON.parse(readFileSync(join(__dirname, '..', 'conformance', 'vectors.json'), 'utf8')) as {
  primitives: {
    threshold_set?: Entry[];
    signer_set_hash?: { name: string; signer_set: Signer[]; hash: string }[];
    malformed?: { name: string; api: string; input: unknown }[];
  };
};
const counts = (e: Entry) => {
  const msg = decodeB64uStrict(e.threshold_message);
  if (msg === null) return false;
  const v = verifyThreshold({ shares: [e.share] }, msg, e.signer_set, e.t);
  return !!e.share && e.share.role === e.role && v.roles.includes(e.role as never);
};

describe('R6-03: duplicate (role, key) with a conflicting pq_pk refuses the set', () => {
  const seed = (l: string) => new Uint8Array(createHash('sha256').update(`r6-unit/${l}`).digest());
  const agentSk = seed('agent');
  const agentPub = b64u(publicKeyOf(agentSk));
  const g = b64u(publicKeyOf(seed('guardian')));
  const aMl = mlDsa65Keygen(seed('a-ml'));
  const xMl = mlDsa65Keygen(seed('x-ml'));
  const pqA = encodeMlDsaPublicKey(aMl.publicKey);
  const pqX = encodeMlDsaPublicKey(xMl.publicKey);
  const msg = seed('msg');
  const hyb = 'hybrid-ed25519-ml-dsa-65' as const;
  it('first or last pq_pk: neither wins', () => {
    for (const set of [
      [{ role: 'agent', publicKey: agentPub, pq_pk: pqA }, { role: 'guardian', publicKey: g }, { role: 'agent', publicKey: agentPub, pq_pk: pqX }],
      [{ role: 'agent', publicKey: agentPub, pq_pk: pqX }, { role: 'guardian', publicKey: g }, { role: 'agent', publicKey: agentPub, pq_pk: pqA }],
      [{ role: 'agent', publicKey: agentPub, pq_pk: pqA }, { role: 'agent', publicKey: agentPub }],
    ] as Signer[][]) {
      for (const ml of [aMl, xMl]) {
        const share = signShare('agent', agentSk, msg, { signerSet: set, t: 1 }, { alg: hyb, mlDsa: ml });
        const v = verifyThreshold({ shares: [share] }, msg, set, 1);
        expect(v.ok).toBe(false);
        expect(v.reason).toBe('malformed signer set (pq_pk)');
      }
    }
  });
  it('an identical duplicate is still accepted', () => {
    const set: Signer[] = [{ role: 'agent', publicKey: agentPub, pq_pk: pqA }, { role: 'agent', publicKey: agentPub, pq_pk: pqA }];
    const share = signShare('agent', agentSk, msg, { signerSet: set, t: 1 }, { alg: hyb, mlDsa: aMl });
    expect(verifyThreshold({ shares: [share] }, msg, set, 1).ok).toBe(true);
  });
});

describe('round-6 conformance primitives (reference)', () => {
  const p = file.primitives;
  it('threshold_set: the reference reproduces every verdict', () => {
    expect(p.threshold_set?.length ?? 0).toBeGreaterThanOrEqual(55);
    for (const e of p.threshold_set!) expect([e.name, counts(e)]).toEqual([e.name, e.valid]);
  });
  it('signer_set_hash: UTF-8 order, pq_pk "" carried', () => {
    expect(p.signer_set_hash?.length ?? 0).toBeGreaterThanOrEqual(8);
    for (const e of p.signer_set_hash!) expect([e.name, b64u(signerSetHash(e.signer_set))]).toEqual([e.name, e.hash]);
  });
  it('malformed: every entry is a clean deny (never a throw)', async () => {
    expect(p.malformed?.length ?? 0).toBeGreaterThanOrEqual(80);
    for (const m of p.malformed!) {
      if (m.api === 'chain') {
        const i = m.input as { chain: Capability[]; expected_root_issuer: string };
        expect([m.name, verifyChain(i.chain, i.expected_root_issuer).ok]).toEqual([m.name, false]);
      } else if (m.api === 'threshold_share') {
        const e = m.input as Entry;
        const ok = e !== null && typeof e === 'object' && !Array.isArray(e) && counts(e);
        expect([m.name, ok]).toEqual([m.name, false]);
      } else if (m.api === 'pcactn_json') {
        const i = m.input as { text: string; grant: Capability; now: number; aud: string };
        let tree: unknown;
        try {
          tree = strictParse(i.text);
        } catch {
          continue;
        }
        const r = await verifyPCActnCore(tree as PCActn, { insecureSkipPlanRootCheck: true, grant: i.grant, nowEpoch: i.now, audience: i.aud });
        expect([m.name, r.allow]).toEqual([m.name, false]);
      } else throw new Error('unknown api ' + m.api);
    }
  });
});
