import { type Capability, type PlanNode, buildPCActn, encodeKey, encodeMlDsaPublicKey, generateKeyPair, mintRoot, mlDsa65Keygen } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { attachPcaToA2ATask, verifyA2ATask } from './index';

/** R4-01 follow-up: with no verifier-held `grant`, the root is lifted from the artifact; a PQ root's own pq_pk proves nothing. */
const NOW = 1_800_000_000_000;
const AUD = 'rs-1';
const victim = generateKeyPair();
const vPub = encodeKey(victim.publicKey);
const atk = generateKeyPair();
const aPub = encodeKey(atk.publicKey);
const vMl = mlDsa65Keygen(new Uint8Array(32).fill(7));
const aMl = mlDsa65Keygen(new Uint8Array(32).fill(9));
const plan: PlanNode[] = [{ id: 'n', verb: 'purchase', resource: 'r/1', reversibility_class: 'reversible' }];
const caveats = [{ type: 'ttl', secs: 3600 }] as never;
const act = (g: Capability) => attachPcaToA2ATask({ id: 't', status: { state: 'submitted' } }, buildPCActn({ grant: g, chain: [g], plan, nodeId: 'n', counter: 1, signerSecret: atk.secretKey, aud: AUD, now: NOW }));

describe('R4-01: A2A verify with an artifact-supplied PQ root', () => {
  const forged = mintRoot({ principalSecret: atk.secretKey, principalPublic: vPub, holder: aPub, caveats, suite: { alg: 'ml-dsa-65', mlDsa: aMl } });
  const genuine = mintRoot({ principalSecret: victim.secretKey, principalPublic: vPub, holder: aPub, caveats, suite: { alg: 'ml-dsa-65', mlDsa: vMl } });

  it('rejects a forged pure-PQ root self-signed under its own pq_pk', async () => {
    const r = await verifyA2ATask(act(forged), { aud: AUD, now: NOW, expectedRootIssuer: vPub });
    expect(r.ok).toBe(false);
    // the artifact root is admitted only under the pinned principal: a PQ root without a server-side pin fails pq_pin
    expect(r.result?.checks.pq_pin).toBe('fail');
  });
  it('rejects it even when a pin exists for the victim (attacker key is not the pin)', async () => {
    const r = await verifyA2ATask(act(forged), { aud: AUD, now: NOW, expectedRootIssuer: vPub, pqPins: { [vPub]: encodeMlDsaPublicKey(vMl.publicKey) } });
    expect(r.ok).toBe(false);
  });
  it('accepts the genuine root only under the verifier-side pin', async () => {
    expect((await verifyA2ATask(act(genuine), { aud: AUD, now: NOW, expectedRootIssuer: vPub })).result?.checks.pq_pin).toBe('fail');
    const r = await verifyA2ATask(act(genuine), { aud: AUD, now: NOW, expectedRootIssuer: vPub, pqPins: { [vPub]: encodeMlDsaPublicKey(vMl.publicKey) } });
    expect(r.result?.checks.cap_chain).toBe('pass');
    expect(r.result?.checks.pq_pin).toBe('pass');
  });
});
