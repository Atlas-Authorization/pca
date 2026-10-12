import { type PlanNode, buildPCActn, encodeKey, encodeMlDsaPublicKey, generateKeyPair, mintRoot, mlDsa65Keygen } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { cmdExplain } from './index';

/** R4-01 follow-up: `explain` lifts the grant from cap_chain[0]; a PQ root must not self-authorise its pq_pk. */
const NOW = 1_800_000_000_000;
const victim = generateKeyPair();
const vPub = encodeKey(victim.publicKey);
const atk = generateKeyPair();
const aPub = encodeKey(atk.publicKey);
const vMl = mlDsa65Keygen(new Uint8Array(32).fill(7));
const aMl = mlDsa65Keygen(new Uint8Array(32).fill(9));
const node: PlanNode = { id: 'n', verb: 'x', resource: 'r', reversibility_class: 'reversible' } as PlanNode;
const caveats = [{ type: 'ttl', secs: 3600 }] as never;
const act = (root: ReturnType<typeof mintRoot>) =>
  JSON.stringify(buildPCActn({ grant: root, chain: [root], plan: [node], nodeId: 'n', counter: 1, signerSecret: atk.secretKey, aud: 'a', now: NOW }));

describe('R4-01: pca explain with an artifact-supplied PQ root', () => {
  it('does not ALLOW a forged pure-PQ root, and ALLOWs the genuine one only under a pin', async () => {
    const forged = mintRoot({ principalSecret: atk.secretKey, principalPublic: vPub, holder: aPub, caveats, suite: { alg: 'ml-dsa-65', mlDsa: aMl } });
    const genuine = mintRoot({ principalSecret: victim.secretKey, principalPublic: vPub, holder: aPub, caveats, suite: { alg: 'ml-dsa-65', mlDsa: vMl } });
    const pins = { [vPub]: encodeMlDsaPublicKey(vMl.publicKey) };
    expect((await cmdExplain(act(forged), { audience: 'a', now: NOW, pqPins: pins })).allow).toBe(false);
    expect((await cmdExplain(act(forged), { audience: 'a', now: NOW })).allow).toBe(false);
    expect((await cmdExplain(act(genuine), { audience: 'a', now: NOW })).allow).toBe(false);
    expect((await cmdExplain(act(genuine), { audience: 'a', now: NOW, pqPins: pins })).allow).toBe(true);
  });
});
