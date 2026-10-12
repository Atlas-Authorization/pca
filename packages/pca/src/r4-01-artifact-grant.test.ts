import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { generateKeyPair } from './keys';
import { mintRoot } from './capability';
import { buildPCActn, verifyPCActnCore } from './pcactn';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';

/** R4-01 follow-up: a grant lifted from the artifact (grantFromArtifact) is never a `trustedRoot` for a PQ root. */
const NOW = 1_800_000_000_000;
const victim = generateKeyPair();
const vPub = b64u(victim.publicKey);
const atk = generateKeyPair();
const aPub = b64u(atk.publicKey);
const vMl = mlDsa65Keygen(new Uint8Array(32).fill(7));
const aMl = mlDsa65Keygen(new Uint8Array(32).fill(9));
const caveats = [{ type: 'ttl', secs: 3600 }] as never;
const node = { id: 'n', verb: 'x', resource: 'r', reversibility_class: 'reversible' } as never;
const mk = (root: ReturnType<typeof mintRoot>) =>
  buildPCActn({ grant: root, chain: [root], plan: [node], nodeId: 'n', counter: 1, signerSecret: atk.secretKey, aud: 'a', now: NOW });

describe('R4-01: verifyPCActnCore grantFromArtifact', () => {
  const forged = mintRoot({ principalSecret: atk.secretKey, principalPublic: vPub, holder: aPub, caveats, suite: { alg: 'ml-dsa-65', mlDsa: aMl } });
  const genuine = mintRoot({ principalSecret: victim.secretKey, principalPublic: vPub, holder: aPub, caveats, suite: { alg: 'ml-dsa-65', mlDsa: vMl } });
  const pins = { [vPub]: encodeMlDsaPublicKey(vMl.publicKey) };

  it('a stored (verifier-held) grant still authorises its own PQ root (unchanged)', async () => {
    expect((await verifyPCActnCore(mk(genuine), { grant: genuine, audience: 'a', nowEpoch: NOW })).checks.cap_chain).toBe('pass');
  });
  it('an artifact-lifted PQ root is refused without a pin, and a forged one even with the victim\'s pin', async () => {
    const o = { audience: 'a', nowEpoch: NOW, grantFromArtifact: true } as const;
    expect((await verifyPCActnCore(mk(forged), { ...o, grant: forged })).checks.cap_chain).toBe('fail');
    expect((await verifyPCActnCore(mk(forged), { ...o, grant: forged, pqPins: pins })).checks.cap_chain).toBe('fail');
    expect((await verifyPCActnCore(mk(genuine), { ...o, grant: genuine })).checks.cap_chain).toBe('fail');
    expect((await verifyPCActnCore(mk(genuine), { ...o, grant: genuine, pqPins: pins })).checks.cap_chain).toBe('pass');
  });
  it('an ed25519 root is unaffected', async () => {
    const ed = mintRoot({ principalSecret: victim.secretKey, principalPublic: vPub, holder: aPub, caveats });
    expect((await verifyPCActnCore(mk(ed), { grant: ed, audience: 'a', nowEpoch: NOW, grantFromArtifact: true })).checks.cap_chain).toBe('pass');
  });
});
