import { type PlanNode, buildPCActn, encodeKey, encodeMlDsaPublicKey, generateKeyPair, mintRoot, mlDsa65Keygen } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { NotAuthorizedError, TokenVault, oauthScopeCaveat } from './index';
import { InMemoryConnectionStore } from './testing';
const mkVault = (o: ConstructorParameters<typeof TokenVault>[0] = {}) => new TokenVault({ strict: false, store: new InMemoryConnectionStore(), ...o });

/** R4-01 follow-up: the vault takes the chain root from the PCActn; a PQ root must be authorised by a verifier-side pin. */
const NOW = 1_800_000_000_000;
const victim = generateKeyPair();
const vPub = encodeKey(victim.publicKey);
const atk = generateKeyPair();
const aPub = encodeKey(atk.publicKey);
const vMl = mlDsa65Keygen(new Uint8Array(32).fill(7));
const aMl = mlDsa65Keygen(new Uint8Array(32).fill(9));
const caveats = [oauthScopeCaveat('google', ['read'])];
const node: PlanNode = { id: 'use', verb: 'use_connection', resource: 'oauth:google' };

async function vaultWith(pqPins?: Record<string, string>) {
  const v = mkVault({ store: new InMemoryConnectionStore(), now: () => NOW, ...(pqPins ? { pqPins } : {}) });
  await v.putConnection({ agentId: aPub, provider: 'google', accessToken: 'AT', expiresAt: NOW + 3_600_000, scopes: ['read'], authority: { principal: vPub, scopes: ['read'] } });
  return v;
}
const actn = (root: ReturnType<typeof mintRoot>) =>
  buildPCActn({ grant: root, chain: [root], plan: [node], nodeId: 'use', counter: 1, signerSecret: atk.secretKey, aud: 'rs', now: NOW });

describe('R4-01: TokenVault with an artifact-supplied PQ root', () => {
  const forged = mintRoot({ principalSecret: atk.secretKey, principalPublic: vPub, holder: aPub, caveats, suite: { alg: 'ml-dsa-65', mlDsa: aMl } });
  const genuine = mintRoot({ principalSecret: victim.secretKey, principalPublic: vPub, holder: aPub, caveats, suite: { alg: 'ml-dsa-65', mlDsa: vMl } });

  it('refuses a forged pure-PQ root issued by the bound principal but signed under the attacker\'s own pq_pk', async () => {
    await expect((await vaultWith()).getConnectionToken(actn(forged), { provider: 'google' })).rejects.toBeInstanceOf(NotAuthorizedError);
    await expect((await vaultWith({ [vPub]: encodeMlDsaPublicKey(vMl.publicKey) })).getConnectionToken(actn(forged), { provider: 'google' })).rejects.toBeInstanceOf(NotAuthorizedError);
  });
  it('accepts the genuine PQ root only when the vault pins the principal\'s PQ key', async () => {
    await expect((await vaultWith()).getConnectionToken(actn(genuine), { provider: 'google' })).rejects.toBeInstanceOf(NotAuthorizedError);
    const t = await (await vaultWith({ [vPub]: encodeMlDsaPublicKey(vMl.publicKey) })).getConnectionToken(actn(genuine), { provider: 'google' });
    expect(t.accessToken).toBe('AT');
  });
});
