// Rotation + the real revocation registry, end to end. Lives outside src/ so the package build does not need pca-revoke.
import { describe, expect, it } from 'vitest';
import { type PCActn, buildPCActn, attenuate, encodeKey, generateKeyPair, mintRoot } from '@atlasauth/pca';
import { RevocationRegistry, checkRevocation } from '../../pca-revoke/src/index';
import { applyRotation, rotateAgentKey } from '../src/index';

describe('rotate then revoke with the real registry', () => {
  it('the old chain is denied, the re-issued chain is not, and the holder key is never revoked', async () => {
    const P = generateKeyPair();
    const A = generateKeyPair();
    const root = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: [{ type: 'ttl', secs: 3600 }] });
    const leaf = attenuate(root, [{ type: 'resource', prefix: '/acct' }], A.secretKey);
    const old = [root, leaf];
    const plan = [{ id: 'n1', verb: 'read', resource: '/acct' }];
    const mk = (chain: typeof old, k: Uint8Array): PCActn => buildPCActn({ grant: root, chain, plan, nodeId: 'n1', counter: 0, signerSecret: k, aud: 'x' });
    const reg = new RevocationRegistry();

    const A2 = generateKeyPair();
    const out = rotateAgentKey(old, { oldHolderSecret: A.secretKey, newKeyPair: A2, now: 5 });
    await applyRotation(reg, out.revocation, out.chain);

    expect((await checkRevocation(mk(old, A.secretKey), reg, { now: 6 })).revoked).toBe(true);
    expect(await checkRevocation(mk(out.chain, A2.secretKey), reg, { now: 6 })).toEqual({ revoked: false });
    expect((await reg.list()).map((e) => e.kind)).toEqual(['cap']);
  });
});
