import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair, mintRoot } from '@atlasauth/pca';
import { createAgent, type FetchLike, type Receipt } from './agent';

describe('verifyReceipt is total', () => {
  it('a receipt that is not an object is refused with false, never an exception', () => {
    const agentKp = generateKeyPair();
    const principal = generateKeyPair();
    const pub = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);
    const grant = mintRoot({ principalSecret: principal.secretKey, principalPublic: pub(principal), holder: pub(agentKp), caveats: [] });
    const fetch: FetchLike = async () => ({ status: 500, json: async () => ({}) });
    const a = createAgent({ grant, agentSecret: agentKp.secretKey, agentPublic: pub(agentKp), rsBaseUrl: 'https://rs.test/', audience: 'ins_test', fetch });
    expect(a.verifyReceipt(null as unknown as Receipt)).toBe(false);
    expect(a.verifyReceipt(undefined as unknown as Receipt)).toBe(false);
  });
});
