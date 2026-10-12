/**
 * Site kills for the per-site ledger migration: verifyCredential's second catch (credential.ts:155) and
 * verifyPresentation's second catch (credential.ts:234) are reachable and must return exactly `false`.
 */
import type { Capability } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { generateKeyPair } from './bbs';
import { issueCapabilityCredential, presentCredential, verifyCredential, verifyPresentation } from './credential';

const capability: Pick<Capability, 'issuer' | 'holder' | 'caveats'> = {
  issuer: 'cGxhdF9mb3J1bXVsYXRl',
  holder: 'YWdlbnQtN19ob2xkZXI',
  caveats: [{ type: 'scope', actions: ['search:read'] }],
};

describe('BBS credential verifiers: malformed structure is false, never undefined', () => {
  const { sk, pk } = generateKeyPair();
  const cred = issueCapabilityCredential(capability, { sk, pk });
  it('verifyCredential with attributes = null', () => {
    expect(verifyCredential(cred)).toBe(true);
    expect(verifyCredential({ ...cred, attributes: null as never })).toBe(false);
  });
  it('verifyPresentation with disclosed = null', () => {
    const pres = presentCredential(cred, { disclose: ['cav:0:scope'] });
    expect(verifyPresentation(pres)).toBe(true);
    expect(verifyPresentation({ ...pres, disclosed: null as never })).toBe(false);
  });
});
