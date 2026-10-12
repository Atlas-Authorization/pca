import type { Capability } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { generateKeyPair } from './bbs';
import {
  capabilityAttributes,
  issueCapabilityCredential,
  presentCredential,
  verifyCredential,
  verifyPresentation,
} from './credential';

const TEXT = new TextEncoder();
const bytes = (s: string): Uint8Array => TEXT.encode(s);

// A PCA capability (only issuer/holder/caveats are mapped into the credential).
const capability: Pick<Capability, 'issuer' | 'holder' | 'caveats'> = {
  issuer: 'cGxhdF9mb3J1bXVsYXRl', // b64u-ish issuer key placeholder
  holder: 'YWdlbnQtN19ob2xkZXI',
  caveats: [
    { type: 'scope', actions: ['search:read', 'docs:read'] },
    { type: 'budget_alloc', limit: 100 },
    { type: 'expiry', notAfter: 1893456000 },
  ],
};

describe('PCA capability credential', () => {
  it('maps issuer, holder and each caveat to an ordered attribute vector', () => {
    const attrs = capabilityAttributes(capability);
    expect(attrs.map((a) => a.name)).toEqual([
      'iss',
      'sub',
      'cav:0:scope',
      'cav:1:budget_alloc',
      'cav:2:expiry',
    ]);
    expect(attrs.map((a) => a.index)).toEqual([0, 1, 2, 3, 4]);
    expect(attrs[0]?.value).toBe(capability.issuer);
  });

  it('round-trips: issue -> verify whole credential', () => {
    const { sk, pk } = generateKeyPair();
    const cred = issueCapabilityCredential(capability, { sk, pk, header: bytes('atlas-pca/v1') });
    expect(verifyCredential(cred)).toBe(true);
  });

  it('round-trips: issue -> present a subset -> verify presentation', () => {
    const { sk, pk } = generateKeyPair();
    const cred = issueCapabilityCredential(capability, { sk, pk });

    // Reveal only the scope caveat (what a tool needs); hide holder, budget, expiry, issuer.
    const pres = presentCredential(cred, {
      disclose: ['cav:0:scope'],
      presentationHeader: bytes('action:search?q=atlas'),
    });

    expect(pres.disclosed.map((d) => d.name)).toEqual(['cav:0:scope']);
    expect(pres.messageCount).toBe(5);
    expect(verifyPresentation(pres)).toBe(true);
  });

  it('verifier can pin issuer key, expected disclosure, and presentation header', () => {
    const { sk, pk } = generateKeyPair();
    const cred = issueCapabilityCredential(capability, { sk, pk });
    const ph = bytes('action:docs.read#42');
    const pres = presentCredential(cred, { disclose: ['iss', 'cav:0:scope'], presentationHeader: ph });

    expect(
      verifyPresentation(pres, {
        pk,
        disclosed: pres.disclosed,
        presentationHeader: ph,
      }),
    ).toBe(true);

    // Wrong pinned issuer key -> reject.
    const other = generateKeyPair();
    expect(verifyPresentation(pres, { pk: other.pk })).toBe(false);

    // Wrong pinned presentation header -> reject.
    expect(verifyPresentation(pres, { presentationHeader: bytes('action:docs.read#99') })).toBe(false);
  });

  it('verifyPresentation rejects a forged disclosed value', () => {
    const { sk, pk } = generateKeyPair();
    const cred = issueCapabilityCredential(capability, { sk, pk });
    const pres = presentCredential(cred, { disclose: ['cav:0:scope'] });

    const forged = {
      ...pres,
      disclosed: pres.disclosed.map((d) => ({ ...d, value: '{"type":"scope","actions":["admin:*"]}' })),
    };
    expect(verifyPresentation(forged)).toBe(false);
  });

  it('UNLINKABILITY: two presentations of the same credential are different bytes, both verify', () => {
    const { sk, pk } = generateKeyPair();
    const cred = issueCapabilityCredential(capability, { sk, pk });
    const a = presentCredential(cred, { disclose: ['cav:0:scope'] });
    const b = presentCredential(cred, { disclose: ['cav:0:scope'] });
    expect(a.proof).not.toBe(b.proof);
    expect(verifyPresentation(a)).toBe(true);
    expect(verifyPresentation(b)).toBe(true);
  });

  it('presentCredential throws on an unknown attribute name', () => {
    const { sk, pk } = generateKeyPair();
    const cred = issueCapabilityCredential(capability, { sk, pk });
    expect(() => presentCredential(cred, { disclose: ['cav:9:nope'] })).toThrow();
  });
});
