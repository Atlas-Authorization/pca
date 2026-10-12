/** Round 2: presentation echo checks that only matter when the echoed list differs from the asserted one. */
import { describe, expect, it } from 'vitest';
import { generateKeyPair } from './bbs';
import { issueCapabilityCredential, presentCredential, verifyCredential, verifyPresentation, type BBSPresentation } from './credential';

const kp = generateKeyPair();
const cred = issueCapabilityCredential({ issuer: 'i', holder: 'h', caveats: [{ type: 'scope', actions: ['a'] }] } as never, { sk: kp.sk, pk: kp.pk });
const pres = presentCredential(cred, { disclose: ['iss', 'sub'] });
const clone = (): BBSPresentation => JSON.parse(JSON.stringify(pres));
const [a, b] = pres.disclosed as [BBSPresentation['disclosed'][number], BBSPresentation['disclosed'][number]];

describe('sameDisclosure', () => {
  it('an echoed list with an extra entry is refused even if the asserted list verifies', () => {
    const t = clone();
    t.disclosed = [a, b, { index: 2, name: 'cav:0:scope', value: 'x' }];
    expect(verifyPresentation(t, { disclosed: [a, b] })).toBe(false);
  });
  it('the echoed list is compared order-insensitively', () => {
    const t = clone();
    t.disclosed = [b, a];
    expect(verifyPresentation(t, { disclosed: [a, b] })).toBe(true);
    expect(verifyPresentation(t, { disclosed: [b, a] })).toBe(true);
  });
  it('non-string stored fields fail closed without throwing', () => {
    expect(verifyCredential({ ...cred, issuerPublicKey: 5 as never })).toBe(false);
    expect(verifyCredential({ ...cred, header: null as never })).toBe(false);
    expect(verifyCredential({ ...cred, signature: undefined as never })).toBe(false);
    const t = clone();
    (t as unknown as Record<string, unknown>).presentationHeader = 5;
    expect(verifyPresentation(t)).toBe(false);
    const u = clone();
    (u as unknown as Record<string, unknown>).proof = 5;
    expect(verifyPresentation(u)).toBe(false);
  });
});
