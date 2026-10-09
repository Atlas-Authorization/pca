import { describe, expect, it } from 'vitest';
import {
  WELL_KNOWN_PCA_PATH,
  acceptsSuite,
  buildDiscoveryDocument,
  fetchDiscovery,
  parseDiscoveryDocument,
} from './discovery';

describe('discovery document', () => {
  it('builds a well-formed doc with sensible defaults', () => {
    const doc = buildDiscoveryDocument({ audience: 'ins_acme' });
    expect(doc.audience).toBe('ins_acme');
    expect(doc.pca_versions).toEqual([2]);
    expect(doc.action_header).toBe('PCA-Action');
    expect(doc.signature_suites).toContain('hybrid-ed25519-ml-dsa-65');
    expect(doc.required_checks).toContain('audience');
  });

  it('carries endpoints + trusted roots when given', () => {
    const doc = buildDiscoveryDocument({
      audience: 'ins_acme',
      endpoints: { revocation_epoch: 'https://api.acme.com/v1/pca/revocations/epoch', stepup: 'https://api.acme.com/v1/pca/stepups' },
      trustedRoots: ['k_root1'],
    });
    expect(doc.endpoints?.revocation_epoch).toMatch(/revocations/);
    expect(doc.trusted_roots).toEqual(['k_root1']);
  });

  it('requires an audience', () => {
    expect(() => buildDiscoveryDocument({ audience: '' })).toThrow(/audience/);
  });

  it('round-trips through JSON + parse, and rejects malformed docs', () => {
    const doc = buildDiscoveryDocument({ audience: 'ins_acme' });
    const parsed = parseDiscoveryDocument(JSON.parse(JSON.stringify(doc)));
    expect(parsed).toEqual(doc);
    expect(() => parseDiscoveryDocument(null)).toThrow();
    expect(() => parseDiscoveryDocument({ audience: '' })).toThrow(/audience/);
    expect(() => parseDiscoveryDocument({ audience: 'x', pca_versions: ['2'], signature_suites: [], action_header: 'h' })).toThrow(/pca_versions/);
    expect(() => parseDiscoveryDocument({ audience: 'x', pca_versions: [2], signature_suites: 'nope', action_header: 'h' })).toThrow(/signature_suites/);
  });

  it('acceptsSuite reflects the advertised suites', () => {
    const doc = buildDiscoveryDocument({ audience: 'ins_acme', signatureSuites: ['ed25519'] });
    expect(acceptsSuite(doc, 'ed25519')).toBe(true);
    expect(acceptsSuite(doc, 'ml-dsa-65')).toBe(false);
  });

  it('fetchDiscovery GETs the well-known path and parses it', async () => {
    const doc = buildDiscoveryDocument({ audience: 'ins_acme' });
    let seenUrl = '';
    const fakeFetch = async (url: string) => {
      seenUrl = url;
      return { ok: true, status: 200, json: async () => doc };
    };
    const got = await fetchDiscovery('https://api.acme.com/', fakeFetch);
    expect(seenUrl).toBe('https://api.acme.com' + WELL_KNOWN_PCA_PATH);
    expect(got.audience).toBe('ins_acme');
  });

  it('fetchDiscovery throws on a non-2xx response', async () => {
    const fakeFetch = async () => ({ ok: false, status: 404, json: async () => ({}) });
    await expect(fetchDiscovery('https://api.acme.com', fakeFetch)).rejects.toThrow(/404/);
  });
});
