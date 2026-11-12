import { describe, expect, it } from 'vitest';
import { oauthDiscoveryHandler, parseProtectedResourceMetadata, protectedResourceMetadata } from './index';

function settle<T>(f: () => T): { ok: true; value: T } | { ok: false; message: string } {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    return { ok: false, message: (e as Error).message };
  }
}
const R = 'https://api.acme.com';
const doc = () => JSON.parse(JSON.stringify(protectedResourceMetadata({ resource: R })));

describe('0.5 strict-by-default', () => {
  it('parse without expectedResource is refused unless strict: false', () => {
    const msg = 'parseProtectedResourceMetadata: expectedResource is required (RFC 9728 section 3.3); pass strict: false to skip';
    expect(settle(() => parseProtectedResourceMetadata(doc()))).toEqual({ ok: false, message: msg });
    expect(settle(() => parseProtectedResourceMetadata(doc(), { strict: true }))).toEqual({ ok: false, message: msg });
    expect(settle(() => parseProtectedResourceMetadata(doc(), { strict: false })).ok).toBe(true);
    expect(settle(() => parseProtectedResourceMetadata(doc(), { expectedResource: R })).ok).toBe(true);
  });
  it('shape errors win over the expectedResource requirement', () => {
    expect(settle(() => parseProtectedResourceMetadata({ resource: R }))).toEqual({
      ok: false,
      message: 'parseProtectedResourceMetadata: bearer_methods_supported must be a string[]',
    });
  });
  it('the pca configuration endpoint ignores a query component of the resource identifier', () => {
    expect(protectedResourceMetadata({ resource: `${R}/mcp?tenant=1` }).pca_configuration_endpoint).toBe(`${R}/mcp/.well-known/pca-configuration`);
    expect(protectedResourceMetadata({ resource: `${R}/` }).pca_configuration_endpoint).toBe(`${R}/.well-known/pca-configuration`);
  });
  it('the handler path carries the resource path and query (RFC 9728 3.1)', () => {
    const h = oauthDiscoveryHandler({ resource: `${R}/mcp?tenant=1` });
    expect(h.path).toBe('/.well-known/oauth-protected-resource/mcp?tenant=1');
    expect(h.rfcPath).toBe(h.path);
  });
});
