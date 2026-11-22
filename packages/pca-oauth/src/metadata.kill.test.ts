import { describe, expect, it } from 'vitest';
import { WELL_KNOWN_PCA_PATH } from '@atlasauth/pca';
import {
  checkResourceIndicator,
  checkTokenAudience,
  mcpUnauthorized,
  parseProtectedResourceMetadata,
  protectedResourceMetadata,
  wwwAuthenticate,
} from './index';

const RS = 'https://rs.example.com';
const P = 'parseProtectedResourceMetadata: ';

function msg(f: () => unknown): string {
  try {
    f();
  } catch (e) {
    return (e as Error).message;
  }
  return 'NO THROW';
}
const base = (): Record<string, unknown> => JSON.parse(JSON.stringify(protectedResourceMetadata({ resource: RS })));
const lax = { strict: false } as const;
const parse = (v: unknown, o: { strict?: boolean; expectedResource?: string } = lax) => msg(() => parseProtectedResourceMetadata(v, o));

describe('protectedResourceMetadata', () => {
  it('refuses a missing or empty resource with the exact message, strict or not', () => {
    const m = 'protectedResourceMetadata: `resource` (the RS id = PCActn audience) is required';
    for (const resource of ['', 5, undefined]) {
      expect(msg(() => protectedResourceMetadata({ resource: resource as never }))).toBe(m);
      expect(msg(() => protectedResourceMetadata({ resource: resource as never, strict: false }))).toBe(m);
    }
  });
  it('derives the configuration endpoint without any run of trailing slashes', () => {
    expect(protectedResourceMetadata({ resource: 'https://rs.example.com//', strict: false }).pca_configuration_endpoint).toBe(`https://rs.example.com${WELL_KNOWN_PCA_PATH}`);
  });
  it('advertises resource_signing_alg_values_supported as given', () => {
    expect(protectedResourceMetadata({ resource: RS, resourceSigningAlgValuesSupported: ['EdDSA', 'ES256'] }).resource_signing_alg_values_supported).toEqual(['EdDSA', 'ES256']);
  });
});

describe('parseProtectedResourceMetadata shape checks', () => {
  it('a non-object is refused', () => {
    for (const v of [null, 5, 'str', undefined]) expect(parse(v)).toBe(`${P}not an object`);
  });
  it('resource must be a non-empty string', () => {
    for (const resource of [undefined, 5, '']) expect(parse({ ...base(), resource })).toBe(`${P}missing \`resource\``);
  });
  it('bearer_methods_supported must be an array of strings', () => {
    for (const v of [undefined, 'header', ['header', 5], [5]]) expect(parse({ ...base(), bearer_methods_supported: v })).toBe(`${P}bearer_methods_supported must be a string[]`);
  });
  it('pca_action_header must be a non-empty string', () => {
    for (const v of [undefined, 5, '']) expect(parse({ ...base(), pca_action_header: v })).toBe(`${P}missing pca_action_header`);
  });
  it('pca_signature_suites must be an array of strings', () => {
    for (const v of [undefined, 'x', ['a', 5], [5]]) expect(parse({ ...base(), pca_signature_suites: v })).toBe(`${P}pca_signature_suites must be a string[]`);
  });
  it('pca_versions must be an array of numbers', () => {
    for (const v of [undefined, 1, ['1'], [1, '2']]) expect(parse({ ...base(), pca_versions: v })).toBe(`${P}pca_versions must be a number[]`);
  });
  it('the embedded pca document must be an object with an audience', () => {
    for (const v of [null, undefined, 'x', 5]) expect(parse({ ...base(), pca: v })).toBe(`${P}missing embedded \`pca\` discovery document`);
    for (const pca of [{}, { audience: '' }, { audience: 5 }]) expect(parse({ ...base(), pca })).toBe(`${P}embedded pca.audience is required`);
  });
  it('a valid document parses', () => {
    expect(parse(base(), { expectedResource: RS })).toBe('NO THROW');
  });
});

describe('parseProtectedResourceMetadata strict bearer methods', () => {
  const strictWith = (methods: unknown[]) => parse({ ...base(), bearer_methods_supported: methods }, { expectedResource: RS });
  it('accepts header, body and query, each on its own, and refuses anything else', () => {
    for (const m of ['header', 'body', 'query']) expect(strictWith([m])).toBe('NO THROW');
    expect(strictWith(['header', 'body', 'query'])).toBe('NO THROW');
    const m = `${P}bearer_methods_supported has a value outside header/body/query`;
    expect(strictWith(['bogus'])).toBe(m);
    expect(strictWith(['header', 'bogus'])).toBe(m);
    expect(strictWith(['bogus', 'header'])).toBe(m);
  });
});

describe('parseProtectedResourceMetadata optional members', () => {
  const keysOf = (extra: Record<string, unknown>) => {
    const doc = base();
    for (const k of ['authorization_servers', 'resource_documentation', 'scopes_supported', 'resource_name', 'resource_signing_alg_values_supported', 'pca_configuration_endpoint', 'authorization_details_types_supported']) delete doc[k];
    return Object.keys(parseProtectedResourceMetadata({ ...doc, ...extra }, lax)).sort();
  };
  const core = ['bearer_methods_supported', 'pca', 'pca_action_header', 'pca_signature_suites', 'pca_versions', 'resource'];
  it('absent members are absent from the result, not present as undefined', () => {
    expect(keysOf({})).toEqual(core);
  });
  it('wrongly typed members are dropped', () => {
    expect(
      keysOf({
        pca_configuration_endpoint: 5,
        authorization_servers: ['a', 5],
        resource_documentation: 5,
        scopes_supported: ['a', 5],
        resource_name: 5,
        resource_signing_alg_values_supported: ['a', 5],
      }),
    ).toEqual(core);
    expect(keysOf({ authorization_servers: 'a', scopes_supported: 'a', resource_signing_alg_values_supported: 'a' })).toEqual(core);
  });
  it('well typed members are kept', () => {
    const got = parseProtectedResourceMetadata(
      {
        ...base(),
        pca_configuration_endpoint: 'https://x/c',
        authorization_servers: ['https://as'],
        resource_documentation: 'https://docs',
        scopes_supported: ['s1', 's2'],
        resource_name: 'RS',
        resource_signing_alg_values_supported: ['EdDSA'],
      },
      lax,
    );
    expect(got).toMatchObject({
      pca_configuration_endpoint: 'https://x/c',
      authorization_servers: ['https://as'],
      resource_documentation: 'https://docs',
      scopes_supported: ['s1', 's2'],
      resource_name: 'RS',
      resource_signing_alg_values_supported: ['EdDSA'],
    });
  });
});

describe('wwwAuthenticate and mcpUnauthorized', () => {
  it('requires a non-empty string prmUrl', () => {
    for (const u of ['', 5, undefined]) expect(msg(() => wwwAuthenticate(u as never))).toBe('wwwAuthenticate: prmUrl is required');
  });
  it('an empty hint adds no hint parameter', () => {
    expect(wwwAuthenticate('https://x/prm', { hint: '' })).toBe('Bearer resource_metadata="https://x/prm", PCA realm="pca"');
  });
  it('mcpUnauthorized defaults the error and keeps a given one and its description only when set', () => {
    expect(mcpUnauthorized('https://x/prm').body).toEqual({ error: 'invalid_request', resource_metadata: 'https://x/prm' });
    expect(Object.keys(mcpUnauthorized('https://x/prm').body).sort()).toEqual(['error', 'resource_metadata']);
    expect(mcpUnauthorized('https://x/prm', { error: 'invalid_token', errorDescription: 'expired' }).body).toEqual({
      error: 'invalid_token',
      resource_metadata: 'https://x/prm',
      error_description: 'expired',
    });
  });
});

describe('resource indicator and token audience checks', () => {
  it('checkResourceIndicator needs a non-empty string expected audience', () => {
    for (const a of ['', 5, undefined]) expect(msg(() => checkResourceIndicator('x', a as never))).toBe('checkResourceIndicator: expectedAudience is required');
  });
  it('a null indicator is "no resource indicator presented"', () => {
    expect(checkResourceIndicator(null, 'a')).toEqual({ ok: false, reason: 'no resource indicator presented' });
    expect(checkResourceIndicator(undefined, 'a')).toEqual({ ok: false, reason: 'no resource indicator presented' });
  });
  it('non-string array entries are skipped, not fatal', () => {
    expect(checkResourceIndicator([null as never, undefined as never, 5 as never, '', 'a'], 'a')).toEqual({ ok: true, matched: 'a' });
  });
  it('checkTokenAudience needs a non-empty string expected resource', () => {
    for (const a of ['', 5, undefined]) expect(msg(() => checkTokenAudience('x', a as never))).toBe('checkTokenAudience: expectedResource is required');
  });
});
