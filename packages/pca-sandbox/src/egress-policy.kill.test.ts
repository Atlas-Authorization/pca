import { describe, expect, it } from 'vitest';
import { authFixture } from './test-auth';
import { EgressPolicy, isPrivateAddress, sha256b64u, type EgressTemplate } from './index';

const get = { verb: 'http.get', resource: 'api', params: { path: '/v1/items' } };
const base = (over: Partial<EgressTemplate> = {}): EgressTemplate => ({ method: 'GET', scheme: 'https', host: 'api.example.com', path: '/v1/items', ...over });

async function admitted(over: Partial<EgressTemplate> = {}) {
  const f = authFixture(['api']);
  const p = new EgressPolicy();
  const result = await f.allow(get);
  p.admit(result, get, () => base(over));
  return { p, result };
}
async function refusal(over: Partial<EgressTemplate>): Promise<string> {
  try {
    await admitted(over);
  } catch (e) {
    return (e as Error).message;
  }
  return 'ADMITTED';
}

describe('EgressPolicy.admit template validation', () => {
  it('hosts: lowercase names, and IP literals in lowercase only', async () => {
    expect(await refusal({ host: '::1' })).toBe('ADMITTED');
    expect(await refusal({ host: '127.0.0.1' })).toBe('ADMITTED');
    expect(await refusal({ host: 'fe80::1' })).toBe('ADMITTED');
    expect(await refusal({ host: 'FE80::1' })).toBe('bad_template_host');
    expect(await refusal({ host: 'API.example.com' })).toBe('bad_template_host');
    expect(await refusal({ host: 'bad host' })).toBe('bad_template_host');
    expect(await refusal({ host: '' })).toBe('bad_template_host');
  });
  it('methods are upper-case letters only', async () => {
    expect(await refusal({ method: 'POST' })).toBe('ADMITTED');
    for (const method of ['get', '1GET', 'GET1', 'GE T', '', 'GET\n']) expect(await refusal({ method })).toBe('bad_template_method');
  });
  it('paths are absolute, with no query, fragment, backslash, encoded dot or slash, or dot segment', async () => {
    for (const path of ['/a', '/a/', '/a.b', '/a..b', '/.well-known/x', '/a/b']) expect(await refusal({ path })).toBe('ADMITTED');
    for (const path of ['a', '/a?x=1', '/a#f', '/a\\b', '/a%2eb', '/a%2Fb', '/a%5cb', '/a/./b', '/a/../b', '/a/..', '/a/.', '/./a', '/../a', '/..', '/.']) {
      expect(await refusal({ path }), path).toBe('bad_template_path');
    }
  });
  it('scheme and port', async () => {
    expect(await refusal({ scheme: 'ftp' as never })).toBe('bad_template_scheme');
    expect(await refusal({ port: 0 })).toBe('bad_template_port');
    expect(await refusal({ port: 65536 })).toBe('bad_template_port');
    expect(await refusal({ port: 1 })).toBe('ADMITTED');
    expect(await refusal({ port: 65535 })).toBe('ADMITTED');
  });
  it('the decision carries the bound operation id', async () => {
    const { p, result } = await admitted();
    const id = (result as unknown as { operation: { id: string } }).operation.id;
    expect(id).toBeTruthy();
    expect(p.claim({ method: 'GET', url: 'https://api.example.com/v1/items' })).toMatchObject({ allow: true, op_id: id });
  });
});

describe('EgressPolicy.claim target parsing', () => {
  it('reports the exact reason for an unusable URL', async () => {
    const { p } = await admitted();
    expect(p.claim({ method: 'GET', url: '/v1/items' })).toEqual({ allow: false, reason: 'not_absolute_url' });
    expect(p.claim({ method: 'GET', url: 'ftp://api.example.com/v1/items' })).toEqual({ allow: false, reason: 'bad_url' });
    expect(p.claim({ method: 'GET', url: 'https://u:p@api.example.com/v1/items' })).toEqual({ allow: false, reason: 'bad_url' });
    expect(p.claim({ method: 'GET', url: 'https://api.example.com/v1/items#f' })).toEqual({ allow: false, reason: 'bad_url' });
    for (const tail of ['a%2Fb', 'a%5Cb', 'a%2eb']) expect(p.claim({ method: 'GET', url: `https://api.example.com/v1/${tail}` })).toEqual({ allow: false, reason: 'encoded_path' });
  });
  it('CONNECT targets are host:port only, lower-cased, with IPv6 in brackets', async () => {
    const f = authFixture(['api']);
    const mk = async (host: string, port: number) => {
      const p = new EgressPolicy();
      p.admit(await f.allow(get), get, () => base({ host, port, tunnel: true }));
      return p;
    };
    expect((await mk('api.example.com', 443)).claim({ method: 'CONNECT', url: 'API.Example.com:443' })).toMatchObject({ allow: true });
    expect((await mk('::1', 443)).claim({ method: 'CONNECT', url: '[::1]:443' })).toMatchObject({ allow: true });
    const p = await mk('api.example.com', 443);
    for (const url of ['api.example.com', 'x api.example.com:443', 'api.example.com:443x', 'api.example.com:123456', '[zz]:443', 'api.example.com:', ':443', '']) {
      expect(p.claim({ method: 'CONNECT', url }), url).toEqual({ allow: false, reason: 'bad_connect_target' });
    }
    expect(p.claim({ method: 'CONNECT', url: '[::1]:443' })).toEqual({ allow: false, reason: 'no_admission' });
  });
  it('a tunnel template admits a CONNECT whatever its scheme field says', async () => {
    const f = authFixture(['api']);
    const p = new EgressPolicy();
    p.admit(await f.allow(get), get, () => base({ scheme: 'http', host: 'api.example.com', port: 443, tunnel: true }));
    expect(p.claim({ method: 'CONNECT', url: 'api.example.com:443' })).toMatchObject({ allow: true });
  });
  it('a scheme difference alone is enough to refuse', async () => {
    const f = authFixture(['api']);
    const p = new EgressPolicy();
    p.admit(await f.allow(get), get, () => base({ port: 8080 }));
    expect(p.claim({ method: 'GET', url: 'http://api.example.com:8080/v1/items' })).toEqual({ allow: false, reason: 'no_admission' });
    expect(p.claim({ method: 'GET', url: 'https://api.example.com:8080/v1/items' })).toMatchObject({ allow: true });
  });
  it('an IPv6 URL host is matched without brackets', async () => {
    const f = authFixture(['api']);
    const p = new EgressPolicy();
    p.admit(await f.allow(get), get, () => base({ host: '::1', port: 8443 }));
    expect(p.claim({ method: 'GET', url: 'https://[::1]:8443/v1/items' })).toMatchObject({ allow: true });
  });
});

describe('EgressPolicy.claim bodies', () => {
  it('an empty body matches an empty-body hash, and a body needs its own hash', async () => {
    const empty = new Uint8Array(0);
    const a = await admitted({ method: 'POST', body_sha256: sha256b64u(empty) });
    expect(a.p.claim({ method: 'POST', url: 'https://api.example.com/v1/items' })).toMatchObject({ allow: true });
    const b = await admitted({ method: 'POST', body_sha256: sha256b64u(new Uint8Array([1])) });
    expect(b.p.claim({ method: 'POST', url: 'https://api.example.com/v1/items' })).toEqual({ allow: false, reason: 'body_mismatch' });
    expect(b.p.claim({ method: 'POST', url: 'https://api.example.com/v1/items', body: new Uint8Array([1]) })).toMatchObject({ allow: true });
    const c = await admitted({ method: 'POST' });
    expect(c.p.claim({ method: 'POST', url: 'https://api.example.com/v1/items', body: new Uint8Array([1]) })).toEqual({ allow: false, reason: 'body_mismatch' });
  });
});

describe('isPrivateAddress', () => {
  it('v4-mapped IPv6 follows the embedded v4 address', () => {
    expect(isPrivateAddress('::ffff:10.100.100.100')).toBe(true);
    expect(isPrivateAddress('::ffff:8.8.8.8')).toBe(false);
    expect(isPrivateAddress('::FFFF:10.0.0.1')).toBe(true);
    expect(isPrivateAddress('fe80::ffff:1.2.3.4')).toBe(true);
    expect(isPrivateAddress('::ffff:8.8.8.8.5')).toBe(true);
    expect(isPrivateAddress('::ffff:10.1.100.100')).toBe(true);
    expect(isPrivateAddress('::ffff:100.100.100.100')).toBe(true);
    expect(isPrivateAddress('::ffff:8.8.100.8')).toBe(false);
    expect(isPrivateAddress('::ffff:8.8.8.100')).toBe(false);
  });
  it('each IPv4 range needs both of its conditions', () => {
    for (const ip of ['8.254.1.1', '8.20.0.1', '8.168.1.1', '8.64.1.1', '1.2.3.4', '172.15.0.1', '172.32.0.1', '100.63.0.1', '100.128.0.1', '169.253.0.1', '192.167.0.1']) expect(isPrivateAddress(ip), ip).toBe(false);
    for (const ip of ['0.1.1.1', '10.1.1.1', '127.0.0.1', '169.254.1.1', '172.16.0.1', '172.31.255.255', '192.168.0.1', '100.64.0.1', '100.127.0.1', '224.0.0.1', '255.255.255.255']) expect(isPrivateAddress(ip), ip).toBe(true);
  });
  it('IPv6 private ranges are prefixes, not substrings; a non-address is refused', () => {
    for (const ip of ['::', '::1', 'fc00::1', 'fd00::1', 'fe80::1', 'febf::1', 'ff02::1']) expect(isPrivateAddress(ip), ip).toBe(true);
    for (const ip of ['2001:fc::1', '2001:fe8::1', '2606:4700::1', '2001:db8::1']) expect(isPrivateAddress(ip), ip).toBe(false);
    expect(isPrivateAddress('example.com')).toBe(true);
    expect(isPrivateAddress('')).toBe(true);
  });
});
