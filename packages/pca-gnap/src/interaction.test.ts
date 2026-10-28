import { describe, expect, it } from 'vitest';
import {
  InteractionError, InteractionServer, acceptFinish, callbackUriOk, interactionHash, newUserCode, validateInteractRequest, verifyInteractionHash, type InteractRequestFull,
} from './interaction';

const GRANT = 'https://as.example/tx';
let now = 1000;
const mk = () => new InteractionServer({
  grantEndpoint: GRANT, supports: ['redirect', 'user_code', 'user_code_uri', 'app'], redirectUri: (id) => `https://as.example/i/${id}`, appUri: (id) => `app://as/launch?tx=${id}`,
  userCodeUri: 'https://as.example/device', ttlSec: 600, now: () => now,
});
const finish = (method: string = 'redirect') => ({ method, uri: 'https://client.example/return/1', nonce: 'LKLTI25DK82FX4T4QFZC' });

describe('interaction hash (RFC 9635 4.2.3)', () => {
  it('matches the RFC example for sha-256 and sha3-512', () => {
    const a = { clientNonce: 'VJLO6A4CATR0KRO', asNonce: 'MBDOFXG4Y5CVJCX821LH', interactRef: '4IFWWIKYB2PQ6U56NL1', grantEndpoint: 'https://server.example.com/tx' };
    expect(interactionHash(a)).toBe('x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY');
    expect(interactionHash({ ...a, hashMethod: 'sha3-512' })).toBe('pyUkVJSmpqSJMaDYsk5G8WCvgY91l-agUPe1wgn-cc5rUtN69gPI2-S_s-Eswed8iB4PJ_a5Hg6DNi7qGgKwSQ');
    expect(verifyInteractionHash('x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY', a)).toBe(true);
    expect(verifyInteractionHash('x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffZ', a)).toBe(false);
    expect(verifyInteractionHash(undefined, a)).toBe(false);
    expect(() => interactionHash({ ...a, hashMethod: 'md5' })).toThrow(InteractionError);
  });
});

describe('request validation', () => {
  it('accepts the four start modes and both finish methods; names each problem', () => {
    expect(validateInteractRequest({ start: ['redirect', 'app', 'user_code', 'user_code_uri', { mode: 'x-custom' }], finish: finish('push') })).toEqual([]);
    expect(validateInteractRequest({ start: [] })).toEqual(['start must be a non-empty array of modes']);
    expect(validateInteractRequest({ start: [1] })).toEqual(['each start entry is a mode name or an object with a mode']);
    expect(validateInteractRequest({ start: ['redirect'], finish: { ...finish(), method: 'poll' } })).toEqual(['finish.method must be redirect or push']);
    expect(validateInteractRequest({ start: ['redirect'], finish: { ...finish(), uri: 'https://c.example/r#frag' } })).toEqual(['finish.uri must be an absolute https, loopback or app-scheme URI without a fragment']);
    expect(validateInteractRequest({ start: ['redirect'], finish: { ...finish(), nonce: 'short' } })).toEqual(['finish.nonce must be 8..256 printable ASCII characters']);
    expect(validateInteractRequest({ start: ['redirect'], finish: { ...finish(), hash_method: 'md5' } })).toEqual(['finish.hash_method is not a supported Named Information hash']);
    expect(validateInteractRequest(null)).toEqual(['interact must be an object']);
  });
  it('callback URIs: https, loopback http and app schemes only', () => {
    for (const ok of ['https://a.example/r', 'http://localhost:8080/cb', 'http://127.0.0.1/cb', 'com.example.app:/cb']) expect(callbackUriOk(ok)).toBe(true);
    for (const bad of ['http://evil.example/r', 'javascript:alert(1)', 'data:text/html,x', 'file:///etc/passwd', 'relative/path', 'https://a.example/r#x', 42]) expect(callbackUriOk(bad)).toBe(false);
  });
});

describe('InteractionServer', () => {
  it('responds only with modes both requested and supported, with unique non-sensitive URIs and a finish nonce', () => {
    now = 1000;
    const s = mk();
    const { response, interaction } = s.start({ start: ['redirect', 'user_code', 'unknown_mode'], finish: finish() });
    expect(Object.keys(response).sort()).toEqual(['expires_in', 'finish', 'redirect', 'user_code']);
    expect(response.redirect).toBe(`https://as.example/i/${interaction.id}`);
    expect(response.user_code).toMatch(/^[A-HJ-NP-Z2-9]{8}$/);
    expect(response.finish).toBe(interaction.finish!.asNonce);
    const both = s.start({ start: ['user_code_uri', 'app'] }).response;
    expect(Object.keys(both).sort()).toEqual(['app', 'expires_in', 'user_code_uri']);
    expect(both.user_code_uri).toMatchObject({ uri: 'https://as.example/device' });
    expect(() => s.start({ start: ['unknown_mode'] })).toThrow(InteractionError);
    const noApp = new InteractionServer({ grantEndpoint: GRANT, supports: ['redirect', 'app'], redirectUri: (i) => `https://as/${i}`, now: () => now });
    expect(Object.keys(noApp.start({ start: ['app', 'redirect'] }).response).sort()).toEqual(['expires_in', 'redirect']);
  });

  it('REDIRECT finish end to end: user code lookup is case-insensitive, the callback hash validates at the client, the ref is single use', () => {
    now = 1000;
    const s = mk();
    const req: InteractRequestFull = { start: ['user_code'], finish: finish('redirect') };
    const { interaction, response } = s.start(req);
    expect(s.lookupUserCode(` ${response.user_code!.toLowerCase().slice(0, 4)}-${response.user_code!.slice(4)} `)?.id).toBe(interaction.id);
    expect(s.lookupUserCode('AAAAAAAA')).toBeUndefined();
    const ap = s.approve(interaction.id);
    expect(ap.finish!.method).toBe('redirect');
    const url = new URL((ap.finish as { url: string }).url);
    expect(url.origin + url.pathname).toBe('https://client.example/return/1');
    const ref = acceptFinish({ hash: url.searchParams.get('hash'), interact_ref: url.searchParams.get('interact_ref') }, { clientNonce: req.finish!.nonce, asNonce: response.finish!, grantEndpoint: GRANT });
    expect(ref).toBe(ap.interactRef);
    expect(s.lookupUserCode(response.user_code!)).toBeUndefined(); // code is spent on approval
    expect(s.consume(ref).id).toBe(interaction.id);
    expect(() => s.consume(ref)).toThrowError(expect.objectContaining({ code: 'too_many_attempts' }));
    expect(s.get(interaction.id)!.state).toBe('finalized');
  });

  it('PUSH finish carries {hash, interact_ref}; a forged hash or foreign nonce does not validate and the ref must not be sent', () => {
    now = 1000;
    const s = mk();
    const req: InteractRequestFull = { start: ['redirect'], finish: { ...finish('push'), hash_method: 'sha3-512' } };
    const { interaction, response } = s.start(req);
    const ap = s.approve(interaction.id);
    const pushed = ap.finish;
    if (pushed?.method !== 'push') throw new Error('expected push');
    expect(pushed.uri).toBe('https://client.example/return/1');
    const ctx = { clientNonce: req.finish!.nonce, asNonce: response.finish!, grantEndpoint: GRANT, hashMethod: 'sha3-512' };
    expect(acceptFinish(pushed.body, ctx)).toBe(ap.interactRef);
    expect(() => acceptFinish({ ...pushed.body, hash: 'forged' }, ctx)).toThrowError(expect.objectContaining({ code: 'unknown_interaction' }));
    expect(() => acceptFinish(pushed.body, { ...ctx, clientNonce: 'ANOTHER-REQUEST-NONCE' })).toThrow(InteractionError);
    expect(() => acceptFinish(pushed.body, { ...ctx, hashMethod: 'sha-256' })).toThrow(InteractionError);
    expect(() => acceptFinish({ interact_ref: 'x' }, ctx)).toThrow(InteractionError);
  });

  it('state and expiry: no approval twice, no continuation before approval, nothing after expiry, unknown refs', () => {
    now = 1000;
    const s = mk();
    const a = s.start({ start: ['redirect'] }).interaction;
    expect(() => s.consume('nope')).toThrowError(expect.objectContaining({ code: 'unknown_interaction' }));
    s.approve(a.id);
    expect(() => s.approve(a.id)).toThrowError(expect.objectContaining({ code: 'wrong_state' }));
    const b = s.start({ start: ['redirect'] }).interaction;
    now = 1000 + 601;
    expect(() => s.approve(b.id)).toThrowError(expect.objectContaining({ code: 'expired' }));
    expect(() => s.consume(s.get(a.id)!.interactRef!)).toThrowError(expect.objectContaining({ code: 'expired' }));
    expect(() => s.approve('missing')).toThrowError(expect.objectContaining({ code: 'unknown_interaction' }));
    now = 1000;
  });

  it('user codes: length bounds, alphabet without look-alikes, enough spread', () => {
    expect(() => newUserCode(5)).toThrow(RangeError);
    const seen = new Set(Array.from({ length: 200 }, () => newUserCode(8)));
    expect(seen.size).toBeGreaterThan(195);
    for (const c of seen) expect(c).not.toMatch(/[01OI]/);
  });
});

import { accessToNeeds } from './interaction';
describe('accessToNeeds', () => {
  it('expands actions x locations into namespaced needs and refuses wildcards', () => {
    expect(accessToNeeds([{ type: 'photo-api', actions: ['read', 'write'], locations: ['https://x/a', 'https://x/b'] }])).toEqual([
      { verb: 'read', resource: 'gnap:photo-api:https://x/a' }, { verb: 'read', resource: 'gnap:photo-api:https://x/b' },
      { verb: 'write', resource: 'gnap:photo-api:https://x/a' }, { verb: 'write', resource: 'gnap:photo-api:https://x/b' },
    ]);
    expect(() => accessToNeeds([{ type: 't', actions: ['read'] }])).toThrow(InteractionError);
    expect(() => accessToNeeds([{ type: 't', locations: ['l'] }])).toThrow(InteractionError);
  });
});
