import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { gnapContentDigest } from './index';
import {
  InteractionError,
  InteractionServer,
  type InteractionServerOptions,
  accessToNeeds,
  acceptFinish,
  callbackUriOk,
  interactionHash,
  newUserCode,
  validateInteractRequest,
} from './interaction';

const GRANT = 'https://as.example/gnap';
const mkServer = (over: Partial<InteractionServerOptions> = {}, clock = { t: 1000 }) => ({
  clock,
  s: new InteractionServer({
    grantEndpoint: GRANT,
    supports: ['redirect', 'app', 'user_code', 'user_code_uri'],
    redirectUri: (id) => `https://as.example/i/${id}`,
    appUri: (id) => `app://as/${id}`,
    userCodeUri: 'https://as.example/device',
    now: () => clock.t,
    ...over,
  }),
});
const FIN = { method: 'redirect', uri: 'https://c.example/cb', nonce: 'abcdefgh' };
const errOf = (f: () => unknown): InteractionError => {
  try {
    f();
  } catch (e) {
    return e as InteractionError;
  }
  throw new Error('did not throw');
};

describe('gnapContentDigest', () => {
  it('hashes Uint8Array content as its exact bytes', () => {
    const bytes = new Uint8Array([1, 2, 3, 250]);
    expect(Buffer.from(gnapContentDigest(bytes)).toString('hex')).toBe(createHash('sha256').update(Buffer.from([1, 2, 3, 250])).digest('hex'));
  });
});

describe('InteractionError', () => {
  it('carries its name, code and message', () => {
    const e = new InteractionError('expired', 'm');
    expect(e.name).toBe('InteractionError');
    expect(e.code).toBe('expired');
    expect(e.message).toBe('m');
    expect(e).toBeInstanceOf(Error);
  });
});

describe('callbackUriOk', () => {
  it('refuses non-strings', () => {
    expect(callbackUriOk(5)).toBe(false);
    expect(callbackUriOk(undefined)).toBe(false);
  });
  it('length limit is 2048 inclusive', () => {
    const base = 'https://a.example/';
    expect(callbackUriOk(base + 'a'.repeat(2048 - base.length))).toBe(true);
    expect(callbackUriOk(base + 'a'.repeat(2049 - base.length))).toBe(false);
  });
  it('refuses any fragment, including an empty one', () => {
    expect(callbackUriOk('https://a.example/#')).toBe(false);
    expect(callbackUriOk('https://a.example/#x')).toBe(false);
  });
  it('accepts https and loopback http, refuses remote http', () => {
    expect(callbackUriOk('https://a.example/cb')).toBe(true);
    expect(callbackUriOk('http://localhost/cb')).toBe(true);
    expect(callbackUriOk('http://127.0.0.1/cb')).toBe(true);
    expect(callbackUriOk('http://[::1]/cb')).toBe(true);
    expect(callbackUriOk('http://a.example/cb')).toBe(false);
  });
  it('accepts app schemes but refuses script-like schemes', () => {
    expect(callbackUriOk('myapp://cb')).toBe(true);
    for (const u of ['javascript:alert(1)', 'data:text/plain,x', 'file:///etc/passwd', 'blob:https://a.example/uuid']) expect(callbackUriOk(u)).toBe(false);
  });
});

describe('validateInteractRequest', () => {
  const ok = { start: ['redirect'] };
  it('non-objects are refused as a whole', () => {
    for (const v of ['x', 5, null, undefined, []]) expect(validateInteractRequest(v)).toEqual(['interact must be an object']);
  });
  it('start length bounds are 1..16', () => {
    expect(validateInteractRequest({ start: [] })).toEqual(['start must be a non-empty array of modes']);
    expect(validateInteractRequest({ start: Array(16).fill('redirect') })).toEqual([]);
    expect(validateInteractRequest({ start: Array(17).fill('redirect') })).toEqual(['start must be a non-empty array of modes']);
    expect(validateInteractRequest({})).toEqual(['start must be a non-empty array of modes']);
  });
  it('each start entry must be a name or an object with a string mode', () => {
    const msg = 'each start entry is a mode name or an object with a mode';
    expect(validateInteractRequest({ start: ['redirect', { mode: 'app' }, { mode: 'x', extra: 1 }] })).toEqual([]);
    for (const bad of [null, undefined, 5, {}, { mode: 5 }, { mode: null }]) expect(validateInteractRequest({ start: [bad] })).toEqual([msg]);
  });
  it('finish must be an object', () => {
    for (const f of [null, 'x', 5]) expect(validateInteractRequest({ ...ok, finish: f })).toEqual(['finish must be an object']);
  });
  it('finish.method, uri, nonce and hash_method are each checked', () => {
    expect(validateInteractRequest({ ...ok, finish: FIN })).toEqual([]);
    expect(validateInteractRequest({ ...ok, finish: { ...FIN, method: 'push', hash_method: 'sha3-512' } })).toEqual([]);
    expect(validateInteractRequest({ ...ok, finish: { ...FIN, method: 'pull' } })).toEqual(['finish.method must be redirect or push']);
    expect(validateInteractRequest({ ...ok, finish: { ...FIN, uri: 'http://a.example/' } })).toEqual(['finish.uri must be an absolute https, loopback or app-scheme URI without a fragment']);
    expect(validateInteractRequest({ ...ok, finish: { ...FIN, hash_method: 'md5' } })).toEqual(['finish.hash_method is not a supported Named Information hash']);
  });
  it('finish.nonce is 8..256 printable ASCII, anchored at both ends', () => {
    const msg = ['finish.nonce must be 8..256 printable ASCII characters'];
    const n = (nonce: unknown) => validateInteractRequest({ ...ok, finish: { ...FIN, nonce } });
    expect(n('a'.repeat(8))).toEqual([]);
    expect(n('a'.repeat(256))).toEqual([]);
    expect(n('a'.repeat(7))).toEqual(msg);
    expect(n('a'.repeat(257))).toEqual(msg);
    expect(n(12345678)).toEqual(msg);
    expect(n(' abcdefgh')).toEqual(msg);
    expect(n('abcdefgh ')).toEqual(msg);
    expect(n('abcd\nefgh')).toEqual(msg);
  });
});

describe('interactionHash', () => {
  const a = { clientNonce: 'cn', asNonce: 'an', interactRef: 'ir', grantEndpoint: GRANT };
  it('refuses an unknown hash method with the exact code and message', () => {
    const e = errOf(() => interactionHash({ ...a, hashMethod: 'md5' }));
    expect(e).toBeInstanceOf(InteractionError);
    expect(e.code).toBe('unsupported_hash');
    expect(e.message).toBe('hash_method md5 is not supported');
  });
  it('hashes the input as single-byte (ascii/latin1) characters', () => {
    const got = interactionHash({ ...a, clientNonce: 'café' });
    const want = createHash('sha256').update(Buffer.from(`café\nan\nir\n${GRANT}`, 'latin1')).digest('base64url');
    expect(got).toBe(want);
  });
});

describe('newUserCode', () => {
  it('length bounds are 6..12 inclusive and out-of-range throws RangeError', () => {
    expect(newUserCode(6)).toHaveLength(6);
    expect(newUserCode(12)).toHaveLength(12);
    expect(newUserCode()).toHaveLength(8);
    for (const n of [5, 13]) {
      expect(() => newUserCode(n)).toThrow(RangeError);
      expect(() => newUserCode(n)).toThrow('user code length 6..12');
    }
  });
});

describe('InteractionServer.start', () => {
  it('joins every problem with "; " under invalid_request', () => {
    const { s } = mkServer();
    const e = errOf(() => s.start({ start: [], finish: { ...FIN, method: 'pull' } }));
    expect(e.code).toBe('invalid_request');
    expect(e.message).toBe('start must be a non-empty array of modes; finish.method must be redirect or push');
  });
  it('a valid request does not throw', () => {
    const { s } = mkServer();
    expect(() => s.start({ start: ['redirect'] })).not.toThrow();
  });
  it('no supported mode and no finish is invalid_interaction', () => {
    const { s } = mkServer({ supports: ['redirect'] });
    const e = errOf(() => s.start({ start: ['app'] }));
    expect(e.code).toBe('invalid_interaction');
    expect(e.message).toBe('no requested interaction mode is supported');
  });
  it('user_code_uri without a configured uri, and app without an appUri, are not offered', () => {
    const a = mkServer({ userCodeUri: undefined });
    expect(errOf(() => a.s.start({ start: ['user_code_uri'] })).code).toBe('invalid_interaction');
    const b = mkServer({ appUri: undefined });
    expect(errOf(() => b.s.start({ start: ['app'] })).code).toBe('invalid_interaction');
    const c = mkServer({ userCodeUri: undefined });
    expect(c.s.start({ start: ['user_code_uri', 'redirect'] }).interaction.modes).toEqual(['redirect']);
  });
  it('a finish-only request without any supported mode is accepted', () => {
    const { s } = mkServer({ supports: ['redirect'] });
    const r = s.start({ start: ['app'], finish: FIN });
    expect(r.interaction.modes).toEqual([]);
    expect(r.response.finish).toBe(r.interaction.finish?.asNonce);
  });
  it('ttl defaults to 600 and a configured ttl wins', () => {
    const d = mkServer().s.start({ start: ['redirect'] });
    expect(d.response.expires_in).toBe(600);
    expect(d.interaction.expiresAt).toBe(1600);
    const t = mkServer({ ttlSec: 30 }).s.start({ start: ['redirect'] });
    expect(t.response.expires_in).toBe(30);
    expect(t.interaction.expiresAt).toBe(1030);
  });
  it('a redirect-only interaction has no user code', () => {
    const r = mkServer().s.start({ start: ['redirect'] });
    expect(r.interaction.userCode).toBeUndefined();
    expect(r.response.user_code).toBeUndefined();
    expect(r.response.user_code_uri).toBeUndefined();
  });
  it('user_code and user_code_uri each get their own response field', () => {
    const { s } = mkServer();
    const a = s.start({ start: ['user_code'] });
    expect(a.response.user_code).toBe(a.interaction.userCode);
    expect(a.response.user_code_uri).toBeUndefined();
    const b = s.start({ start: ['user_code_uri'] });
    expect(b.response.user_code_uri).toEqual({ code: b.interaction.userCode, uri: 'https://as.example/device' });
    expect(b.response.user_code).toBeUndefined();
  });
});

describe('InteractionServer lookup, approve, consume, finalize', () => {
  it('lookupUserCode finds a pending interaction case-insensitively and ignores separators', () => {
    const { s } = mkServer();
    const { interaction } = s.start({ start: ['user_code'] });
    const code = interaction.userCode!;
    expect(s.lookupUserCode(code.toLowerCase())).toBe(interaction);
    expect(s.lookupUserCode(` ${code.slice(0, 4)}-${code.slice(4)} `)).toBe(interaction);
    expect(s.lookupUserCode('ZZZZZZZZ')).toBeUndefined();
  });
  it('lookupUserCode refuses a finalized interaction', () => {
    const { s } = mkServer();
    const { interaction } = s.start({ start: ['user_code'] });
    s.finalize(interaction.id);
    expect(s.lookupUserCode(interaction.userCode!)).toBeUndefined();
  });
  it('lookupUserCode: valid at the expiry instant, gone one tick later', () => {
    const { s, clock } = mkServer({ ttlSec: 10 });
    const { interaction } = s.start({ start: ['user_code'] });
    clock.t = 1010;
    expect(s.lookupUserCode(interaction.userCode!)).toBe(interaction);
    clock.t = 1011;
    expect(s.lookupUserCode(interaction.userCode!)).toBeUndefined();
  });
  it('approving removes the user code from the lookup table', () => {
    const { s } = mkServer();
    const { interaction } = s.start({ start: ['user_code'] });
    s.approve(interaction.id);
    interaction.state = 'pending'; // a state reset must still not resurrect the spent code
    expect(s.lookupUserCode(interaction.userCode!)).toBeUndefined();
  });
  it('approve without a finish returns just the interact_ref', () => {
    const { s } = mkServer();
    const { interaction } = s.start({ start: ['redirect'] });
    const out = s.approve(interaction.id);
    expect(out).toEqual({ interactRef: interaction.interactRef });
    expect(typeof out.interactRef).toBe('string');
    expect(interaction.state).toBe('approved');
  });
  it('approve twice is wrong_state with the state in the message', () => {
    const { s } = mkServer();
    const { interaction } = s.start({ start: ['redirect'] });
    s.approve(interaction.id);
    const e = errOf(() => s.approve(interaction.id));
    expect(e.code).toBe('wrong_state');
    expect(e.message).toBe('interaction is approved');
  });
  it('approve of an unknown id is unknown_interaction', () => {
    const e = errOf(() => mkServer().s.approve('nope'));
    expect(e.code).toBe('unknown_interaction');
    expect(e.message).toBe('no such interaction');
  });
  it('approve: valid at the expiry instant, expired one tick later', () => {
    const a = mkServer({ ttlSec: 10 });
    const ia = a.s.start({ start: ['redirect'] }).interaction;
    a.clock.t = 1010;
    expect(() => a.s.approve(ia.id)).not.toThrow();
    const b = mkServer({ ttlSec: 10 });
    const ib = b.s.start({ start: ['redirect'] }).interaction;
    b.clock.t = 1011;
    const e = errOf(() => b.s.approve(ib.id));
    expect(e.code).toBe('expired');
    expect(e.message).toBe('the interaction expired');
  });
  it('consume: unknown, replay, finalized, expired, wrong_state with exact codes and messages', () => {
    const u = errOf(() => mkServer().s.consume('nope'));
    expect([u.code, u.message]).toEqual(['unknown_interaction', 'no such interaction reference']);

    const a = mkServer({ ttlSec: 10 });
    const ia = a.s.start({ start: ['redirect'] }).interaction;
    const ref = a.s.approve(ia.id).interactRef;
    expect(a.s.consume(ref)).toBe(ia);
    expect(ia.refUsed).toBe(true);
    const r = errOf(() => a.s.consume(ref));
    expect([r.code, r.message]).toEqual(['too_many_attempts', 'the interaction reference was already used']);
    expect(ia.state).toBe('finalized');

    const b = mkServer({ ttlSec: 10 });
    const ib = b.s.start({ start: ['redirect'] }).interaction;
    const refB = b.s.approve(ib.id).interactRef;
    b.s.finalize(ib.id);
    expect(ib.state).toBe('finalized');
    const f = errOf(() => b.s.consume(refB));
    expect([f.code, f.message]).toEqual(['too_many_attempts', 'the interaction reference was already used']);

    const c = mkServer({ ttlSec: 10 });
    const ic = c.s.start({ start: ['redirect'] }).interaction;
    const refC = c.s.approve(ic.id).interactRef;
    c.clock.t = 1010;
    expect(c.s.consume(refC)).toBe(ic);
    const d = mkServer({ ttlSec: 10 });
    const id = d.s.start({ start: ['redirect'] }).interaction;
    const refD = d.s.approve(id.id).interactRef;
    d.clock.t = 1011;
    const x = errOf(() => d.s.consume(refD));
    expect([x.code, x.message]).toEqual(['expired', 'the interaction expired']);

    const e = mkServer();
    const ie = e.s.start({ start: ['redirect'] }).interaction;
    const refE = e.s.approve(ie.id).interactRef;
    ie.state = 'pending';
    const w = errOf(() => e.s.consume(refE));
    expect([w.code, w.message]).toEqual(['wrong_state', 'interaction is pending']);
    expect(ie.refUsed).toBe(false);
  });
  it('finalize ignores unknown ids and marks known ones finalized', () => {
    const { s } = mkServer();
    expect(() => s.finalize('nope')).not.toThrow();
    const { interaction } = s.start({ start: ['redirect'] });
    s.finalize(interaction.id);
    expect(s.get(interaction.id)?.state).toBe('finalized');
  });
});

describe('acceptFinish', () => {
  const ctx = { clientNonce: 'cn-cn-cn', asNonce: 'as-as-as', grantEndpoint: GRANT };
  const hashFor = (ref: string) => interactionHash({ ...ctx, interactRef: ref });
  it('returns the interact_ref when the hash validates', () => {
    expect(acceptFinish({ hash: hashFor('r1'), interact_ref: 'r1' }, ctx)).toBe('r1');
  });
  it('missing or malformed fields: unknown_interaction, hash and interact_ref are required', () => {
    const cases: Array<{ hash?: unknown; interact_ref?: unknown }> = [
      { hash: hashFor('r1') },
      { hash: hashFor('r1'), interact_ref: 5 },
      { hash: hashFor('r1'), interact_ref: '' },
      { hash: hashFor(''), interact_ref: '' },
      { interact_ref: 'r1' },
      { hash: 5, interact_ref: 'r1' },
    ];
    for (const c of cases) {
      const e = errOf(() => acceptFinish(c, ctx));
      expect([e.code, e.message]).toEqual(['unknown_interaction', 'hash and interact_ref are required']);
    }
  });
  it('a non-validating hash is unknown_interaction with its own message', () => {
    const e = errOf(() => acceptFinish({ hash: hashFor('r2'), interact_ref: 'r1' }, ctx));
    expect([e.code, e.message]).toEqual(['unknown_interaction', 'the callback hash does not validate']);
  });
});

describe('accessToNeeds', () => {
  it('expands one need per action and location', () => {
    expect(accessToNeeds([{ type: 't', actions: ['read', 'write'], locations: ['a', 'b'] }])).toEqual([
      { verb: 'read', resource: 'gnap:t:a' },
      { verb: 'read', resource: 'gnap:t:b' },
      { verb: 'write', resource: 'gnap:t:a' },
      { verb: 'write', resource: 'gnap:t:b' },
    ]);
  });
  it('refuses a wildcard right with invalid_request and the type in the message', () => {
    for (const a of [{ type: 'photo' }, { type: 'photo', actions: [], locations: ['x'] }, { type: 'photo', actions: ['read'] }, { type: 'photo', actions: ['read'], locations: [] }]) {
      const e = errOf(() => accessToNeeds([a]));
      expect(e.code).toBe('invalid_request');
      expect(e.message).toBe('access "photo" needs explicit actions and locations to become a need');
    }
  });
});
