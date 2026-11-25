import { beforeAll, describe, expect, it } from 'vitest';
import { SignJWT, generateKeyPair, type JWTPayload, type KeyLike } from 'jose';
import { b64u, generateKeyPair as generatePcaKeyPair, mlDsa65Keygen } from '@atlasauth/pca';
import {
  IDJAG_AUTHORITY_CAVEAT,
  IDJAG_PROVENANCE_CAVEAT,
  IdJagVerificationError,
  idJagToCapability,
  idJagToPcaPrincipal,
  isIdJagAuthorityCaveat,
  isIdJagProvenanceCaveat,
  jwtBearerAssertion,
  readIdJagAuthority,
  readIdJagProvenance,
  tokenExchangeRequest,
  verifyIdJag,
  type IdJagGrant,
  type VerifyIdJagOptions,
} from './index';

const ISS = 'https://idp.example.com';
const AUD = 'https://resource.example.com';
const TYP = 'oauth-id-jag+jwt';
let priv: KeyLike;
let pub: KeyLike;
beforeAll(async () => {
  const kp = await generateKeyPair('EdDSA', { extractable: true });
  priv = kp.privateKey;
  pub = kp.publicKey;
});
const mint = (over: Record<string, unknown> = {}, typ: string | null = TYP) => {
  const now = Math.floor(Date.now() / 1000);
  const claims: JWTPayload = { iss: ISS, sub: 'u', aud: AUD, iat: now, exp: now + 300, jti: 'j1', client_id: 'rc', act: { sub: 'ag' }, scope: 'a b', ...over };
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA', ...(typ !== null ? { typ } : {}) })
    .sign(priv);
};
const loose = (o: Partial<VerifyIdJagOptions> = {}): VerifyIdJagOptions => ({ issuer: ISS, audience: AUD, key: pub, strictDraft: false, ...o });
const fail = (p: Promise<unknown>): Promise<IdJagVerificationError> =>
  p.then(
    () => {
      throw new Error('expected a failure');
    },
    (e: unknown) => e as IdJagVerificationError,
  );
const msg = (e: unknown) => (e as Error).message;

describe('verifyIdJag argument validation', () => {
  it('has a named error class', () => {
    expect(new IdJagVerificationError('scope', 'm').name).toBe('IdJagVerificationError');
  });
  it('rejects a bad jwt, options, issuer or audience with the exact code and message', async () => {
    const cases: Array<[unknown, unknown, string, string]> = [
      ['', loose(), 'invalid_token', 'verifyIdJag: jwt must be a non-empty string'],
      [5, loose(), 'invalid_token', 'verifyIdJag: jwt must be a non-empty string'],
      ['x', null, 'config', 'verifyIdJag: opts is required'],
      ['x', 5, 'config', 'verifyIdJag: opts is required'],
      ['x', loose({ issuer: '' }), 'config', 'verifyIdJag: opts.issuer is required'],
      ['x', loose({ issuer: 5 as never }), 'config', 'verifyIdJag: opts.issuer is required'],
      ['x', loose({ audience: 5 as never }), 'config', 'verifyIdJag: opts.audience is required (ID-JAG is single-audience)'],
      ['x', loose({ audience: '' }), 'config', 'verifyIdJag: opts.audience is required (ID-JAG is single-audience)'],
    ];
    for (const [jwt, opts, code, message] of cases) {
      const e = await fail(verifyIdJag(jwt as string, opts as VerifyIdJagOptions));
      expect(e).toBeInstanceOf(IdJagVerificationError);
      expect([e.code, e.message]).toEqual([code, message]);
    }
  });
});

describe('verifyIdJag forwards its options to the OIDC verifier', () => {
  it('nonce round-trips and a mismatch is refused', async () => {
    const jwt = await mint({ nonce: 'n1' });
    expect((await verifyIdJag(jwt, loose({ nonce: 'n1' }))).nonce).toBe('n1');
    expect((await fail(verifyIdJag(jwt, loose({ nonce: 'other' })))).code).toBe('nonce');
    const grant = await verifyIdJag(await mint(), loose());
    expect('nonce' in grant).toBe(false);
  });
  it('clock tolerance, token age and the algorithm list are honoured', async () => {
    const now = Math.floor(Date.now() / 1000);
    const expired = await mint({ iat: now - 400, exp: now - 10 });
    await expect(fail(verifyIdJag(expired, loose()))).resolves.toBeInstanceOf(IdJagVerificationError);
    await expect(verifyIdJag(expired, loose({ clockToleranceSec: 60 }))).resolves.toBeDefined();
    const old = await mint({ iat: now - 1000, exp: now + 300 });
    await expect(verifyIdJag(old, loose())).resolves.toBeDefined();
    await expect(fail(verifyIdJag(old, loose({ maxTokenAgeSec: 10 })))).resolves.toBeInstanceOf(IdJagVerificationError);
    await expect(fail(verifyIdJag(await mint(), loose({ algorithms: ['RS256'] })))).resolves.toBeInstanceOf(IdJagVerificationError);
  });
  it('jwksUri, discovery and the injected fetch reach the verifier', async () => {
    const jwt = await mint();
    const noKey = { issuer: ISS, audience: AUD, strictDraft: false };
    expect(msg(await fail(verifyIdJag(jwt, noKey)))).toContain('no key source');
    const viaUri = await fail(verifyIdJag(jwt, { ...noKey, jwksUri: 'http://insecure.example/jwks' }));
    expect(msg(viaUri)).not.toContain('no key source');
    let calls = 0;
    const fetchMock = (async () => {
      calls += 1;
      return new Response('{}', { status: 200 });
    }) as unknown as typeof fetch;
    await fail(verifyIdJag(jwt, { ...noKey, discover: true, fetch: fetchMock }));
    expect(calls).toBe(1);
  });
  it('a non-OIDC failure inside the verifier is wrapped with its cause', async () => {
    const e = await fail(verifyIdJag(await mint(), loose({ algorithms: 5 as never })));
    expect([e.code, e.message]).toEqual(['invalid_token', 'ID-JAG verification failed']);
    expect(e.cause).toBeInstanceOf(TypeError);
  });
  it('an OIDC failure keeps its code and cause', async () => {
    const e = await fail(verifyIdJag(await mint({ iss: 'https://evil.example' }), loose()));
    expect(e.code).not.toBe('invalid_token');
    expect(e.cause).toBeDefined();
  });
});

describe('verifyIdJag claim handling', () => {
  it('refuses a missing or malformed actor, with the typed message', async () => {
    const message = 'ID-JAG is missing a well-formed "act" (agent) claim with a string "sub"';
    for (const act of [null, 'x', [], { sub: '' }, { sub: 5 }, undefined]) {
      const e = await fail(verifyIdJag(await mint({ act }), loose()));
      expect([e.code, e.message]).toEqual(['actor', message]);
    }
  });
  it('refuses a missing scope claim and a missing required scope with exact messages', async () => {
    const e = await fail(verifyIdJag(await mint({ scope: undefined }), loose()));
    expect([e.code, e.message]).toEqual(['scope', 'ID-JAG is missing the "scope" (or "scopes") claim']);
    const r = await fail(verifyIdJag(await mint(), loose({ requiredScopes: ['zz'] })));
    expect([r.code, r.message]).toEqual(['scope', 'ID-JAG does not grant the required scope "zz"']);
  });
  it('parses scope strings, arrays and the scopes claim, dropping empties and non-strings', async () => {
    const scopes = async (over: Record<string, unknown>) => (await verifyIdJag(await mint(over), loose())).scopes;
    expect(await scopes({ scope: ' a  b ' })).toEqual(['a', 'b']);
    expect(await scopes({ scope: ['a', '', 7, 'b'] })).toEqual(['a', 'b']);
    expect(await scopes({ scope: undefined, scopes: ['x', '', 3, 'y'] })).toEqual(['x', 'y']);
    expect(await scopes({ scope: ['k'], scopes: ['other'] })).toEqual(['k']);
  });
  it('keeps only a non-empty string jti and a present cnf, and omits absent members', async () => {
    const g = await verifyIdJag(await mint({ jti: 5 }), loose());
    expect('jti' in g).toBe(false);
    expect('jti' in (await verifyIdJag(await mint({ jti: '' }), loose()))).toBe(false);
    expect('nonce' in g).toBe(false);
    expect('cnf' in g).toBe(false);
    const cnf = { jwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(new Uint8Array(32).fill(1)) } };
    expect((await verifyIdJag(await mint({ cnf }), loose())).cnf).toEqual(cnf);
  });
  it('an empty client_id is reported as missing', async () => {
    const strict = { issuer: ISS, audience: AUD, key: pub, clientId: 'rc', consumeJti: () => true };
    const e = await fail(verifyIdJag(await mint({ client_id: '' }), strict));
    expect([e.code, e.message]).toEqual(['grant', 'ID-JAG is missing "client_id"']);
  });
  it('a throwing single-use store refuses the grant', async () => {
    const strict = {
      issuer: ISS,
      audience: AUD,
      key: pub,
      clientId: 'rc',
      consumeJti: () => {
        throw new Error('store down');
      },
    };
    const e = await fail(verifyIdJag(await mint(), strict));
    expect([e.code, e.message]).toEqual(['grant', 'ID-JAG jti was already used or the single-use store failed']);
  });
});

describe('grant projection', () => {
  const human = generatePcaKeyPair();
  const holder = b64u(generatePcaKeyPair().publicKey);
  const principalPublic = b64u(human.publicKey);
  const grantOf = async (over: Record<string, unknown> = {}) => verifyIdJag(await mint(over), loose());
  const without = (g: IdJagGrant, key: 'jti'): IdJagGrant => {
    const { [key]: _drop, ...rest } = g;
    return rest as IdJagGrant;
  };

  it('refuses a missing grant or options with the typed message', async () => {
    const g = await grantOf();
    const ok = { principalSecret: human.secretKey, principalPublic, holder };
    for (const bad of [null, 5]) {
      expect(() => idJagToPcaPrincipal(bad as never)).toThrow(new TypeError('idJagToPcaPrincipal: grant is required'));
      expect(() => idJagToCapability(bad as never, ok)).toThrow(new TypeError('idJagToCapability: grant is required'));
      expect(() => idJagToCapability(g, bad as never)).toThrow(new TypeError('idJagToCapability: opts is required'));
    }
    expect(() => idJagToCapability(g, { ...ok, principalSecret: 'x' as never })).toThrow(new TypeError('idJagToCapability: opts.principalSecret must be a Uint8Array'));
    for (const principalPublicBad of ['', 5]) {
      expect(() => idJagToCapability(g, { ...ok, principalPublic: principalPublicBad as never })).toThrow(new TypeError('idJagToCapability: opts.principalPublic is required'));
    }
    for (const holderBad of [5, undefined]) {
      expect(() => idJagToCapability(g, { ...ok, holder: holderBad as never })).toThrow(new TypeError('idJagToCapability: opts.holder (the agent key) is required'));
    }
  });
  it('an empty holder is not refused by the shape check', async () => {
    const g = await grantOf();
    expect(() => idJagToCapability(g, { principalSecret: human.secretKey, principalPublic, holder: '' })).toThrow(new TypeError('idJagToCapability: opts.holder (the agent key) is required'));
  });
  it('the provenance caveat carries a jti only when the grant has one', async () => {
    const g = await grantOf();
    const withJti = readIdJagProvenance(idJagToCapability(g, { principalSecret: human.secretKey, principalPublic, holder }).capability);
    expect(withJti).toMatchObject({ jti: 'j1' });
    const bare = readIdJagProvenance(idJagToCapability(without(g, 'jti'), { principalSecret: human.secretKey, principalPublic, holder }).capability);
    expect(bare && 'jti' in bare).toBe(false);
  });
  it('a chosen signature suite is used for the root capability', async () => {
    const g = await grantOf();
    const mlDsa = mlDsa65Keygen(new Uint8Array(32).fill(7));
    const { capability } = idJagToCapability(g, { principalSecret: human.secretKey, principalPublic, holder, suite: { alg: 'ml-dsa-65', mlDsa } });
    expect(capability.alg).toBe('ml-dsa-65');
  });
});

describe('caveat guards and readers', () => {
  const auth = { type: IDJAG_AUTHORITY_CAVEAT, scopes: ['a'], aud: 'x' };
  const prov = { type: IDJAG_PROVENANCE_CAVEAT, iss: 'i', sub: 's', agent: 'a', aud: 'x', iat: 1, exp: 2 };
  const fnWith = (o: object) => Object.assign(() => 0, o);

  it('isIdJagAuthorityCaveat checks each member on its own', () => {
    expect(isIdJagAuthorityCaveat(auth)).toBe(true);
    for (const bad of [null, 5, 'x', fnWith(auth), { ...auth, type: 'other' }, { ...auth, scopes: 'a' }, { ...auth, scopes: ['a', 1] }, { ...auth, aud: 5 }, { ...auth, aud: '' }]) {
      expect(isIdJagAuthorityCaveat(bad)).toBe(false);
    }
    expect(isIdJagAuthorityCaveat({ ...auth, scopes: [] })).toBe(true);
  });
  it('isIdJagProvenanceCaveat checks each member on its own', () => {
    expect(isIdJagProvenanceCaveat(prov)).toBe(true);
    const bads: unknown[] = [null, 5, fnWith(prov), { ...prov, type: 'x' }];
    for (const k of ['iss', 'sub', 'agent', 'aud'] as const) bads.push({ ...prov, [k]: 5 });
    for (const k of ['iat', 'exp'] as const) bads.push({ ...prov, [k]: '1' });
    for (const bad of bads) expect(isIdJagProvenanceCaveat(bad)).toBe(false);
  });
  it('the readers tolerate odd capabilities and pick the right caveat', () => {
    for (const cap of [undefined, null, {}, { caveats: [] }, { caveats: [null, { type: 'other' }] }]) {
      expect(readIdJagAuthority(cap as never)).toBeNull();
      expect(readIdJagProvenance(cap as never)).toBeNull();
    }
    expect(readIdJagAuthority({ caveats: [{ type: 'other' }, auth] } as never)).toEqual(auth);
    expect(readIdJagProvenance({ caveats: [{ type: 'other' }, prov] } as never)).toEqual(prov);
    expect(readIdJagAuthority({ caveats: [{ ...auth, aud: '' }] } as never)).toBeNull();
    expect(readIdJagProvenance({ caveats: [{ ...prov, iat: 'x' }] } as never)).toBeNull();
  });
});

describe('request builders', () => {
  const base = { tokenEndpoint: 'https://idp.example/token', subjectToken: 'st' };
  it('tokenExchangeRequest refuses bad options with exact messages', () => {
    for (const bad of [null, 5]) expect(() => tokenExchangeRequest(bad as never)).toThrow(new TypeError('tokenExchangeRequest: opts is required'));
    for (const t of ['', 5]) expect(() => tokenExchangeRequest({ ...base, tokenEndpoint: t as never })).toThrow(new TypeError('tokenExchangeRequest: opts.tokenEndpoint is required'));
    for (const t of ['', 5]) expect(() => tokenExchangeRequest({ ...base, subjectToken: t as never })).toThrow(new TypeError('tokenExchangeRequest: opts.subjectToken is required'));
  });
  it('tokenExchangeRequest sends the json accept header and drops empty fields', () => {
    const r = tokenExchangeRequest({ ...base, extra: { keep: 'v', empty: '', gone: undefined as never } });
    expect(r.headers).toEqual({ 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' });
    expect(r.params.keep).toBe('v');
    expect('empty' in r.params).toBe(false);
    expect('gone' in r.params).toBe(false);
    expect(r.body).toBe(new URLSearchParams(r.params).toString());
  });
  it('optional members appear only when given', () => {
    const bare = tokenExchangeRequest(base);
    for (const k of ['audience', 'resource', 'scope', 'actor_token', 'actor_token_type', 'client_id']) expect(k in bare.params).toBe(false);
    const full = tokenExchangeRequest({ ...base, audience: 'a', resource: 'https://r', scope: ' x  y ', actorToken: 'at', clientId: 'c' });
    expect(full.params).toMatchObject({ audience: 'a', resource: 'https://r', scope: 'x y', actor_token: 'at', actor_token_type: 'urn:ietf:params:oauth:token-type:jwt', client_id: 'c' });
  });
  it('an empty actor token adds no actor type, and an empty scope adds no scope', () => {
    const r = tokenExchangeRequest({ ...base, actorToken: '', scope: '' });
    expect('actor_token_type' in r.params).toBe(false);
    expect('scope' in r.params).toBe(false);
    expect('scope' in tokenExchangeRequest({ ...base, scope: [] }).params).toBe(false);
  });
  it('extra fields are merged', () => {
    expect(tokenExchangeRequest({ ...base, extra: { z: '1' } }).params.z).toBe('1');
    expect(jwtBearerAssertion({ tokenEndpoint: 'https://t', assertion: 'a', extra: { z: '1' } }).request.params.z).toBe('1');
  });
  it('jwtBearerAssertion refuses bad options with exact messages', () => {
    for (const bad of [null, 5]) expect(() => jwtBearerAssertion(bad as never)).toThrow(new TypeError('jwtBearerAssertion: opts is required'));
    for (const t of ['', 5]) expect(() => jwtBearerAssertion({ tokenEndpoint: t as never, assertion: 'a' })).toThrow(new TypeError('jwtBearerAssertion: opts.tokenEndpoint is required'));
    for (const t of ['', 5]) expect(() => jwtBearerAssertion({ tokenEndpoint: 'https://t', assertion: t as never })).toThrow(new TypeError('jwtBearerAssertion: opts.assertion is required'));
  });
  it('jwtBearerAssertion carries scope, client and client assertion only when given', () => {
    const bare = jwtBearerAssertion({ tokenEndpoint: 'https://t', assertion: 'a' });
    expect('scope' in bare).toBe(false);
    expect(Object.keys(bare.request.params).sort()).toEqual(['assertion', 'grant_type']);
    const empties = jwtBearerAssertion({ tokenEndpoint: 'https://t', assertion: 'a', scope: '', clientAssertion: '' });
    expect('scope' in empties).toBe(false);
    expect(Object.keys(empties.request.params).sort()).toEqual(['assertion', 'grant_type']);
    const full = jwtBearerAssertion({ tokenEndpoint: 'https://t', assertion: 'a', scope: ' p  q ', clientId: 'c', clientAssertion: 'ca' });
    expect(full.scope).toBe('p q');
    expect(full.request.params).toMatchObject({ scope: 'p q', client_id: 'c', client_assertion: 'ca', client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' });
  });
});
