import { describe, it, expect, beforeAll } from 'vitest';
import { SignJWT, exportJWK, generateKeyPair, type JWK, type JWTPayload, type KeyLike } from 'jose';
import { b64u, generateKeyPair as generatePcaKeyPair, verifyChain, type KeyPair } from '@atlasauth/pca';
import { isOidcSubjectCaveat } from '@atlasauth/pca-oidc';
import {
  verifyIdJag,
  idJagToPcaPrincipal,
  idJagToCapability,
  readIdJagAuthority,
  readIdJagProvenance,
  isIdJagAuthorityCaveat,
  isIdJagProvenanceCaveat,
  tokenExchangeRequest,
  jwtBearerAssertion,
  IdJagVerificationError,
  GRANT_TYPE_TOKEN_EXCHANGE,
  GRANT_TYPE_JWT_BEARER,
  TOKEN_TYPE_ID_JAG,
  TOKEN_TYPE_ID_TOKEN,
  TOKEN_TYPE_JWT,
  CLIENT_ASSERTION_TYPE_JWT_BEARER,
  type IdJagGrant,
} from './index';

const ISSUER = 'https://idp.example.com';
const AUDIENCE = 'https://resource.example.com';
const AGENT_ID = 'agent-app-7';
const HUMAN = 'user-123';
const KID = 'idjag-key-1';

let signingKey: KeyLike;
let publicKey: KeyLike;
let publicJwk: JWK;

beforeAll(async () => {
  const kp = await generateKeyPair('EdDSA', { extractable: true });
  signingKey = kp.privateKey;
  publicKey = kp.publicKey;
  publicJwk = { ...(await exportJWK(kp.publicKey)), kid: KID, alg: 'EdDSA', use: 'sig' };
});

/** Mint an ID-JAG JWT (sub=human, act=agent, single aud, scope). */
async function mintIdJag(overrides: Partial<JWTPayload> & { act?: unknown; scope?: unknown } = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: JWTPayload = {
    iss: ISSUER,
    sub: HUMAN,
    aud: AUDIENCE,
    iat: now,
    exp: now + 300,
    jti: 'jag-0001',
    act: { sub: AGENT_ID },
    scope: 'calendar.read mail.send',
    ...overrides,
  };
  return new SignJWT(payload).setProtectedHeader({ alg: 'EdDSA', kid: KID }).sign(signingKey);
}

describe('verifyIdJag', () => {
  it('verifies a well-formed ID-JAG and parses sub/act/aud/scope', async () => {
    const jwt = await mintIdJag();
    const grant = await verifyIdJag(jwt, { issuer: ISSUER, audience: AUDIENCE, key: publicKey });
    expect(grant.iss).toBe(ISSUER);
    expect(grant.sub).toBe(HUMAN);
    expect(grant.agent).toBe(AGENT_ID);
    expect(grant.actor.sub).toBe(AGENT_ID);
    expect(grant.audience).toBe(AUDIENCE);
    expect(grant.scopes).toEqual(['calendar.read', 'mail.send']);
    expect(grant.jti).toBe('jag-0001');
  });

  it('accepts a scopes array claim as an alternative to space-delimited scope', async () => {
    const jwt = await mintIdJag({ scope: undefined, scopes: ['a', 'b'] });
    const grant = await verifyIdJag(jwt, { issuer: ISSUER, audience: AUDIENCE, key: publicKey });
    expect(grant.scopes).toEqual(['a', 'b']);
  });

  it('enforces requiredScopes (subset)', async () => {
    const jwt = await mintIdJag();
    await expect(
      verifyIdJag(jwt, { issuer: ISSUER, audience: AUDIENCE, key: publicKey, requiredScopes: ['calendar.read'] }),
    ).resolves.toBeDefined();
    await expect(
      verifyIdJag(jwt, { issuer: ISSUER, audience: AUDIENCE, key: publicKey, requiredScopes: ['admin'] }),
    ).rejects.toMatchObject({ code: 'scope' });
  });

  it('fails closed on the WRONG audience', async () => {
    const jwt = await mintIdJag();
    await expect(
      verifyIdJag(jwt, { issuer: ISSUER, audience: 'https://other.example.com', key: publicKey }),
    ).rejects.toBeInstanceOf(IdJagVerificationError);
  });

  it('fails closed when the audience is NOT single (multi-aud)', async () => {
    // azp=AUDIENCE satisfies the reused OIDC multi-aud rule so our OWN single-audience guard is what fires.
    const jwt = await mintIdJag({ aud: [AUDIENCE, 'https://extra.example.com'], azp: AUDIENCE });
    const err = await verifyIdJag(jwt, { issuer: ISSUER, audience: AUDIENCE, key: publicKey }).catch((e) => e);
    expect(err).toBeInstanceOf(IdJagVerificationError);
    expect((err as IdJagVerificationError).code).toBe('audience');
  });

  it('fails closed on a multi-aud grant with no azp (reused OIDC rule)', async () => {
    const jwt = await mintIdJag({ aud: [AUDIENCE, 'https://extra.example.com'] });
    await expect(verifyIdJag(jwt, { issuer: ISSUER, audience: AUDIENCE, key: publicKey })).rejects.toBeInstanceOf(
      IdJagVerificationError,
    );
  });

  it('fails closed when the act (agent) claim is MISSING', async () => {
    const jwt = await mintIdJag({ act: undefined });
    const err = await verifyIdJag(jwt, { issuer: ISSUER, audience: AUDIENCE, key: publicKey }).catch((e) => e);
    expect(err).toBeInstanceOf(IdJagVerificationError);
    expect((err as IdJagVerificationError).code).toBe('actor');
  });

  it('fails closed when the act claim lacks a string sub', async () => {
    const jwt = await mintIdJag({ act: { foo: 'bar' } });
    await expect(verifyIdJag(jwt, { issuer: ISSUER, audience: AUDIENCE, key: publicKey })).rejects.toMatchObject({
      code: 'actor',
    });
  });

  it('fails closed when the scope claim is absent entirely', async () => {
    const jwt = await mintIdJag({ scope: undefined });
    await expect(verifyIdJag(jwt, { issuer: ISSUER, audience: AUDIENCE, key: publicKey })).rejects.toMatchObject({
      code: 'scope',
    });
  });

  it('fails closed on an EXPIRED grant', async () => {
    const past = Math.floor(Date.now() / 1000) - 10_000;
    const jwt = await mintIdJag({ iat: past, exp: past + 300 });
    const err = await verifyIdJag(jwt, { issuer: ISSUER, audience: AUDIENCE, key: publicKey }).catch((e) => e);
    expect(err).toBeInstanceOf(IdJagVerificationError);
    expect((err as IdJagVerificationError).code).toBe('expired');
  });

  it('fails closed on a bad signature (wrong key)', async () => {
    const jwt = await mintIdJag();
    const other = await generateKeyPair('EdDSA', { extractable: true });
    await expect(verifyIdJag(jwt, { issuer: ISSUER, audience: AUDIENCE, key: other.publicKey })).rejects.toMatchObject({
      code: 'signature',
    });
  });

  it('fails closed on the wrong issuer', async () => {
    const jwt = await mintIdJag();
    await expect(
      verifyIdJag(jwt, { issuer: 'https://evil.example.com', audience: AUDIENCE, key: publicKey }),
    ).rejects.toMatchObject({ code: 'issuer' });
  });

  it('resolves keys via an injectable JWKS resolver', async () => {
    const jwt = await mintIdJag();
    const getKey = async () => publicKey; // dynamic resolver (JWTVerifyGetKey shape)
    const grant = await verifyIdJag(jwt, { issuer: ISSUER, audience: AUDIENCE, key: getKey });
    expect(grant.agent).toBe(AGENT_ID);
  });

  it('rejects empty / missing config', async () => {
    await expect(verifyIdJag('', { issuer: ISSUER, audience: AUDIENCE, key: publicKey })).rejects.toMatchObject({
      code: 'invalid_token',
    });
    const jwt = await mintIdJag();
    await expect(verifyIdJag(jwt, { issuer: '', audience: AUDIENCE, key: publicKey })).rejects.toMatchObject({
      code: 'config',
    });
    await expect(verifyIdJag(jwt, { issuer: ISSUER, audience: '', key: publicKey })).rejects.toMatchObject({
      code: 'config',
    });
  });
});

describe('idJagToPcaPrincipal', () => {
  it('maps the grant onto a PCA principal descriptor', async () => {
    const jwt = await mintIdJag();
    const grant = await verifyIdJag(jwt, { issuer: ISSUER, audience: AUDIENCE, key: publicKey });
    const principal = idJagToPcaPrincipal(grant);
    expect(principal.iss).toBe(ISSUER);
    expect(principal.sub).toBe(HUMAN);
    expect(principal.principalId).toBe(`${ISSUER}#${HUMAN}`);
    expect(isOidcSubjectCaveat(principal.subjectCaveat)).toBe(true);
  });
});

describe('idJagToCapability', () => {
  let human: KeyPair;
  let agent: KeyPair;
  let principalPublic: string;
  let holder: string;

  beforeAll(() => {
    human = generatePcaKeyPair();
    agent = generatePcaKeyPair();
    principalPublic = b64u(human.publicKey);
    holder = b64u(agent.publicKey);
  });

  async function grant(): Promise<IdJagGrant> {
    const jwt = await mintIdJag();
    return verifyIdJag(jwt, { issuer: ISSUER, audience: AUDIENCE, key: publicKey });
  }

  it('projects a signed root capability: authority = scopes, holder = agent, subject = human', async () => {
    const g = await grant();
    const { capability, principal, scopes } = idJagToCapability(g, {
      principalSecret: human.secretKey,
      principalPublic,
      holder,
    });

    // holder = the agent key; issuer = the human principal key.
    expect(capability.holder).toBe(holder);
    expect(capability.issuer).toBe(principalPublic);
    expect(capability.parent).toBeUndefined();

    // authority == the grant's scopes
    expect(scopes).toEqual(['calendar.read', 'mail.send']);
    const authority = readIdJagAuthority(capability);
    expect(authority).not.toBeNull();
    expect(authority?.scopes).toEqual(['calendar.read', 'mail.send']);
    expect(authority?.aud).toBe(AUDIENCE);
    expect(isIdJagAuthorityCaveat(authority)).toBe(true);

    // provenance caveat records the ID-JAG
    const prov = readIdJagProvenance(capability);
    expect(prov).not.toBeNull();
    expect(prov?.iss).toBe(ISSUER);
    expect(prov?.sub).toBe(HUMAN);
    expect(prov?.agent).toBe(AGENT_ID);
    expect(prov?.jti).toBe('jag-0001');
    expect(isIdJagProvenanceCaveat(prov)).toBe(true);

    // subject = human, via the reused OIDC subject caveat
    expect(principal.sub).toBe(HUMAN);
    expect(capability.caveats.some((c) => isOidcSubjectCaveat(c))).toBe(true);
  });

  it('the capability verifies via the core (verifyChain anchored at the human principal)', async () => {
    const g = await grant();
    const { capability } = idJagToCapability(g, { principalSecret: human.secretKey, principalPublic, holder });
    const result = verifyChain([capability], principalPublic);
    expect(result.ok).toBe(true);
    // wrong expected root issuer fails closed
    expect(verifyChain([capability], holder).ok).toBe(false);
  });

  it('honors a cnf-bound principal key and rejects a mismatch (fail closed)', async () => {
    // Mint an ID-JAG that binds the human's PCA key via cnf.
    const cnf = { jwk: { kty: 'OKP', crv: 'Ed25519', x: principalPublic } };
    const jwt = await mintIdJag({ cnf });
    const g = await verifyIdJag(jwt, { issuer: ISSUER, audience: AUDIENCE, key: publicKey });
    // matching principalPublic -> works
    const { capability } = idJagToCapability(g, { principalSecret: human.secretKey, principalPublic, holder });
    expect(verifyChain([capability], principalPublic).ok).toBe(true);
    // a DIFFERENT principalPublic than the cnf-bound key must throw
    const other = generatePcaKeyPair();
    expect(() =>
      idJagToCapability(g, { principalSecret: other.secretKey, principalPublic: b64u(other.publicKey), holder }),
    ).toThrow();
  });

  it('appends extraCaveats after authority/provenance/subject', async () => {
    const g = await grant();
    const { capability } = idJagToCapability(g, {
      principalSecret: human.secretKey,
      principalPublic,
      holder,
      extraCaveats: [{ type: 'ttl', max: 60 }],
    });
    expect(verifyChain([capability], principalPublic).ok).toBe(true);
    expect(capability.caveats.some((c) => c.type === 'ttl')).toBe(true);
  });

  it('validates inputs (fail closed)', async () => {
    const g = await grant();
    expect(() => idJagToCapability(g, { principalSecret: human.secretKey, principalPublic: '', holder })).toThrow();
    expect(() => idJagToCapability(g, { principalSecret: human.secretKey, principalPublic, holder: '' })).toThrow();
  });
});

describe('RFC 8693 token-exchange request', () => {
  it('builds the ID-JAG token-exchange request shape', () => {
    const req = tokenExchangeRequest({
      tokenEndpoint: 'https://idp.example.com/oauth2/token',
      subjectToken: 'the-id-token',
      audience: AUDIENCE,
      scope: ['calendar.read', 'mail.send'],
      clientId: AGENT_ID,
    });
    expect(req.method).toBe('POST');
    expect(req.url).toBe('https://idp.example.com/oauth2/token');
    expect(req.headers['content-type']).toBe('application/x-www-form-urlencoded');
    expect(req.params.grant_type).toBe(GRANT_TYPE_TOKEN_EXCHANGE);
    expect(req.params.requested_token_type).toBe(TOKEN_TYPE_ID_JAG);
    expect(req.params.subject_token).toBe('the-id-token');
    expect(req.params.subject_token_type).toBe(TOKEN_TYPE_ID_TOKEN);
    expect(req.params.audience).toBe(AUDIENCE);
    expect(req.params.scope).toBe('calendar.read mail.send');
    expect(req.params.client_id).toBe(AGENT_ID);
    // body round-trips the params
    const parsed = new URLSearchParams(req.body);
    expect(parsed.get('grant_type')).toBe(GRANT_TYPE_TOKEN_EXCHANGE);
    expect(parsed.get('scope')).toBe('calendar.read mail.send');
  });

  it('includes actor_token + actor_token_type when delegating', () => {
    const req = tokenExchangeRequest({
      tokenEndpoint: 'https://idp.example.com/token',
      subjectToken: 'subj',
      actorToken: 'act-jwt',
    });
    expect(req.params.actor_token).toBe('act-jwt');
    expect(req.params.actor_token_type).toBe(TOKEN_TYPE_JWT);
  });

  it('omits actor fields when no actor token is given', () => {
    const req = tokenExchangeRequest({ tokenEndpoint: 'https://idp.example.com/token', subjectToken: 'subj' });
    expect(req.params.actor_token).toBeUndefined();
    expect(req.params.actor_token_type).toBeUndefined();
  });

  it('validates inputs', () => {
    expect(() => tokenExchangeRequest({ tokenEndpoint: '', subjectToken: 'x' })).toThrow();
    expect(() => tokenExchangeRequest({ tokenEndpoint: 'https://x', subjectToken: '' })).toThrow();
  });
});

describe('RFC 7523 jwt-bearer assertion', () => {
  it('represents an ID-JAG being redeemed + builds the request shape', () => {
    const rep = jwtBearerAssertion({
      tokenEndpoint: 'https://resource.example.com/token',
      assertion: 'the-id-jag-jwt',
      scope: 'calendar.read',
      clientId: AGENT_ID,
    });
    expect(rep.grantType).toBe(GRANT_TYPE_JWT_BEARER);
    expect(rep.assertion).toBe('the-id-jag-jwt');
    expect(rep.scope).toBe('calendar.read');
    expect(rep.request.url).toBe('https://resource.example.com/token');
    expect(rep.request.params.grant_type).toBe(GRANT_TYPE_JWT_BEARER);
    expect(rep.request.params.assertion).toBe('the-id-jag-jwt');
    expect(rep.request.params.scope).toBe('calendar.read');
    expect(rep.request.params.client_id).toBe(AGENT_ID);
  });

  it('carries a client assertion for client auth when supplied', () => {
    const rep = jwtBearerAssertion({
      tokenEndpoint: 'https://resource.example.com/token',
      assertion: 'the-id-jag',
      clientAssertion: 'client-jwt',
    });
    expect(rep.request.params.client_assertion_type).toBe(CLIENT_ASSERTION_TYPE_JWT_BEARER);
    expect(rep.request.params.client_assertion).toBe('client-jwt');
  });

  it('validates inputs', () => {
    expect(() => jwtBearerAssertion({ tokenEndpoint: '', assertion: 'x' })).toThrow();
    expect(() => jwtBearerAssertion({ tokenEndpoint: 'https://x', assertion: '' })).toThrow();
  });
});
