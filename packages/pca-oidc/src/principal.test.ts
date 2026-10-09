import { describe, expect, it } from 'vitest';
import {
  type Capability,
  type CapabilityChain,
  delegate,
  generateKeyPair,
  mintGrant,
  mintRoot,
  readEnvelope,
  verifyChain,
  b64u,
  DEFAULT_RISK_POLICY,
} from '@atlasauth/pca';
import { isOidcSubjectCaveat, OIDC_SUBJECT_CAVEAT, oidcPrincipal } from './principal';
import { verifyIdToken } from './verify';
import { baseClaims, makeIssuer, makePrincipalBinding } from './testkit';

const AUD = 'client-abc';

describe('oidcPrincipal', () => {
  it('derives a stable principalId and a subject caveat from claims', async () => {
    const idp = await makeIssuer();
    const token = await idp.mint(
      baseClaims({
        issuer: idp.issuer,
        audience: AUD,
        sub: 'abc|42',
        extra: { email: 'u@x.com', email_verified: true, name: 'Grace', preferred_username: 'grace', auth_time: 1000 },
      }),
    );
    const claims = await verifyIdToken(token, { issuer: idp.issuer, audience: AUD, key: idp.publicKey });
    const principal = oidcPrincipal(claims);

    expect(principal.iss).toBe(idp.issuer);
    expect(principal.sub).toBe('abc|42');
    expect(principal.principalId).toBe(`${idp.issuer}#abc|42`);
    expect(principal.email).toBe('u@x.com');
    expect(principal.emailVerified).toBe(true);
    expect(principal.name).toBe('Grace');
    expect(principal.preferredUsername).toBe('grace');
    expect(principal.authTime).toBe(1000);
    expect(principal.subjectCaveat).toEqual({ type: OIDC_SUBJECT_CAVEAT, iss: idp.issuer, sub: 'abc|42' });
    expect(isOidcSubjectCaveat(principal.subjectCaveat)).toBe(true);
    // No cnf key bound and none supplied => no principalPublic.
    expect(principal.principalPublic).toBeUndefined();
  });

  it('surfaces the cnf-bound Ed25519 key as principalPublic', async () => {
    const idp = await makeIssuer();
    const binding = makePrincipalBinding();
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD, extra: { cnf: binding.cnf } }));
    const claims = await verifyIdToken(token, { issuer: idp.issuer, audience: AUD, key: idp.publicKey });
    const principal = oidcPrincipal(claims);
    expect(principal.principalPublic).toBe(binding.principalPublic);
  });

  it('accepts an explicitly supplied principalPublic when the token carries no cnf', async () => {
    const idp = await makeIssuer();
    const binding = makePrincipalBinding();
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD }));
    const claims = await verifyIdToken(token, { issuer: idp.issuer, audience: AUD, key: idp.publicKey });
    const principal = oidcPrincipal(claims, { principalPublic: binding.principalPublic });
    expect(principal.principalPublic).toBe(binding.principalPublic);
  });

  it('rejects a supplied principalPublic that disagrees with the cnf-bound key', async () => {
    const idp = await makeIssuer();
    const bound = makePrincipalBinding();
    const other = makePrincipalBinding();
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD, extra: { cnf: bound.cnf } }));
    const claims = await verifyIdToken(token, { issuer: idp.issuer, audience: AUD, key: idp.publicKey });
    expect(() => oidcPrincipal(claims, { principalPublic: other.principalPublic })).toThrow();
  });

  it('rejects a malformed supplied principalPublic', async () => {
    const idp = await makeIssuer();
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD }));
    const claims = await verifyIdToken(token, { issuer: idp.issuer, audience: AUD, key: idp.publicKey });
    expect(() => oidcPrincipal(claims, { principalPublic: 'not-a-key' })).toThrow();
  });

  it('ignores a cnf that is not an Ed25519 OKP JWK', async () => {
    const idp = await makeIssuer();
    const token = await idp.mint(
      baseClaims({ issuer: idp.issuer, audience: AUD, extra: { cnf: { jwk: { kty: 'EC', crv: 'P-256', x: 'aaa', y: 'bbb' } } } }),
    );
    const claims = await verifyIdToken(token, { issuer: idp.issuer, audience: AUD, key: idp.publicKey });
    const principal = oidcPrincipal(claims);
    expect(principal.principalPublic).toBeUndefined();
  });
});

describe('oidcPrincipal → core capability root', () => {
  it('produces a principalPublic the core accepts as a root principal (mintRoot + verifyChain)', async () => {
    const idp = await makeIssuer();
    const binding = makePrincipalBinding();
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD, extra: { cnf: binding.cnf } }));
    const claims = await verifyIdToken(token, { issuer: idp.issuer, audience: AUD, key: idp.publicKey });
    const principal = oidcPrincipal(claims);
    const principalPublic = principal.principalPublic;
    expect(principalPublic).toBe(binding.principalPublic);
    if (principalPublic === undefined) throw new Error('expected a cnf-bound principalPublic');

    const agent = generateKeyPair();
    // Root the chain in the OIDC human's key; embed the subject caveat so the signed capability
    // carries a verifiable record of who authorized it.
    const root: Capability = mintRoot({
      principalSecret: binding.keyPair.secretKey,
      principalPublic,
      holder: b64u(agent.publicKey),
      caveats: [principal.subjectCaveat],
    });

    // The core accepts the OIDC-derived key as the expected root issuer.
    const chain: CapabilityChain = [root];
    const result = verifyChain(chain, principalPublic);
    expect(result.ok).toBe(true);

    // A different principal key is rejected as the root.
    const wrong = makePrincipalBinding();
    expect(verifyChain(chain, wrong.principalPublic).ok).toBe(false);

    // The subject caveat is present on the signed root and parses back.
    expect(isOidcSubjectCaveat(root.caveats[0])).toBe(true);

    // And a delegated sub-agent chain still verifies against the OIDC root.
    const sub = generateKeyPair();
    const child = delegate(root, b64u(sub.publicKey), [], agent.secretKey);
    expect(verifyChain([root, child], principalPublic).ok).toBe(true);
  });

  it('roots a full grant (mintGrant) in the OIDC human and embeds the subject caveat', async () => {
    const idp = await makeIssuer();
    const binding = makePrincipalBinding();
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD, extra: { cnf: binding.cnf } }));
    const claims = await verifyIdToken(token, { issuer: idp.issuer, audience: AUD, key: idp.publicKey });
    const principal = oidcPrincipal(claims);

    const principalPublic = principal.principalPublic;
    if (principalPublic === undefined) throw new Error('expected a cnf-bound principalPublic');
    const agent = generateKeyPair();
    const { grant } = mintGrant({
      principalSecret: binding.keyPair.secretKey,
      principalPublic,
      holder: b64u(agent.publicKey),
      goal: 'reconcile refunds',
      envelope: {
        predicates: [],
        caveats: [principal.subjectCaveat],
        agent_binding: {},
        risk_policy: DEFAULT_RISK_POLICY,
      },
    });

    expect(verifyChain([grant], principalPublic).ok).toBe(true);
    const env = readEnvelope(grant);
    expect(env).not.toBeNull();
    const subjectCaveat = env?.caveats.find(isOidcSubjectCaveat);
    expect(subjectCaveat?.iss).toBe(idp.issuer);
    expect(subjectCaveat?.sub).toBe('user-123');
  });
});
