import { describe, it, expect } from 'vitest';
import {
  type Signer,
  generateKeyPair,
  publicKeyOf,
  b64u,
  verifyChain,
} from '@atlasauth/pca';
import {
  type GnapGrantRequest,
  AGENT_GNAP_PROFILE,
  accessContains,
  accessToPredicates,
  authorizeGnapAction,
  beginGnapContinuation,
  capabilityToGrantResponse,
  clampAccess,
  completeGnapContinuation,
  encodeBoundToken,
  gnapActionResource,
  gnapRequestRequiresStepUp,
  grantRequestToCapability,
  grantedAccessOf,
  signGnapRequest,
  verifyGnapRequest,
  verifyGnapToken,
} from './index';

// ---- helpers --------------------------------------------------------------------------------

function kp() {
  const k = generateKeyPair();
  return { secretKey: k.secretKey, publicKey: k.publicKey, b64: b64u(k.publicKey) };
}

/** A grant request bound to a given Ed25519 client key, asking for `access`. */
function request(clientPub: Uint8Array, access: GnapGrantRequest['access_token']['access'], interact?: GnapGrantRequest['interact']): GnapGrantRequest {
  return {
    access_token: { access },
    client: { key: { proof: 'jwsd', jwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(clientPub) } } },
    ...(interact !== undefined ? { interact } : {}),
  };
}

// ============================================================================================

describe('grant request → PCA capability', () => {
  it('issues a verifying, bound capability whose authority MATCHES the requested rights', () => {
    const principal = kp();
    const agent = kp();
    const req = request(agent.publicKey, [{ type: 'repo', actions: ['read', 'write'], locations: ['main'] }]);

    const { grant, chain, holder, grantedAccess } = grantRequestToCapability(req, {
      issuerSecret: principal.secretKey,
      issuerPublic: principal.b64,
    });

    // the capability verifies and is rooted in the principal
    expect(verifyChain(chain, principal.b64).ok).toBe(true);
    // bound to the GNAP client key
    expect(holder).toBe(agent.b64);
    expect(grant.holder).toBe(agent.b64);
    // authority == requested rights
    expect(grantedAccess).toEqual([{ type: 'repo', actions: ['read', 'write'], locations: ['main'] }]);
    const res = gnapActionResource('repo', 'main');
    expect(authorizeGnapAction(chain, { verb: 'read', resource: res }).allowed).toBe(true);
    expect(authorizeGnapAction(chain, { verb: 'write', resource: res }).allowed).toBe(true);
    // an action OUTSIDE the granted rights is denied (not wider than requested)
    expect(authorizeGnapAction(chain, { verb: 'delete', resource: res }).allowed).toBe(false);
    expect(authorizeGnapAction(chain, { verb: 'read', resource: gnapActionResource('repo', 'other') }).allowed).toBe(false);
  });

  it('maps type/actions/locations/datatypes onto predicates and enforces datatypes via params', () => {
    const preds = accessToPredicates({ type: 'files', actions: ['get'], locations: ['/docs'], datatypes: ['pdf', 'txt'] });
    expect(preds).toHaveLength(1);
    expect(preds[0]!.verb).toEqual(['get']);
    expect(preds[0]!.resource).toBe('gnap:files:/docs');
    expect(preds[0]!.where).toEqual([{ field: 'action.params.datatype', op: 'in', value: ['pdf', 'txt'] }]);

    const principal = kp();
    const agent = kp();
    const req = request(agent.publicKey, [{ type: 'files', actions: ['get'], locations: ['/docs'], datatypes: ['pdf'] }]);
    const { chain } = grantRequestToCapability(req, { issuerSecret: principal.secretKey, issuerPublic: principal.b64 });
    const res = gnapActionResource('files', '/docs');
    // datatype constraint honored: pdf allowed, png denied, missing params denied (fail closed)
    expect(authorizeGnapAction(chain, { verb: 'get', resource: res, params: { datatype: 'pdf' } }).allowed).toBe(true);
    expect(authorizeGnapAction(chain, { verb: 'get', resource: res, params: { datatype: 'png' } }).allowed).toBe(false);
    expect(authorizeGnapAction(chain, { verb: 'get', resource: res }).allowed).toBe(false);
  });
});

describe('GNAP bound token ↔ PCA principal round-trip', () => {
  it('round-trips a capability chain to a PCA principal, and fails closed on tamper', () => {
    const principal = kp();
    const agent = kp();
    const req = request(agent.publicKey, [{ type: 'calendar', actions: ['read'], locations: ['primary'] }]);
    const { chain } = grantRequestToCapability(req, { issuerSecret: principal.secretKey, issuerPublic: principal.b64 });

    const response = capabilityToGrantResponse(chain, { expiresIn: 3600 });
    expect(response.access_token).toBeDefined();
    const token = response.access_token!;
    expect(token.key).toEqual({ kty: 'OKP', crv: 'Ed25519', x: agent.b64, use: 'sig', alg: 'EdDSA' });
    expect(token.access).toEqual([{ type: 'calendar', actions: ['read'], locations: ['primary'] }]);

    const verified = verifyGnapToken(token.value, { expectedRootIssuer: principal.b64 });
    expect(verified.ok).toBe(true);
    if (verified.ok) {
      expect(verified.principal).toBe(principal.b64); // the root issuer == the PCA principal
      expect(verified.capability.holder).toBe(agent.b64);
      expect(verified.access).toEqual([{ type: 'calendar', actions: ['read'], locations: ['primary'] }]);
    }

    // wrong expected principal → fail closed
    expect(verifyGnapToken(token.value, { expectedRootIssuer: kp().b64 }).ok).toBe(false);
    // tampered token → fail closed
    expect(verifyGnapToken(token.value + 'AA').ok).toBe(false);
    expect(verifyGnapToken('not-a-token').ok).toBe(false);
    expect(verifyGnapToken('').ok).toBe(false);
  });

  it('a token whose chain has been edited after signing does not verify', () => {
    const principal = kp();
    const agent = kp();
    const { chain } = grantRequestToCapability(
      request(agent.publicKey, [{ type: 'repo', actions: ['read'], locations: ['main'] }]),
      { issuerSecret: principal.secretKey, issuerPublic: principal.b64 },
    );
    // rebind the holder to an attacker key without re-signing
    const tampered = [{ ...chain[0]!, holder: kp().b64 }];
    expect(verifyGnapToken(encodeBoundToken(tampered), { expectedRootIssuer: principal.b64 }).ok).toBe(false);
  });
});

describe('key-bound requests (jwsd, verified with jose)', () => {
  it('a jwsd-signed request verifies; a tampered body, bad signature, or wrong holder fail closed', async () => {
    const client = kp();
    const req = request(client.publicKey, [{ type: 'repo', actions: ['read'], locations: ['main'] }]);
    const htm = 'POST';
    const uri = 'https://as.example/tx';

    const signed = await signGnapRequest({ body: req, key: client, htm, uri });
    expect(signed.holder).toBe(client.b64);
    expect(signed.detachedJws.split('.')).toHaveLength(3);
    expect(signed.detachedJws.split('.')[1]).toBe(''); // detached: empty payload segment

    // happy path
    const ok = await verifyGnapRequest({ detachedJws: signed.detachedJws, body: req, holder: client.b64, htm, uri });
    expect(ok.ok).toBe(true);

    // tampered body
    const tamperedBody = request(client.publicKey, [{ type: 'repo', actions: ['read', 'write'], locations: ['main'] }]);
    expect((await verifyGnapRequest({ detachedJws: signed.detachedJws, body: tamperedBody, holder: client.b64, htm, uri })).ok).toBe(false);

    // wrong holder key
    expect((await verifyGnapRequest({ detachedJws: signed.detachedJws, body: req, holder: kp().b64, htm, uri })).ok).toBe(false);

    // mismatched method / uri
    expect((await verifyGnapRequest({ detachedJws: signed.detachedJws, body: req, holder: client.b64, htm: 'GET', uri })).ok).toBe(false);
    expect((await verifyGnapRequest({ detachedJws: signed.detachedJws, body: req, holder: client.b64, htm, uri: 'https://evil/tx' })).ok).toBe(false);

    // tampered signature
    const chars = signed.detachedJws.split('.');
    const sig = chars[2]!;
    const flipped = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
    const badSig = `${chars[0]}..${flipped}`;
    expect((await verifyGnapRequest({ detachedJws: badSig, body: req, holder: client.b64, htm, uri })).ok).toBe(false);
  });

  it('binds to an access token via ath, and rejects a stale proof', async () => {
    const client = kp();
    const req = request(client.publicKey, [{ type: 'repo', actions: ['read'], locations: ['main'] }]);
    const htm = 'POST';
    const uri = 'https://as.example/tx';
    const tokenValue = 'bound-access-token-value';

    const nowSec = 1_000_000;
    const signed = await signGnapRequest({ body: req, key: client, htm, uri, created: nowSec, accessTokenValue: tokenValue });
    // ath must bind the right token
    expect((await verifyGnapRequest({ detachedJws: signed.detachedJws, body: req, holder: client.b64, htm, uri, accessTokenValue: tokenValue, now: nowSec * 1000 })).ok).toBe(true);
    expect((await verifyGnapRequest({ detachedJws: signed.detachedJws, body: req, holder: client.b64, htm, uri, accessTokenValue: 'other', now: nowSec * 1000 })).ok).toBe(false);
    // stale: proof created well before now
    expect((await verifyGnapRequest({ detachedJws: signed.detachedJws, body: req, holder: client.b64, htm, uri, now: (nowSec + 10_000) * 1000, maxAgeSec: 300 })).ok).toBe(false);
  });
});

describe('continuation → step-up (FROST / threshold co-signature folded into a PCActn)', () => {
  it('a request beyond the issuer needs a continuation that resolves via a co-signature', () => {
    const principal = kp();
    const agentA = kp();
    // agentA holds read-only on repo:main
    const { chain: issuerChain } = grantRequestToCapability(
      request(agentA.publicKey, [{ type: 'repo', actions: ['read'], locations: ['main'] }]),
      { issuerSecret: principal.secretKey, issuerPublic: principal.b64 },
    );

    // a downstream request asks for `write` — beyond agentA's authority
    const over = request(kp().publicKey, [{ type: 'repo', actions: ['write'], locations: ['main'] }]);
    const assessment = gnapRequestRequiresStepUp(over, { issuerChain });
    expect(assessment.required).toBe(true);
    expect(assessment.beyond).toHaveLength(1);

    // an in-scope request needs no step-up
    const inScope = request(kp().publicKey, [{ type: 'repo', actions: ['read'], locations: ['main'] }]);
    expect(gnapRequestRequiresStepUp(inScope, { issuerChain }).required).toBe(false);

    // interaction requested → step-up
    const withInteract = request(kp().publicKey, [{ type: 'repo', actions: ['read'], locations: ['main'] }], { start: ['redirect'] });
    expect(gnapRequestRequiresStepUp(withInteract).required).toBe(true);
  });

  it('completes a continuation: the step-up co-signature is folded into the PCActn threshold (t=2)', () => {
    const principal = kp();
    const agent = kp();
    const guardian = kp();

    // mint a grant to the agent
    const { grant, chain } = grantRequestToCapability(
      request(agent.publicKey, [{ type: 'payments', actions: ['transfer'], locations: ['acct-1'] }]),
      { issuerSecret: principal.secretKey, issuerPublic: principal.b64 },
    );

    const signerSet: Signer[] = [
      { role: 'agent', publicKey: agent.b64 },
      { role: 'guardian', publicKey: guardian.b64 },
      { role: 'principal', publicKey: principal.b64 },
    ];

    const { response, stepUp } = beginGnapContinuation({
      signerSet,
      t: 2,
      tier: 2,
      continueUri: 'https://as.example/continue/abc',
      continueToken: 'cont-token',
    });
    expect(response.continue?.uri).toBe('https://as.example/continue/abc');
    expect(response.access_token).toBeUndefined(); // no token until the step-up resolves
    expect(stepUp.tier).toBe(2);

    const plan = [{ id: 'n1', verb: 'transfer', resource: gnapActionResource('payments', 'acct-1') }];

    // with the guardian co-signature folded in → threshold t=2 satisfied
    const done = completeGnapContinuation({
      grant,
      chain,
      plan,
      nodeId: 'n1',
      counter: 0,
      aud: 'https://rs.example',
      agentLeafSecret: agent.secretKey,
      signerSet,
      t: 2,
      cosignSecrets: [{ role: 'guardian', secret: guardian.secretKey }],
    });
    expect(done.verdict.ok).toBe(true);
    expect(done.verdict.count).toBeGreaterThanOrEqual(2);
    expect(done.pcactn.threshold).toBeDefined();
    expect(done.pcactn.threshold!.shares.length).toBe(2);

    // WITHOUT the co-signature (agent only) → t=2 is NOT reached (step-up genuinely required)
    const agentOnly = completeGnapContinuation({
      grant,
      chain,
      plan,
      nodeId: 'n1',
      counter: 0,
      aud: 'https://rs.example',
      agentLeafSecret: agent.secretKey,
      signerSet,
      t: 2,
      cosignSecrets: [],
    });
    expect(agentOnly.verdict.ok).toBe(false);
  });
});

describe('agent-GNAP multi-hop profile: attenuation holds across a 2-hop chain', () => {
  it('clamps a widening request at issue time and denies it at action time', () => {
    const principal = kp();
    const agentA = kp();
    const agentB = kp();

    // hop 0: principal → agent A gets read+write on repo:main
    const hop0 = grantRequestToCapability(
      request(agentA.publicKey, [{ type: 'repo', actions: ['read', 'write'], locations: ['main'] }]),
      { issuerSecret: principal.secretKey, issuerPublic: principal.b64 },
    );

    // hop 1: agent A → agent B asks for read + delete (delete is BEYOND A's authority)
    const hop1 = grantRequestToCapability(
      request(agentB.publicKey, [
        { type: 'repo', actions: ['read'], locations: ['main'] },
        { type: 'repo', actions: ['delete'], locations: ['main'] },
      ]),
      {
        issuerSecret: agentA.secretKey,
        issuerPublic: agentA.b64,
        parent: hop0.grant,
        issuerChain: hop0.chain,
      },
    );

    // the chain verifies structurally (append-only attenuation)
    expect(verifyChain(hop1.chain, principal.b64).ok).toBe(true);
    expect(hop1.chain).toHaveLength(2);

    // `delete` was clamped away at issue time; only `read` granted
    expect(hop1.grantedAccess).toEqual([{ type: 'repo', actions: ['read'], locations: ['main'] }]);
    expect(hop1.droppedAccess).toEqual([{ type: 'repo', actions: ['delete'], locations: ['main'] }]);
    expect(grantedAccessOf(hop1.chain)).toEqual([{ type: 'repo', actions: ['read'], locations: ['main'] }]);

    const res = gnapActionResource('repo', 'main');
    // read: allowed at both hops
    expect(authorizeGnapAction(hop1.chain, { verb: 'read', resource: res }).allowed).toBe(true);
    // write: hop0 allowed it, but hop1 (agent B) never got it → denied (never wider than the issuer... and narrower)
    expect(authorizeGnapAction(hop1.chain, { verb: 'write', resource: res }).allowed).toBe(false);
    // delete: beyond the whole chain → denied
    expect(authorizeGnapAction(hop1.chain, { verb: 'delete', resource: res }).allowed).toBe(false);
  });

  it('even WITHOUT clamping, an action beyond the issuer is denied at action time', () => {
    const principal = kp();
    const agentA = kp();
    const agentB = kp();

    const hop0 = grantRequestToCapability(
      request(agentA.publicKey, [{ type: 'repo', actions: ['read'], locations: ['main'] }]),
      { issuerSecret: principal.secretKey, issuerPublic: principal.b64 },
    );
    // disable clamp: agent A records a `write` right it does not actually hold
    const hop1 = grantRequestToCapability(
      request(agentB.publicKey, [{ type: 'repo', actions: ['read', 'write'], locations: ['main'] }]),
      {
        issuerSecret: agentA.secretKey,
        issuerPublic: agentA.b64,
        parent: hop0.grant,
        issuerChain: hop0.chain,
        clampToIssuer: false,
      },
    );
    expect(hop1.grantedAccess).toEqual([{ type: 'repo', actions: ['read', 'write'], locations: ['main'] }]);
    const res = gnapActionResource('repo', 'main');
    // the root envelope (read-only) still gates: `write` denied despite the hop recording it
    expect(authorizeGnapAction(hop1.chain, { verb: 'write', resource: res }).allowed).toBe(false);
    expect(authorizeGnapAction(hop1.chain, { verb: 'read', resource: res }).allowed).toBe(true);
  });
});

describe('access-containment + profile spec', () => {
  it('accessContains / clampAccess compute rights subsets correctly', () => {
    const g = { type: 'repo', actions: ['read', 'write'], locations: ['main', 'dev'] };
    expect(accessContains(g, { type: 'repo', actions: ['read'], locations: ['main'] })).toBe(true);
    expect(accessContains(g, { type: 'repo', actions: ['delete'], locations: ['main'] })).toBe(false);
    expect(accessContains(g, { type: 'repo', actions: ['read'], locations: ['prod'] })).toBe(false);
    expect(accessContains(g, { type: 'other', actions: ['read'], locations: ['main'] })).toBe(false);
    // wildcard issuer location covers everything
    expect(accessContains({ type: 'repo', locations: ['*'] }, { type: 'repo', locations: ['anything'] })).toBe(true);
    // issuer with no `actions` means all actions
    expect(accessContains({ type: 'repo', locations: ['main'] }, { type: 'repo', actions: ['read'], locations: ['main'] })).toBe(true);

    const split = clampAccess([g], [
      { type: 'repo', actions: ['read'], locations: ['main'] },
      { type: 'repo', actions: ['admin'], locations: ['main'] },
    ]);
    expect(split.granted).toHaveLength(1);
    expect(split.dropped).toHaveLength(1);
  });

  it('exports a machine-readable agent-GNAP profile spec', () => {
    expect(AGENT_GNAP_PROFILE.name).toBe('agent-gnap');
    expect(AGENT_GNAP_PROFILE.rfc).toBe('RFC 9635');
    expect(AGENT_GNAP_PROFILE.proofMethods).toContain('jwsd');
    expect(AGENT_GNAP_PROFILE.mapping.length).toBeGreaterThan(5);
    expect(AGENT_GNAP_PROFILE.security.length).toBeGreaterThan(0);
    // sanity: publicKeyOf agrees with the key we bind holders to
    const k = generateKeyPair();
    expect(b64u(publicKeyOf(k.secretKey))).toBe(b64u(k.publicKey));
  });
});
