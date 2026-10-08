import { describe, expect, it } from 'vitest';
import {
  DEFAULT_RISK_POLICY,
  buildPCActn,
  delegate,
  encodeKey,
  generateKeyPair,
  mintGrant,
  type Capability,
  type CapabilityChain,
  type PCActn,
  type PlanNode,
} from '@atlasauth/pca';
import {
  KB_JWT_TYP,
  PCA_SD_JWT_TYP,
  SD_ALG,
  ed25519PublicJwk,
  importEd25519PrivateKey,
  importEd25519PublicKey,
  issuePcaSdJwt,
  present,
  verifyPcaSdJwt,
} from './index';

// ---------------------------------------------------------------------------------------------------
// Build a real, signed PCActn via the core builders (principal → agent delegation + a committed plan).
// ---------------------------------------------------------------------------------------------------

interface Fixture {
  pcActn: PCActn;
  principal: ReturnType<typeof generateKeyPair>;
  agent: ReturnType<typeof generateKeyPair>;
  principalPublic: string;
  agentPublic: string;
  grant: Capability;
  chain: CapabilityChain;
  now: number;
}

function fixture(overrides?: { ttlMs?: number; now?: number }): Fixture {
  const now = overrides?.now ?? Date.now();
  const principal = generateKeyPair();
  const agent = generateKeyPair();
  const principalPublic = encodeKey(principal.publicKey);
  const agentPublic = encodeKey(agent.publicKey);

  // Principal mints the root grant (held by itself), then delegates to the agent.
  const { grant } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic,
    holder: principalPublic,
    goal: 'secure my account',
    envelope: {
      predicates: [{ verb: 'revoke_session', resource: 'session:*' }],
      caveats: [{ type: 'expires', at: now + 3_600_000 }],
      agent_binding: {},
      risk_policy: DEFAULT_RISK_POLICY,
    },
  });
  const task = delegate(grant, agentPublic, [{ type: 'expires', at: now + 600_000 }], principal.secretKey);
  const chain: CapabilityChain = [grant, task];

  const plan: PlanNode[] = [
    { id: 'n1', verb: 'revoke_session', resource: 'session:s2', params_digest: undefined, reversibility_class: 'reversible' },
  ];

  const pcActn = buildPCActn({
    grant,
    chain,
    plan,
    nodeId: 'n1',
    params: { device: 'phone' },
    counter: 1,
    signerSecret: agent.secretKey,
    aud: 'atlas-rs-prod',
    now,
    ttlMs: overrides?.ttlMs ?? 600_000,
    nonce: 'nonce-xyz',
    caution: 0.2,
  });

  return { pcActn, principal, agent, principalPublic, agentPublic, grant, chain, now };
}

// ---------------------------------------------------------------------------------------------------

describe('issuePcaSdJwt', () => {
  it('serializes a PCActn as an SD-JWT: clear std claims + disclosures, trailing ~, no KB', async () => {
    const f = fixture();
    const issuerKey = importEd25519PrivateKey(f.principal.secretKey);
    const sdjwt = await issuePcaSdJwt(f.pcActn, { issuerKey });

    expect(sdjwt.endsWith('~')).toBe(true); // issued form carries no KB-JWT
    const segments = sdjwt.split('~');
    const jwt = segments[0] as string;
    expect(jwt.split('.').length).toBe(3); // compact JWS
    // one disclosure per present capability claim (action, grant_ref, cap_chain, plan, attestation,
    // provenance, freshness, counter, risk_claim, nonce, caution, sig) = 12 here
    const disclosures = segments.slice(1).filter((s) => s.length > 0);
    expect(disclosures.length).toBe(12);
  });
});

describe('verifyPcaSdJwt — full disclosure', () => {
  it('verifies the issuer JWS and recovers every capability claim verbatim', async () => {
    const f = fixture();
    const issuerKey = importEd25519PrivateKey(f.principal.secretKey);
    const sdjwt = await issuePcaSdJwt(f.pcActn, { issuerKey });

    const res = await verifyPcaSdJwt(sdjwt, { issuerKey: importEd25519PublicKey(f.principal.publicKey) });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    // standard claims mapped from the PCActn
    expect(res.payload.iss).toBe(f.principalPublic); // root issuer = principal
    expect(res.payload.sub).toBe(f.agentPublic); // leaf holder = acting agent
    expect(res.payload.aud).toBe('atlas-rs-prod');
    expect(res.payload.iat).toBe(Math.floor(f.pcActn.iat / 1000));
    expect(res.payload.exp).toBe(Math.ceil(f.pcActn.exp / 1000));
    expect(res.payload.ver).toBe(f.pcActn.ver);
    expect(res.payload._sd_alg).toBe(SD_ALG);
    expect(res.protectedHeader.typ).toBe(PCA_SD_JWT_TYP);

    // capability claims round-trip verbatim through the disclosures
    expect(res.disclosed.action).toEqual(f.pcActn.action);
    expect(res.disclosed.cap_chain).toEqual(f.pcActn.cap_chain);
    expect(res.disclosed.plan).toEqual(f.pcActn.plan);
    expect(res.disclosed.grant_ref).toBe(f.pcActn.grant_ref);
    expect(res.disclosed.counter).toBe(1);
    expect(res.disclosed.nonce).toBe('nonce-xyz');
    expect(res.disclosed.caution).toBe(0.2);
    expect(res.disclosed.sig).toBe(f.pcActn.sig); // the PCActn's own signature rides as a claim
    expect(res.keyBinding).toEqual({ presented: false, verified: false });
  });
});

describe('present — selective disclosure', () => {
  it('discloses only the selected claims and drops the rest', async () => {
    const f = fixture();
    const issuerKey = importEd25519PrivateKey(f.principal.secretKey);
    const sdjwt = await issuePcaSdJwt(f.pcActn, { issuerKey });

    const presentation = await present(sdjwt, ['action', 'grant_ref']);
    const res = await verifyPcaSdJwt(presentation, { issuerKey: importEd25519PublicKey(f.principal.publicKey) });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(Object.keys(res.disclosed).sort()).toEqual(['action', 'grant_ref']);
    expect(res.disclosed.cap_chain).toBeUndefined();
    expect(res.disclosed.sig).toBeUndefined();
    // standard claims remain visible even when all else is withheld
    expect(res.payload.aud).toBe('atlas-rs-prod');
    expect(res.payload.ver).toBe(f.pcActn.ver);
  });

  it('fails verification when a required disclosure was withheld', async () => {
    const f = fixture();
    const issuerKey = importEd25519PrivateKey(f.principal.secretKey);
    const sdjwt = await issuePcaSdJwt(f.pcActn, { issuerKey });

    const presentation = await present(sdjwt, ['action']);
    const res = await verifyPcaSdJwt(presentation, {
      issuerKey: importEd25519PublicKey(f.principal.publicKey),
      requiredDisclosures: ['cap_chain'],
    });
    expect(res.ok).toBe(false);
  });
});

describe('verifyPcaSdJwt — fail closed', () => {
  it('rejects a tampered disclosure (digest not in _sd)', async () => {
    const f = fixture();
    const issuerKey = importEd25519PrivateKey(f.principal.secretKey);
    const sdjwt = await issuePcaSdJwt(f.pcActn, { issuerKey });

    // Replace one disclosure with a re-salted disclosure of a changed `counter` value.
    const segments = sdjwt.split('~');
    const jwt = segments[0] as string;
    const forged = Buffer.from(JSON.stringify(['forged-salt-0000000000', 'counter', 9999]), 'utf8').toString('base64url');
    const tampered = `${jwt}~${forged}~`;

    const res = await verifyPcaSdJwt(tampered, { issuerKey: importEd25519PublicKey(f.principal.publicKey) });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.reason).toMatch(/does not match any _sd digest/);
  });

  it('rejects the wrong audience', async () => {
    const f = fixture();
    const issuerKey = importEd25519PrivateKey(f.principal.secretKey);
    const sdjwt = await issuePcaSdJwt(f.pcActn, { issuerKey });

    const res = await verifyPcaSdJwt(sdjwt, {
      issuerKey: importEd25519PublicKey(f.principal.publicKey),
      expectedAudience: 'some-other-rs',
    });
    expect(res.ok).toBe(false);
  });

  it('accepts the matching audience', async () => {
    const f = fixture();
    const issuerKey = importEd25519PrivateKey(f.principal.secretKey);
    const sdjwt = await issuePcaSdJwt(f.pcActn, { issuerKey });

    const res = await verifyPcaSdJwt(sdjwt, {
      issuerKey: importEd25519PublicKey(f.principal.publicKey),
      expectedAudience: 'atlas-rs-prod',
    });
    expect(res.ok).toBe(true);
  });

  it('rejects an expired proof', async () => {
    const f = fixture();
    const issuerKey = importEd25519PrivateKey(f.principal.secretKey);
    const sdjwt = await issuePcaSdJwt(f.pcActn, { issuerKey });

    const res = await verifyPcaSdJwt(sdjwt, {
      issuerKey: importEd25519PublicKey(f.principal.publicKey),
      now: f.pcActn.exp + 600_000, // 10 minutes past expiry
    });
    expect(res.ok).toBe(false);
  });

  it('rejects a forged issuer signature', async () => {
    const f = fixture();
    const issuerKey = importEd25519PrivateKey(f.principal.secretKey);
    const sdjwt = await issuePcaSdJwt(f.pcActn, { issuerKey });

    const wrong = generateKeyPair();
    const res = await verifyPcaSdJwt(sdjwt, { issuerKey: importEd25519PublicKey(wrong.publicKey) });
    expect(res.ok).toBe(false);
  });
});

describe('verifyPcaSdJwt — key binding (cnf + KB-JWT)', () => {
  it('embeds cnf (default: the leaf holder), verifies a holder KB-JWT, and binds aud + sd_hash', async () => {
    const f = fixture();
    const issuerKey = importEd25519PrivateKey(f.principal.secretKey);
    // default keyBinding derives cnf from the acting agent (leaf holder)
    const sdjwt = await issuePcaSdJwt(f.pcActn, { issuerKey, keyBinding: {} });

    const presentation = await present(sdjwt, ['action', 'cap_chain'], {
      keyBinding: {
        holderKey: importEd25519PrivateKey(f.agent.secretKey),
        audience: 'atlas-rs-prod',
        nonce: 'kb-nonce-1',
      },
    });
    expect(presentation.endsWith('~')).toBe(false); // ends with the KB-JWT
    const kbJwt = presentation.slice(presentation.lastIndexOf('~') + 1);
    expect(kbJwt.split('.').length).toBe(3);

    const res = await verifyPcaSdJwt(presentation, {
      issuerKey: importEd25519PublicKey(f.principal.publicKey),
      expectedAudience: 'atlas-rs-prod',
      keyBindingKey: f.agent.publicKey, // expect binding to the acting agent's key
      expectedNonce: 'kb-nonce-1',
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.keyBinding).toEqual({ presented: true, verified: true, aud: 'atlas-rs-prod', nonce: 'kb-nonce-1' });
    const cnf = res.payload.cnf as { jwk: { x: string } };
    expect(cnf.jwk).toEqual(ed25519PublicJwk(f.agent.publicKey));
  });

  it('rejects a KB-JWT signed by the wrong holder key', async () => {
    const f = fixture();
    const issuerKey = importEd25519PrivateKey(f.principal.secretKey);
    const sdjwt = await issuePcaSdJwt(f.pcActn, { issuerKey, keyBinding: {} });

    const impostor = generateKeyPair(); // NOT the cnf-bound agent
    const presentation = await present(sdjwt, ['action'], {
      keyBinding: {
        holderKey: importEd25519PrivateKey(impostor.secretKey),
        audience: 'atlas-rs-prod',
      },
    });

    const res = await verifyPcaSdJwt(presentation, {
      issuerKey: importEd25519PublicKey(f.principal.publicKey),
      expectedAudience: 'atlas-rs-prod',
    });
    expect(res.ok).toBe(false); // KB-JWT does not verify under the cnf key
  });

  it('rejects when key binding is required but absent', async () => {
    const f = fixture();
    const issuerKey = importEd25519PrivateKey(f.principal.secretKey);
    const sdjwt = await issuePcaSdJwt(f.pcActn, { issuerKey, keyBinding: {} });

    // Present WITHOUT attaching a KB-JWT, but the verifier expects one.
    const presentation = await present(sdjwt, ['action']);
    const res = await verifyPcaSdJwt(presentation, {
      issuerKey: importEd25519PublicKey(f.principal.publicKey),
      keyBindingKey: f.agent.publicKey,
    });
    expect(res.ok).toBe(false);
  });

  it('rejects a KB-JWT that does not cover the presented disclosures (sd_hash mismatch)', async () => {
    const f = fixture();
    const issuerKey = importEd25519PrivateKey(f.principal.secretKey);
    const sdjwt = await issuePcaSdJwt(f.pcActn, { issuerKey, keyBinding: {} });

    // Bind the KB-JWT over a 1-disclosure presentation, then splice extra disclosures back in.
    const bound = await present(sdjwt, ['action'], {
      keyBinding: { holderKey: importEd25519PrivateKey(f.agent.secretKey), audience: 'atlas-rs-prod' },
    });
    const kbJwt = bound.slice(bound.lastIndexOf('~') + 1);
    const fullIssued = await present(sdjwt, ['action', 'cap_chain']); // ends with '~'
    const spliced = fullIssued + kbJwt; // KB-JWT no longer matches this head

    const res = await verifyPcaSdJwt(spliced, {
      issuerKey: importEd25519PublicKey(f.principal.publicKey),
      expectedAudience: 'atlas-rs-prod',
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.reason).toMatch(/sd_hash/);
  });
});

describe('custom disclosable set', () => {
  it('keeps non-selected capability claims in the clear', async () => {
    const f = fixture();
    const issuerKey = importEd25519PrivateKey(f.principal.secretKey);
    const sdjwt = await issuePcaSdJwt(f.pcActn, { issuerKey, disclosable: ['sig'] });

    // only `sig` is behind a disclosure; everything else is a clear claim
    const segments = sdjwt.split('~');
    expect(segments.slice(1).filter((s) => s.length > 0).length).toBe(1);

    const res = await verifyPcaSdJwt(sdjwt, { issuerKey: importEd25519PublicKey(f.principal.publicKey) });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(Object.keys(res.disclosed)).toEqual(['sig']);
    // action is now a clear claim, still recovered into `claims`
    expect(res.claims.action).toEqual(f.pcActn.action);
    expect(res.claims.sig).toBe(f.pcActn.sig);
  });
});
