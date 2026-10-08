import { describe, expect, it } from 'vitest';
import { type AgentPassport, issuePassport } from '@atlasauth/pca';
import { exportJWK, generateKeyPair as joseGenerateKeyPair } from 'jose';
import {
  type AgentCard,
  type AgentFacts,
  AGENT_FACTS_CONTEXT,
  PCA_ATTESTOR_ID,
  WELL_KNOWN_AGENT_CARD_PATH,
  WELL_KNOWN_AGENT_FACTS_PATH,
  addAttestation,
  agentCardHandler,
  agentFactsHandler,
  buildAgentCard,
  issueAgentFacts,
  issueSignedAgentCard,
  toRegistryEntry,
  verifyAgentCard,
  verifyAgentFacts,
} from './index';

const NOW = 1_800_000_000_000;

// ---- a real PCA passport (via the core) -----------------------------------------------------------

const passport: AgentPassport = issuePassport({
  model_id: 'claude-opus-4-8',
  weights_digest: 'wd_abc',
  system_prompt_digest: 'sp_abc',
  tool_manifest_digest: 'tm_abc',
  operator: 'acme-corp',
  hardware_rooted: true,
  weights_measured: true,
  issued_at: NOW,
});

// ===================================================================================================
// 1. Signed Agent Card (A2A 1.0) — build + sign + verify
// ===================================================================================================

describe('signed agent card', () => {
  it('builds a card from a passport that points at the passport + live proof endpoint', () => {
    const card = buildAgentCard(passport, {
      name: 'Atlas Procurement Agent',
      description: 'Buys SaaS seats within a budget',
      url: 'https://agents.example.com/procure',
      version: '1.0.0',
      skills: [{ id: 'buy', name: 'Purchase' }],
      passportUri: 'https://agents.example.com/passport',
      pcaProofRef: { verificationEndpoint: 'https://atlasauth.net/v1/pca/verify', aud: 'atlas-instance-rs-1' },
    });
    expect(card.pcaPassport).toEqual({ id: passport.id, uri: 'https://agents.example.com/passport' });
    expect(card.pcaProof?.verificationEndpoint).toBe('https://atlasauth.net/v1/pca/verify');
    expect(card.signatures).toBeUndefined(); // not yet signed
  });

  it('signs a built card and verifies it, carrying the passport + proof ref', async () => {
    const { publicKey, privateKey } = await joseGenerateKeyPair('EdDSA');
    const card = buildAgentCard(passport, {
      name: 'Atlas Procurement Agent',
      url: 'https://agents.example.com/procure',
      pcaProofRef: { verificationEndpoint: 'https://atlasauth.net/v1/pca/verify', proofRef: 'pcactn_abc' },
    });
    const signed = await issueSignedAgentCard(card, privateKey);
    expect(signed.signatures?.length).toBe(1);

    const res = await verifyAgentCard(signed, { key: publicKey });
    expect(res.ok).toBe(true);
    expect(res.passportRef).toBe(passport.id);
    expect(res.passport).toEqual({ id: passport.id });
    expect(res.pcaProof?.verificationEndpoint).toBe('https://atlasauth.net/v1/pca/verify');
    expect(res.pcaProof?.proofRef).toBe('pcactn_abc');
  });

  it('verifies via a JWKS (kid-resolved)', async () => {
    const { publicKey, privateKey } = await joseGenerateKeyPair('EdDSA');
    const card = buildAgentCard(passport, { name: 'Agent' });
    const signed = await issueSignedAgentCard(card, privateKey, { kid: 'key-1' });
    const jwk = await exportJWK(publicKey);
    const res = await verifyAgentCard(signed, { jwks: { keys: [{ ...jwk, kid: 'key-1', alg: 'EdDSA' }] } });
    expect(res.ok).toBe(true);
    expect(res.passportRef).toBe(passport.id);
  });

  it('rejects a forged card (body mutated after signing)', async () => {
    const { publicKey, privateKey } = await joseGenerateKeyPair('EdDSA');
    const signed = await issueSignedAgentCard(buildAgentCard(passport, { name: 'Agent' }), privateKey);
    const forged: AgentCard = { ...signed, url: 'https://evil.example.com/pwn' };
    const res = await verifyAgentCard(forged, { key: publicKey });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/did not verify/);
  });

  it('rejects a mutated passport pointer (the whole card body is signed)', async () => {
    const { publicKey, privateKey } = await joseGenerateKeyPair('EdDSA');
    const signed = await issueSignedAgentCard(buildAgentCard(passport, { name: 'Agent' }), privateKey);
    const forged: AgentCard = { ...signed, pcaPassport: { id: 'pp_attacker' } };
    const res = await verifyAgentCard(forged, { key: publicKey });
    expect(res.ok).toBe(false);
  });

  it('rejects verification under the wrong key', async () => {
    const { privateKey } = await joseGenerateKeyPair('EdDSA');
    const { publicKey: otherPub } = await joseGenerateKeyPair('EdDSA');
    const signed = await issueSignedAgentCard(buildAgentCard(passport, { name: 'Agent' }), privateKey);
    expect((await verifyAgentCard(signed, { key: otherPub })).ok).toBe(false);
  });

  it('rejects an unsigned card (fail closed)', async () => {
    const { publicKey } = await joseGenerateKeyPair('EdDSA');
    const res = await verifyAgentCard(buildAgentCard(passport, { name: 'Agent' }), { key: publicKey });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/no signatures/);
  });

  it('rejects when no key or JWKS is supplied', async () => {
    const { privateKey } = await joseGenerateKeyPair('EdDSA');
    const signed = await issueSignedAgentCard(buildAgentCard(passport, { name: 'Agent' }), privateKey);
    expect((await verifyAgentCard(signed, {})).ok).toBe(false);
  });
});

// ===================================================================================================
// 2. AgentFacts — self-asserted vs third-party-attested
// ===================================================================================================

describe('AgentFacts attestation', () => {
  it('issues facts with a PCA attestation; verify marks attested vs self-asserted', async () => {
    const { publicKey, privateKey } = await joseGenerateKeyPair('EdDSA');
    const facts = await issueAgentFacts(passport, {
      selfAsserted: { marketingBlurb: 'the best agent', supportsRefunds: true, maxBudgetUsd: 5000 },
      attestorKey: privateKey,
      attests: { hardware_rooted: true, operator: 'acme-corp', maxBudgetUsd: 5000 },
      now: NOW,
      validUntil: new Date(NOW + 86_400_000).toISOString(),
    });
    expect(facts['@context']).toEqual(AGENT_FACTS_CONTEXT);
    expect(facts.id).toBe(passport.id);
    expect(facts.attestations).toHaveLength(1);
    expect(facts.attestations[0]?.issuer).toBe(PCA_ATTESTOR_ID);
    expect(facts.attestations[0]?.subject).toBe(passport.id);

    const res = await verifyAgentFacts(facts, { key: publicKey, now: NOW });
    expect(res.ok).toBe(true);
    expect(res.attestations[0]?.ok).toBe(true);
    // attested claims are backed by the third party:
    expect(res.attested).toEqual({ hardware_rooted: true, operator: 'acme-corp', maxBudgetUsd: 5000 });
    // self-asserted claims are echoed + flagged:
    expect(res.selfAsserted.marketingBlurb).toBe('the best agent');
    // provenance map: an attested claim wins over a self-asserted one of the same name
    expect(res.claims.maxBudgetUsd).toBe('attested');
    expect(res.claims.marketingBlurb).toBe('self-asserted');
    expect(res.claims.supportsRefunds).toBe('self-asserted');
    expect(res.claims.operator).toBe('attested');
  });

  it('fails closed on a FORGED attestation (attests block mutated after signing)', async () => {
    const { publicKey, privateKey } = await joseGenerateKeyPair('EdDSA');
    const facts = await issueAgentFacts(passport, {
      attestorKey: privateKey,
      attests: { hardware_rooted: true },
      now: NOW,
    });
    const att0 = facts.attestations[0];
    expect(att0).toBeDefined();
    const forged: AgentFacts = {
      ...facts,
      attestations: [{ ...att0!, attests: { hardware_rooted: true, operator: 'super-trusted-gov' } }],
    };
    const res = await verifyAgentFacts(forged, { key: publicKey, now: NOW });
    expect(res.ok).toBe(false);
    expect(res.attestations[0]?.ok).toBe(false);
    expect(res.attestations[0]?.reason).toMatch(/did not verify/);
    expect(res.attested).toEqual({}); // nothing is promoted to attested
  });

  it('fails closed under the wrong attestor key', async () => {
    const { privateKey } = await joseGenerateKeyPair('EdDSA');
    const { publicKey: otherPub } = await joseGenerateKeyPair('EdDSA');
    const facts = await issueAgentFacts(passport, { attestorKey: privateKey, attests: { x: 1 }, now: NOW });
    expect((await verifyAgentFacts(facts, { key: otherPub, now: NOW })).ok).toBe(false);
  });

  it('fails closed on an attestation about a DIFFERENT subject', async () => {
    const { publicKey, privateKey } = await joseGenerateKeyPair('EdDSA');
    const facts = await issueAgentFacts(passport, { attestorKey: privateKey, attests: { x: 1 }, now: NOW });
    const att0 = facts.attestations[0]!;
    const swapped: AgentFacts = { ...facts, id: 'did:other:agent', attestations: [att0] };
    const res = await verifyAgentFacts(swapped, { key: publicKey, now: NOW });
    expect(res.ok).toBe(false);
    expect(res.attestations[0]?.reason).toMatch(/does not match agent id/);
  });

  it('fails closed on an EXPIRED attestation', async () => {
    const { publicKey, privateKey } = await joseGenerateKeyPair('EdDSA');
    const facts = await issueAgentFacts(passport, {
      attestorKey: privateKey,
      attests: { x: 1 },
      now: NOW,
      validUntil: new Date(NOW + 1000).toISOString(),
    });
    const res = await verifyAgentFacts(facts, { key: publicKey, now: NOW + 5000 });
    expect(res.ok).toBe(false);
    expect(res.attestations[0]?.reason).toMatch(/expired/);
  });

  it('fails closed when a key is needed but none supplied', async () => {
    const { privateKey } = await joseGenerateKeyPair('EdDSA');
    const facts = await issueAgentFacts(passport, { attestorKey: privateKey, attests: { x: 1 }, now: NOW });
    expect((await verifyAgentFacts(facts, { now: NOW })).ok).toBe(false);
  });

  it('a doc with no attestations verifies but attests nothing; all claims self-asserted', async () => {
    const facts: AgentFacts = {
      '@context': AGENT_FACTS_CONTEXT,
      id: passport.id,
      type: 'AgentFacts',
      selfAsserted: { a: 1, b: 2 },
      attestations: [],
    };
    const res = await verifyAgentFacts(facts, {});
    expect(res.ok).toBe(true);
    expect(res.attested).toEqual({});
    expect(res.claims).toEqual({ a: 'self-asserted', b: 'self-asserted' });
  });

  it('supports multiple attestors via addAttestation', async () => {
    const a = await joseGenerateKeyPair('EdDSA');
    const b = await joseGenerateKeyPair('EdDSA');
    let facts = await issueAgentFacts(passport, {
      attestorKey: a.privateKey,
      attests: { hardware_rooted: true },
      attestorId: PCA_ATTESTOR_ID,
      kid: 'a',
      now: NOW,
    });
    facts = await addAttestation(facts, {
      attestorKey: b.privateKey,
      attests: { kyc_passed: true },
      attestorId: 'did:example:compliance',
      kid: 'b',
      now: NOW,
    });
    const jwkA = await exportJWK(a.publicKey);
    const jwkB = await exportJWK(b.publicKey);
    const res = await verifyAgentFacts(facts, {
      jwks: { keys: [{ ...jwkA, kid: 'a', alg: 'EdDSA' }, { ...jwkB, kid: 'b', alg: 'EdDSA' }] },
      now: NOW,
    });
    expect(res.ok).toBe(true);
    expect(res.attested).toEqual({ hardware_rooted: true, kyc_passed: true });
  });
});

// ===================================================================================================
// 3. Well-known hosting
// ===================================================================================================

describe('well-known hosting', () => {
  it('serves the signed card at the well-known path and nowhere else', async () => {
    const { privateKey } = await joseGenerateKeyPair('EdDSA');
    const signed = await issueSignedAgentCard(
      buildAgentCard(passport, { name: 'Agent', url: 'https://agents.example.com' }),
      privateKey,
    );
    const handler = agentCardHandler(signed);

    const hit = handler(WELL_KNOWN_AGENT_CARD_PATH);
    expect(hit?.status).toBe(200);
    expect(hit?.headers['content-type']).toBe('application/json');
    expect(JSON.parse(hit!.body)).toEqual(signed);
    // tolerates a query string:
    expect(handler(`${WELL_KNOWN_AGENT_CARD_PATH}?v=1`)?.status).toBe(200);
    // falls through on an unrelated path:
    expect(handler('/other')).toBeUndefined();
  });

  it('serves the AgentFacts doc at its well-known path', async () => {
    const { privateKey } = await joseGenerateKeyPair('EdDSA');
    const facts = await issueAgentFacts(passport, { attestorKey: privateKey, attests: { x: 1 }, now: NOW });
    const handler = agentFactsHandler(facts);
    const hit = handler(WELL_KNOWN_AGENT_FACTS_PATH);
    expect(hit?.status).toBe(200);
    expect(JSON.parse(hit!.body)).toEqual(facts);
    expect(handler(WELL_KNOWN_AGENT_CARD_PATH)).toBeUndefined();
  });
});

// ===================================================================================================
// 4. Registry entry
// ===================================================================================================

describe('toRegistryEntry', () => {
  it('shapes a well-formed registry entry splitting attested from self-asserted claims', async () => {
    const { privateKey } = await joseGenerateKeyPair('EdDSA');
    const signed = await issueSignedAgentCard(
      buildAgentCard(passport, {
        name: 'Atlas Procurement Agent',
        url: 'https://agents.example.com/procure',
        version: '1.0.0',
        skills: [{ id: 'buy', name: 'Purchase' }],
        pcaProofRef: { verificationEndpoint: 'https://atlasauth.net/v1/pca/verify' },
      }),
      privateKey,
    );
    const facts = await issueAgentFacts(passport, {
      selfAsserted: { marketingBlurb: 'the best', maxBudgetUsd: 5000 },
      attestorKey: privateKey,
      attests: { hardware_rooted: true, maxBudgetUsd: 5000 },
      now: NOW,
    });

    const entry = toRegistryEntry(signed, facts);
    expect(entry.id).toBe(passport.id);
    expect(entry.name).toBe('Atlas Procurement Agent');
    expect(entry.url).toBe('https://agents.example.com/procure');
    expect(entry.version).toBe('1.0.0');
    expect(entry.skills).toEqual([{ id: 'buy', name: 'Purchase' }]);
    expect(entry.passport).toEqual({ id: passport.id });
    expect(entry.pcaProof?.verificationEndpoint).toBe('https://atlasauth.net/v1/pca/verify');
    expect(entry.card).toBe(signed);
    expect(entry.facts).toBe(facts);
    expect(entry.agentCardUrl).toBe('https://agents.example.com/.well-known/agent-card.json');
    expect(entry.attestedClaims.sort()).toEqual(['hardware_rooted', 'maxBudgetUsd']);
    // maxBudgetUsd is attested, so it is NOT listed as self-asserted-only:
    expect(entry.selfAssertedClaims).toEqual(['marketingBlurb']);
  });
});
