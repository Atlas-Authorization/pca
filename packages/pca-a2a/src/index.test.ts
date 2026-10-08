import { describe, expect, it } from 'vitest';
import {
  type Capability,
  type CapabilityChain,
  type PCActn,
  type PlanNode,
  buildPCActn,
  delegate,
  encodeKey,
  generateKeyPair,
  mintRoot,
  pcactnDigest,
} from '@atlasauth/pca';
import { exportJWK, generateKeyPair as joseGenerateKeyPair } from 'jose';
import {
  type A2ATask,
  type AgentCard,
  PCA_A2A_EXTENSION_URI,
  a2aPaymentMandateFromPca,
  attachPcaToA2ATask,
  extractPca,
  issueSignedAgentCard,
  pcaA2AMiddleware,
  pcaBindingFromA2APaymentMandate,
  verifyA2APaymentMandate,
  verifyA2ATask,
  verifyAgentCard,
} from './index';

const NOW = 1_800_000_000_000;
const AUD = 'atlas-instance-rs-1';

// ---- real PCActn fixtures (built through the PCA core) --------------------------------------------

const P = generateKeyPair(); // principal
const A = generateKeyPair(); // agent (delegated-to leaf holder)

const grant: Capability = mintRoot({
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: encodeKey(A.publicKey),
  caveats: [{ type: 'ttl', secs: 3600 }],
});
const chain: CapabilityChain = [grant];

const plan: PlanNode[] = [
  { id: 'buy-1', verb: 'purchase', resource: 'merchant/acme/cart/42', reversibility_class: 'reversible' },
];

function makePcActn(overrides: Partial<Parameters<typeof buildPCActn>[0]> = {}): PCActn {
  return buildPCActn({
    grant,
    chain,
    plan,
    nodeId: 'buy-1',
    counter: 1,
    signerSecret: A.secretKey,
    aud: AUD,
    now: NOW,
    ...overrides,
  });
}

function bareTask(): A2ATask {
  return { id: 'task-1', status: { state: 'submitted' } };
}

// ===================================================================================================
// 1. Proof-carrying A2A tasks
// ===================================================================================================

describe('proof-carrying A2A tasks', () => {
  it('attaches a PCActn under the namespaced extension key and extracts it back', () => {
    const pcActn = makePcActn();
    const task = attachPcaToA2ATask(bareTask(), pcActn);
    expect(task.metadata?.[PCA_A2A_EXTENSION_URI]).toBeDefined();
    expect(extractPca(task)).toEqual(pcActn);
    // the input task is not mutated
    expect(bareTask().metadata).toBeUndefined();
  });

  it('verifies a well-formed proof on a task (pass)', async () => {
    const task = attachPcaToA2ATask(bareTask(), makePcActn());
    const res = await verifyA2ATask(task, { aud: AUD, now: NOW });
    expect(res.ok).toBe(true);
    expect(res.result?.allow).toBe(true);
    expect(res.result?.checks).toMatchObject({
      wire: 'pass',
      audience: 'pass',
      validity: 'pass',
      cap_chain: 'pass',
      plan_inclusion: 'pass',
      leaf_signature: 'pass',
    });
  });

  it('rejects a task with NO proof (fail closed)', async () => {
    const res = await verifyA2ATask(bareTask(), { aud: AUD, now: NOW });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/no proof-carrying action/);
  });

  it('rejects a TAMPERED proof (action mutated after signing)', async () => {
    const pcActn = makePcActn();
    const tampered: PCActn = { ...pcActn, action: { ...pcActn.action, resource: 'merchant/acme/cart/ALL' } };
    const task = attachPcaToA2ATask(bareTask(), tampered);
    const res = await verifyA2ATask(task, { aud: AUD, now: NOW });
    expect(res.ok).toBe(false);
    expect(res.result?.checks.leaf_signature).toBe('fail');
  });

  it('rejects a wrong-audience proof', async () => {
    const task = attachPcaToA2ATask(bareTask(), makePcActn());
    const res = await verifyA2ATask(task, { aud: 'some-other-instance', now: NOW });
    expect(res.ok).toBe(false);
    expect(res.result?.checks.audience).toBe('fail');
  });

  it('rejects an expired proof', async () => {
    const task = attachPcaToA2ATask(bareTask(), makePcActn());
    const res = await verifyA2ATask(task, { aud: AUD, now: NOW + 3_600_000 * 2 });
    expect(res.ok).toBe(false);
    expect(res.result?.checks.validity).toBe('fail');
  });

  it('pins the principal via expectedRootIssuer', async () => {
    const task = attachPcaToA2ATask(bareTask(), makePcActn());
    const good = await verifyA2ATask(task, { aud: AUD, now: NOW, expectedRootIssuer: encodeKey(P.publicKey) });
    expect(good.ok).toBe(true);
    const bad = await verifyA2ATask(task, { aud: AUD, now: NOW, expectedRootIssuer: encodeKey(generateKeyPair().publicKey) });
    expect(bad.ok).toBe(false);
    expect(bad.reason).toMatch(/expected principal/);
  });

  it('extracts a proof carried on the status message when absent from task metadata', async () => {
    const pcActn = makePcActn();
    const task: A2ATask = {
      id: 'task-2',
      status: { state: 'working', message: { role: 'user', parts: [], metadata: { [PCA_A2A_EXTENSION_URI]: pcActn } } },
    };
    expect(extractPca(task)).toEqual(pcActn);
    const res = await verifyA2ATask(task, { aud: AUD, now: NOW });
    expect(res.ok).toBe(true);
  });
});

describe('pcaA2AMiddleware', () => {
  it('require:true rejects a task with no proof, allows a valid one', async () => {
    const guard = pcaA2AMiddleware({ require: true, aud: AUD, now: NOW });
    expect((await guard(bareTask())).ok).toBe(false);
    expect((await guard(attachPcaToA2ATask(bareTask(), makePcActn()))).ok).toBe(true);
  });

  it('require:false allows a proofless task but still fails closed on a tampered proof', async () => {
    const guard = pcaA2AMiddleware({ require: false, aud: AUD, now: NOW });
    expect((await guard(bareTask())).ok).toBe(true);
    const pcActn = makePcActn();
    const tampered: PCActn = { ...pcActn, counter: pcActn.counter + 999 };
    expect((await guard(attachPcaToA2ATask(bareTask(), tampered))).ok).toBe(false);
  });

  it('defaults to require:true', async () => {
    const guard = pcaA2AMiddleware({ aud: AUD, now: NOW });
    expect((await guard(bareTask())).ok).toBe(false);
  });
});

// ===================================================================================================
// 2. Signed Agent Cards
// ===================================================================================================

describe('signed agent cards', () => {
  const baseCard: AgentCard = {
    name: 'Atlas Procurement Agent',
    description: 'Buys SaaS seats within a budget',
    url: 'https://agents.example.com/procure',
    version: '1.0.0',
  };

  it('issues a card embedding the PCA passport reference and verifies it', async () => {
    const { publicKey, privateKey } = await joseGenerateKeyPair('EdDSA');
    const signed = await issueSignedAgentCard(baseCard, privateKey, { passport: { id: 'pp_abc123', uri: 'https://agents.example.com/passport' } });
    expect(signed.pcaPassport).toEqual({ id: 'pp_abc123', uri: 'https://agents.example.com/passport' });
    expect(signed.signatures?.length).toBe(1);

    const res = await verifyAgentCard(signed, { key: publicKey });
    expect(res.ok).toBe(true);
    expect(res.passportRef).toBe('pp_abc123');
    expect(res.passport).toEqual({ id: 'pp_abc123', uri: 'https://agents.example.com/passport' });
  });

  it('verifies via a JWKS (kid-resolved)', async () => {
    const { publicKey, privateKey } = await joseGenerateKeyPair('EdDSA');
    const signed = await issueSignedAgentCard(baseCard, privateKey, { passport: { id: 'pp_jwks' }, kid: 'key-1' });
    const jwk = await exportJWK(publicKey);
    const res = await verifyAgentCard(signed, { jwks: { keys: [{ ...jwk, kid: 'key-1', alg: 'EdDSA' }] } });
    expect(res.ok).toBe(true);
    expect(res.passportRef).toBe('pp_jwks');
  });

  it('rejects a forged card (body mutated after signing)', async () => {
    const { publicKey, privateKey } = await joseGenerateKeyPair('EdDSA');
    const signed = await issueSignedAgentCard(baseCard, privateKey, { passport: { id: 'pp_x' } });
    const forged: AgentCard = { ...signed, url: 'https://evil.example.com/pwn' };
    const res = await verifyAgentCard(forged, { key: publicKey });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/did not verify/);
  });

  it('rejects a tampered signature value', async () => {
    const { publicKey, privateKey } = await joseGenerateKeyPair('EdDSA');
    const signed = await issueSignedAgentCard(baseCard, privateKey, { passport: { id: 'pp_x' } });
    const sig0 = signed.signatures?.[0];
    expect(sig0).toBeDefined();
    const flipped = sig0!.signature.slice(0, -2) + (sig0!.signature.endsWith('AA') ? 'BB' : 'AA');
    const forged: AgentCard = { ...signed, signatures: [{ ...sig0!, signature: flipped }] };
    const res = await verifyAgentCard(forged, { key: publicKey });
    expect(res.ok).toBe(false);
  });

  it('rejects verification under the wrong key', async () => {
    const { privateKey } = await joseGenerateKeyPair('EdDSA');
    const { publicKey: otherPub } = await joseGenerateKeyPair('EdDSA');
    const signed = await issueSignedAgentCard(baseCard, privateKey, { passport: { id: 'pp_x' } });
    const res = await verifyAgentCard(signed, { key: otherPub });
    expect(res.ok).toBe(false);
  });

  it('rejects an unsigned card (fail closed)', async () => {
    const { publicKey } = await joseGenerateKeyPair('EdDSA');
    const res = await verifyAgentCard(baseCard, { key: publicKey });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/no signatures/);
  });
});

// ===================================================================================================
// 3. AP2 payment profile
// ===================================================================================================

describe('AP2 payment profile', () => {
  it('maps a PCActn to an AP2 payment mandate and round-trips the binding', () => {
    const pcActn = makePcActn();
    const mandate = a2aPaymentMandateFromPca(pcActn, {
      amount: { currency: 'USD', value: 120 },
      paymentMethod: { type: 'card', display: 'Visa ••4242' },
      merchant: 'acme',
      humanPresent: true,
    });
    expect(mandate.type).toEqual(['VerifiableCredential', 'PaymentMandate']);
    expect(mandate.issuer).toBe(encodeKey(A.publicKey)); // defaults to the PCActn leaf holder
    expect(mandate.credentialSubject.amount).toEqual({ currency: 'USD', value: 120 });
    expect(mandate.credentialSubject.human_present).toBe(true);
    expect(mandate.credentialSubject.merchant).toBe('acme');

    const binding = pcaBindingFromA2APaymentMandate(mandate);
    expect(binding.pcactn_digest).toBe(pcactnDigest(pcActn));
    expect(binding.aud).toBe(AUD);
    expect(binding.verb).toBe('purchase');
    expect(binding.resource).toBe('merchant/acme/cart/42');
    expect(binding.params_digest).toBe(pcActn.action.params_digest);
    expect(binding.grant_ref).toBe(grant.id);
    expect(binding.leaf_holder).toBe(encodeKey(A.publicKey));
  });

  it('defaults human_present to false for an agent-only (no-threshold) PCActn', () => {
    const mandate = a2aPaymentMandateFromPca(makePcActn(), {
      amount: { currency: 'USD', value: 10 },
      paymentMethod: { type: 'card' },
    });
    expect(mandate.credentialSubject.human_present).toBe(false);
  });

  it('verifies a mandate bound to a valid PCActn', async () => {
    const pcActn = makePcActn();
    const mandate = a2aPaymentMandateFromPca(pcActn, { amount: { currency: 'USD', value: 50 }, paymentMethod: { type: 'card' } });
    const res = await verifyA2APaymentMandate(mandate, pcActn, { aud: AUD, now: NOW });
    expect(res.ok).toBe(true);
  });

  it('rejects a mandate whose binding does not match the supplied PCActn', async () => {
    const pcActn = makePcActn();
    const mandate = a2aPaymentMandateFromPca(pcActn, { amount: { currency: 'USD', value: 50 }, paymentMethod: { type: 'card' } });
    const otherPcActn = makePcActn({ counter: 2 }); // a different proof ⇒ different digest
    const res = await verifyA2APaymentMandate(mandate, otherPcActn, { aud: AUD, now: NOW });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/pcactn_digest mismatch/);
  });

  it('rejects a mandate when the bound PCActn itself fails to verify (wrong audience)', async () => {
    const pcActn = makePcActn();
    const mandate = a2aPaymentMandateFromPca(pcActn, { amount: { currency: 'USD', value: 50 }, paymentMethod: { type: 'card' } });
    const res = await verifyA2APaymentMandate(mandate, pcActn, { aud: 'wrong-instance', now: NOW });
    expect(res.ok).toBe(false);
    expect(res.result?.checks.audience).toBe('fail');
  });

  it('uses a delegated sub-agent leaf holder as the default issuer', () => {
    const S = generateKeyPair();
    // Build a proof on a 2-hop chain (principal -> A -> S) where S is the acting leaf.
    const sub = delegate(grant, encodeKey(S.publicKey), [], A.secretKey);
    const pcActn = buildPCActn({
      grant,
      chain: [grant, sub],
      plan,
      nodeId: 'buy-1',
      counter: 1,
      signerSecret: S.secretKey,
      aud: AUD,
      now: NOW,
    });
    const mandate = a2aPaymentMandateFromPca(pcActn, { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' } });
    expect(mandate.issuer).toBe(encodeKey(S.publicKey));
    expect(mandate.credentialSubject.x_pca.leaf_holder).toBe(encodeKey(S.publicKey));
  });
});
