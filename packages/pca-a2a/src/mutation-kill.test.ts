/** Mutation-kill tests for pca-a2a: extraction order, fail-closed reasons, key forms, header contents, mandate shape. */
import { describe, expect, it } from 'vitest';
import {
  type Capability,
  type PCActn,
  type PlanNode,
  buildPCActn,
  canonicalBytes,
  encodeKey,
  generateKeyPair,
  mintRoot,
  mintGrant,
  DEFAULT_RISK_POLICY,
  pcactnDigest,
} from '@atlasauth/pca';
import { FlattenedSign, exportJWK, generateKeyPair as joseKeys } from 'jose';
import {
  type A2AMessage,
  type A2ATask,
  type AgentCard,
  A2A_AP2_CONTEXT,
  PCA_A2A_EXTENSION_URI,
  a2aPaymentMandateFromPca,
  attachPcaToA2AMessage,
  attachPcaToA2ATask,
  extractPca,
  extractPcaFromMessage,
  issueSignedAgentCard,
  pcaA2AMiddleware,
  verifyA2APaymentMandate,
  verifyA2ATask,
  verifyAgentCard,
} from './index';

const NOW = 1_800_000_000_000;
const AUD = 'atlas-instance-rs-1';
const P = generateKeyPair();
const A = generateKeyPair();
const grant: Capability = mintGrant({
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: encodeKey(A.publicKey),
  goal: 'buy the cart',
  envelope: { predicates: [{ verb: 'purchase', resource: '*' }], caveats: [{ type: 'expires', at: NOW + 3_600_000 }], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
}).grant;
const plan: PlanNode[] = [{ id: 'buy-1', verb: 'purchase', resource: 'merchant/acme/cart/42', reversibility_class: 'reversible' }];

/** The resource server's authority + view for the full verifier: the stored grant, revocation, its plan, a budget, low risk. */
const FULL = {
  grant,
  hooks: { revocation: () => ({ enforced: true as const, ok: true }) },
  context: { plan, planAuthorized: true, budget: { B: 100, tau: NOW, asOf: NOW }, risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1 } },
};
const mk = (counter = 1): PCActn =>
  buildPCActn({ grant, chain: [grant], plan, nodeId: 'buy-1', counter, signerSecret: A.secretKey, aud: AUD, now: NOW });
const hdr = (s: { protected: string }): Record<string, unknown> => JSON.parse(Buffer.from(s.protected, 'base64url').toString('utf8'));
const bare = (): A2ATask => ({ id: 't', status: { state: 'submitted' } });
const msgWith = (p: unknown): A2AMessage => ({ role: 'user', parts: [], metadata: { [PCA_A2A_EXTENSION_URI]: p } });

describe('attach / extract', () => {
  it('attach merges into existing metadata and does not mutate the input', () => {
    const p = mk();
    const task: A2ATask = { ...bare(), metadata: { keep: 1 } };
    const out = attachPcaToA2ATask(task, p);
    expect(out).toStrictEqual({ ...task, metadata: { keep: 1, [PCA_A2A_EXTENSION_URI]: p } });
    expect(task.metadata).toStrictEqual({ keep: 1 });
    const m: A2AMessage = { role: 'agent', parts: [], metadata: { k: 2 } };
    expect(attachPcaToA2AMessage(m, p)).toStrictEqual({ role: 'agent', parts: [], metadata: { k: 2, [PCA_A2A_EXTENSION_URI]: p } });
    expect(attachPcaToA2AMessage({ role: 'agent', parts: [] }, p)).toStrictEqual({ role: 'agent', parts: [], metadata: { [PCA_A2A_EXTENSION_URI]: p } });
    expect(extractPcaFromMessage(attachPcaToA2AMessage(m, p))).toBe(p);
  });
  it('only a plain object counts as a carried PCActn', () => {
    for (const bad of [null, [], 'x', 5, true, undefined]) {
      expect(extractPcaFromMessage(msgWith(bad))).toBeUndefined();
    }
    expect(extractPcaFromMessage({ role: 'user', parts: [] })).toBeUndefined();
    expect(extractPcaFromMessage(msgWith({ a: 1 }))).toStrictEqual({ a: 1 });
  });
  it('lookup order: task metadata, status message, then history newest first', () => {
    const t = { id: 't', metadata: { [PCA_A2A_EXTENSION_URI]: { w: 'task' } }, status: { state: 's', message: msgWith({ w: 'status' }) }, history: [msgWith({ w: 'h0' }), msgWith({ w: 'h1' })] } as A2ATask;
    expect(extractPca(t)).toStrictEqual({ w: 'task' });
    expect(extractPca({ ...t, metadata: undefined })).toStrictEqual({ w: 'status' });
    expect(extractPca({ ...t, metadata: undefined, status: { state: 's' } })).toStrictEqual({ w: 'h1' });
    expect(extractPca({ ...t, metadata: undefined, status: { state: 's', message: { role: 'user', parts: [] } } })).toStrictEqual({ w: 'h1' });
    expect(extractPca({ ...t, metadata: undefined, status: { state: 's' }, history: [msgWith({ w: 'h0' }), { role: 'user', parts: [] }] })).toStrictEqual({ w: 'h0' });
    expect(extractPca({ ...t, metadata: undefined, status: { state: 's' }, history: [msgWith({ w: 'h0' }), undefined as never] })).toStrictEqual({ w: 'h0' });
    expect(extractPca({ ...t, metadata: undefined, status: { state: 's' }, history: [undefined as never, msgWith({ w: 'h1' })] })).toStrictEqual({ w: 'h1' });
    expect(extractPca({ ...t, metadata: undefined, status: { state: 's' }, history: [msgWith({ w: 'only' })] })).toStrictEqual({ w: 'only' });
    expect(extractPca({ ...t, metadata: undefined, status: { state: 's' }, history: [] })).toBeUndefined();
    expect(extractPca({ ...t, metadata: undefined, status: { state: 's' }, history: undefined })).toBeUndefined();
    expect(extractPca({ ...t, metadata: undefined, status: { state: 's' }, history: [{ role: 'user', parts: [] }] })).toBeUndefined();
  });
});

describe('verifyA2ATask / middleware reasons', () => {
  it('no proof: exact result', async () => {
    expect(await verifyA2ATask(bare(), { ...FULL, aud: AUD, now: NOW })).toStrictEqual({ ok: false, reason: 'no proof-carrying action attached to this task' });
    expect(await pcaA2AMiddleware({ ...FULL, aud: AUD, now: NOW })(bare())).toStrictEqual({ ok: false, reason: 'proof-carrying action required but none attached to task' });
    expect(await pcaA2AMiddleware({ ...FULL, aud: AUD, now: NOW, require: true })(bare())).toStrictEqual({ ok: false, reason: 'proof-carrying action required but none attached to task' });
    expect(await pcaA2AMiddleware({ ...FULL, aud: AUD, now: NOW, require: false })(bare())).toStrictEqual({ ok: true });
  });
  it('a chain-less PCActn is refused with the exact result (empty, missing)', async () => {
    for (const cap_chain of [[], undefined]) {
      const p = { ...mk(), cap_chain } as unknown as PCActn;
      const t = attachPcaToA2ATask(bare(), p);
      expect(await verifyA2ATask(t, { ...FULL, aud: AUD, now: NOW })).toStrictEqual({ ok: false, reason: 'PCActn carries no capability chain', pcActn: p });
    }
  });
  it('success and failure shapes; the failure reason is the core reason', async () => {
    const p = mk();
    const ok = await verifyA2ATask(attachPcaToA2ATask(bare(), p), { ...FULL, aud: AUD, now: NOW });
    expect(ok.ok).toBe(true);
    expect(ok.pcActn).toBe(p);
    expect('reason' in ok).toBe(false);
    const bad = await verifyA2ATask(attachPcaToA2ATask(bare(), p), { ...FULL, aud: 'other', now: NOW });
    expect(bad.ok).toBe(false);
    expect(bad.reason).toBe(bad.result!.reason);
    expect(bad.reason).toMatch(/audience/);
    expect(bad.pcActn).toBe(p);
    // the mismatching root issuer result is exact
    const pin = await verifyA2ATask(attachPcaToA2ATask(bare(), p), { ...FULL, aud: AUD, now: NOW, expectedRootIssuer: 'zzz' });
    expect(pin).toStrictEqual({ ok: false, reason: 'chain root issuer does not match the expected principal', pcActn: p });
  });
  it('now defaults to the wall clock and an explicit grant is the trust anchor', async () => {
    const p = mk();
    // wall clock is far past NOW + 1h: expired
    const r = await verifyA2ATask(attachPcaToA2ATask(bare(), p), { ...FULL, aud: AUD });
    expect(r.ok).toBe(false);
    expect(r.result?.checks.validity).toBe('fail');
    const other = mintRoot({ principalSecret: generateKeyPair().secretKey, principalPublic: encodeKey(generateKeyPair().publicKey), holder: encodeKey(A.publicKey), caveats: [] });
    const g = await verifyA2ATask(attachPcaToA2ATask(bare(), p), { ...FULL, aud: AUD, now: NOW, grant: other });
    expect(g.ok).toBe(false);
  });
  it('require:false still rejects a present-but-bad proof', async () => {
    const t = attachPcaToA2ATask(bare(), mk());
    expect((await pcaA2AMiddleware({ ...FULL, aud: 'x', now: NOW, require: false })(t)).ok).toBe(false);
    expect((await pcaA2AMiddleware({ ...FULL, aud: AUD, now: NOW, require: false })(t)).ok).toBe(true);
  });
});

describe('agent card keys and headers', () => {
  it('private/public JWK round trip with default alg; header contents', async () => {
    const { publicKey, privateKey } = await joseKeys('EdDSA', { extractable: true });
    const card: AgentCard = { name: 'n' };
    const s = await issueSignedAgentCard(card, await exportJWK(privateKey));
    expect(hdr(s.signatures![0]!)).toStrictEqual({ alg: 'EdDSA', b64: false, crit: ['b64'] });
    expect((await verifyAgentCard(s, { key: await exportJWK(publicKey) })).ok).toBe(true);
    const k = await issueSignedAgentCard(card, privateKey, { kid: 'k1', passport: { id: 'P' } });
    expect(hdr(k.signatures![0]!)).toStrictEqual({ alg: 'EdDSA', b64: false, crit: ['b64'], kid: 'k1', pca_passport: 'P' });
    expect(Object.keys(k.signatures![0]!).sort()).toStrictEqual(['protected', 'signature']);
  });
  it('RSA JWK needs the explicit alg on verify', async () => {
    const { publicKey, privateKey } = await joseKeys('RS256', { extractable: true });
    const s = await issueSignedAgentCard({ name: 'n' }, privateKey, { alg: 'RS256' });
    expect(hdr(s.signatures![0]!).alg).toBe('RS256');
    expect((await verifyAgentCard(s, { key: await exportJWK(publicKey), alg: 'RS256' })).ok).toBe(true);
  });
  it('CryptoKey and raw secrets are passed through', async () => {
    const { publicKey, privateKey } = await joseKeys('EdDSA');
    expect((await verifyAgentCard(await issueSignedAgentCard({ name: 'n' }, privateKey), { key: publicKey })).ok).toBe(true);
    const secret = new Uint8Array(32).fill(3);
    expect((await verifyAgentCard(await issueSignedAgentCard({ name: 'n' }, secret, { alg: 'HS256' }), { key: secret })).ok).toBe(true);
  });
  it('null / string / number / kty-less object keys are not JWKs', async () => {
    const { privateKey } = await joseKeys('EdDSA');
    const s = await issueSignedAgentCard({ name: 'n' }, privateKey);
    for (const k of [null, 'abc', 5, { crv: 'Ed25519' }]) {
      const r = await verifyAgentCard(s, { key: k as never });
      expect(r.ok).toBe(false);
      expect(r.reason).toMatch(/^signature 0 did not verify: /);
    }
  });
  it('key resolution reasons', async () => {
    const { privateKey } = await joseKeys('EdDSA');
    const s = await issueSignedAgentCard({ name: 'n' }, privateKey);
    expect(await verifyAgentCard(s, {})).toStrictEqual({ ok: false, reason: 'no verification key or JWKS supplied' });
    const r = await verifyAgentCard(s, { key: { kty: 'bogus' } as never });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^could not resolve verification key: .{4,}/);
  });
  it('passport embedding', async () => {
    const { privateKey } = await joseKeys('EdDSA');
    const bareCard: AgentCard = { name: 'n' };
    expect((await issueSignedAgentCard(bareCard, privateKey, { passport: { id: 'P1' } })).pcaPassport).toStrictEqual({ id: 'P1' });
    expect((await issueSignedAgentCard(bareCard, privateKey, { passport: { id: 'P2', uri: 'U' } })).pcaPassport).toStrictEqual({ id: 'P2', uri: 'U' });
    expect((await issueSignedAgentCard(bareCard, privateKey, { passport: { id: 'P3', uri: undefined } })).pcaPassport).toStrictEqual({ id: 'P3' });
    const own = await issueSignedAgentCard({ name: 'n', pcaPassport: { id: 'OWN' } }, privateKey);
    expect(hdr(own.signatures![0]!).pca_passport).toBe('OWN');
    const none = await issueSignedAgentCard(bareCard, privateKey);
    expect('pcaPassport' in none).toBe(false);
    expect('pca_passport' in hdr(none.signatures![0]!)).toBe(false);
  });
  it('verification outcomes: shapes, empty list, malformed members, tamper message', async () => {
    const { publicKey, privateKey } = await joseKeys('EdDSA');
    const s = await issueSignedAgentCard({ name: 'n' }, privateKey);
    expect(await verifyAgentCard(s, { key: publicKey })).toStrictEqual({ ok: true });
    const withP = await issueSignedAgentCard({ name: 'n' }, privateKey, { passport: { id: 'P' } });
    expect(await verifyAgentCard(withP, { key: publicKey })).toStrictEqual({ ok: true, passportRef: 'P', passport: { id: 'P' } });
    for (const signatures of [[], undefined, 'x' as never]) {
      expect(await verifyAgentCard({ name: 'n', signatures }, { key: publicKey })).toStrictEqual({ ok: false, reason: 'agent card carries no signatures' });
    }
    const good = s.signatures![0]!;
    for (const bad of [undefined, { protected: 5, signature: good.signature }, { protected: good.protected, signature: 5 }, { protected: 5, signature: 5 }]) {
      expect(await verifyAgentCard({ ...s, signatures: [bad as never] }, { key: publicKey })).toStrictEqual({ ok: false, reason: 'signature 0 is malformed' });
    }
    expect(await verifyAgentCard({ ...s, name: 'evil' }, { key: publicKey })).toStrictEqual({ ok: false, reason: 'signature 0 did not verify: signature verification failed' });
    expect((await verifyAgentCard({ ...s, signatures: [good, { protected: good.protected, signature: 'AAAA' }] }, { key: publicKey })).reason).toMatch(/^signature 1 did not verify: .+/);
  });
  it('the first string pca_passport wins; non-strings are ignored', async () => {
    const { publicKey, privateKey } = await joseKeys('EdDSA');
    const base: AgentCard = { name: 'n' };
    const { signatures: _s, ...rest } = base;
    void _s;
    const sign = async (extra: Record<string, unknown>) => {
      const j = await new FlattenedSign(canonicalBytes(rest)).setProtectedHeader({ alg: 'EdDSA', b64: false, crit: ['b64'], ...extra }).sign(privateKey);
      return { protected: j.protected!, signature: j.signature };
    };
    const num = await sign({ pca_passport: 123 });
    const none = await sign({});
    const b = await sign({ pca_passport: 'B' });
    const c = await sign({ pca_passport: 'C' });
    expect((await verifyAgentCard({ ...base, signatures: [num, b, c] }, { key: publicKey })).passportRef).toBe('B');
    expect((await verifyAgentCard({ ...base, signatures: [b, c] }, { key: publicKey })).passportRef).toBe('B');
    expect((await verifyAgentCard({ ...base, signatures: [none, b] }, { key: publicKey })).passportRef).toBe('B');
    expect('passportRef' in (await verifyAgentCard({ ...base, signatures: [num, none] }, { key: publicKey }))).toBe(false);
  });
  it('JWKS verification', async () => {
    const { publicKey, privateKey } = await joseKeys('EdDSA', { extractable: true });
    const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'EdDSA' };
    const s = await issueSignedAgentCard({ name: 'n' }, privateKey, { kid: 'k1' });
    expect((await verifyAgentCard(s, { jwks: { keys: [jwk] } })).ok).toBe(true);
    expect((await verifyAgentCard(s, { jwks: { keys: [] } })).ok).toBe(false);
  });
});

describe('payment mandate', () => {
  const amount = { currency: 'USD', value: 5 };
  it('exact shape, defaults and copies', () => {
    const p = mk();
    const method = { type: 'card', display: 'V' };
    const m = a2aPaymentMandateFromPca(p, { amount, paymentMethod: method, now: NOW });
    expect(m).toStrictEqual({
      '@context': A2A_AP2_CONTEXT,
      type: ['VerifiableCredential', 'PaymentMandate'],
      issuer: encodeKey(A.publicKey),
      issuanceDate: new Date(NOW).toISOString(),
      credentialSubject: {
        amount: { currency: 'USD', value: 5 },
        payment_method: { type: 'card', display: 'V' },
        human_present: false,
        x_pca: {
          pcactn_digest: pcactnDigest(p),
          aud: AUD,
          verb: 'purchase',
          resource: 'merchant/acme/cart/42',
          params_digest: p.action.params_digest,
          grant_ref: grant.id,
          leaf_holder: encodeKey(A.publicKey),
        },
      },
    });
    expect(m.credentialSubject.amount).not.toBe(amount);
    expect(m.credentialSubject.payment_method).not.toBe(method);
    expect('merchant' in m.credentialSubject).toBe(false);
    expect(a2aPaymentMandateFromPca(p, { amount, paymentMethod: method, merchant: 'acme', now: NOW }).credentialSubject.merchant).toBe('acme');
  });
  it('issuerPublic overrides the issuer but never the leaf holder; humanPresent is honoured', () => {
    const m = a2aPaymentMandateFromPca(mk(), { amount, paymentMethod: { type: 'c' }, issuerPublic: 'ISS', humanPresent: true });
    expect(m.issuer).toBe('ISS');
    expect(m.credentialSubject.x_pca.leaf_holder).toBe(encodeKey(A.publicKey));
    expect(m.credentialSubject.human_present).toBe(true);
    expect(Math.abs(Date.parse(m.issuanceDate) - Date.now())).toBeLessThan(120_000);
  });
  it('without a chain the issuer must be supplied; the leaf falls back to it', () => {
    const noChain = { ...mk(), cap_chain: [] } as unknown as PCActn;
    expect(() => a2aPaymentMandateFromPca(noChain, { amount, paymentMethod: { type: 'c' } })).toThrow('a2aPaymentMandateFromPca: no issuerPublic given and the PCActn has no capability chain');
    const m = a2aPaymentMandateFromPca(noChain, { amount, paymentMethod: { type: 'c' }, issuerPublic: 'ISS' });
    expect(m.credentialSubject.x_pca.leaf_holder).toBe('ISS');
    // a missing chain is tolerated by the leaf lookup (the digest is what then refuses the malformed proof)
    const undef = { ...mk(), cap_chain: undefined } as unknown as PCActn;
    expect(() => a2aPaymentMandateFromPca(undef, { amount, paymentMethod: { type: 'c' }, issuerPublic: 'ISS' })).toThrow(/canonicalize/);
    const hole = { ...mk(), cap_chain: [null] } as unknown as PCActn;
    expect(a2aPaymentMandateFromPca(hole, { amount, paymentMethod: { type: 'c' }, issuerPublic: 'ISS' }).credentialSubject.x_pca.leaf_holder).toBe('ISS');
  });
  it('an unverifiable human signer set yields false instead of throwing', () => {
    const m = a2aPaymentMandateFromPca(mk(), { amount, paymentMethod: { type: 'c' }, humanSignerSet: [null as never] });
    expect(m.credentialSubject.human_present).toBe(false);
  });
  it('verify: exact mismatch result and pass-through of the core verdict', async () => {
    const p = mk();
    const m = a2aPaymentMandateFromPca(p, { amount, paymentMethod: { type: 'c' } });
    const other = mk(2);
    expect(await verifyA2APaymentMandate(m, other, { ...FULL, aud: AUD, now: NOW })).toStrictEqual({
      ok: false,
      reason: 'payment mandate is not bound to this PCActn (pcactn_digest mismatch)',
      pcActn: other,
    });
    const ok = await verifyA2APaymentMandate(m, p, { ...FULL, aud: AUD, now: NOW });
    expect(ok.ok).toBe(true);
    expect(ok.pcActn).toBe(p);
  });
});
