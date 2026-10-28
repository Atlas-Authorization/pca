/** 0.4.2 mutation kills: the authority requirement, the shape of a successful result, and the payment-mandate binding on hostile PCActn shapes. */
import { describe, expect, it } from 'vitest';
import {
  type Capability,
  type PCActn,
  type PlanNode,
  DEFAULT_RISK_POLICY,
  buildPCActn,
  encodeKey,
  generateKeyPair,
  mintGrant,
  paramsDigest,
  pcactnDigest,
} from '@atlasauth/pca';
import { type A2APaymentMandate, A2AAuthorityError, a2aPaymentMandateFromPca, attachPcaToA2ATask, pcaA2AMiddleware, verifyA2APaymentMandate, verifyA2ATask } from './index';

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
const PAY = { amount: 5, currency: 'USD' };
const plan: PlanNode[] = [{ id: 'pay-1', verb: 'purchase', resource: 'merchant/acme/cart/42', params_digest: paramsDigest(PAY), reversibility_class: 'reversible' }];
const FULL = {
  grant,
  hooks: { revocation: () => ({ enforced: true as const, ok: true }) },
  context: { plan, planAuthorized: true, budget: { B: 100, tau: NOW, asOf: NOW }, risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1 }, params: PAY },
};
const mk = (): PCActn => buildPCActn({ grant, chain: [grant], plan, nodeId: 'pay-1', params: PAY, counter: 1, signerSecret: A.secretKey, aud: AUD, now: NOW });
const bare = () => ({ id: 't', status: { state: 'submitted' } });

describe('A2AAuthorityError', () => {
  it('carries its code, name and the exact message', () => {
    const e = new A2AAuthorityError();
    expect(e.code).toBe('authority_required');
    expect(e.name).toBe('A2AAuthorityError');
    expect(e.message).toBe('pca-a2a: pass `grant` (from your store) or `expectedRootIssuer`; a chain is never its own authority');
    expect(e).toBeInstanceOf(Error);
  });
});

describe('an authority is required (a grant object or a non-empty expectedRootIssuer) before anything else is looked at', () => {
  const noProof = bare() as never;
  const bad: [string, unknown][] = [
    ['undefined options', undefined],
    ['no authority', { aud: AUD }],
    ['grant: null', { aud: AUD, grant: null }],
    ['grant: a string', { aud: AUD, grant: 'g' }],
    ['grant: a number', { aud: AUD, grant: 5 }],
    ['an empty expectedRootIssuer', { aud: AUD, expectedRootIssuer: '' }],
    ['a non-string expectedRootIssuer', { aud: AUD, expectedRootIssuer: 5 }],
  ];
  it.each(bad)('verifyA2ATask refuses %s with A2AAuthorityError, even with no proof attached', async (_n, opts) => {
    await expect(verifyA2ATask(noProof, opts as never)).rejects.toBeInstanceOf(A2AAuthorityError);
  });
  it('a grant object, or a non-empty expectedRootIssuer, is an authority', async () => {
    expect((await verifyA2ATask(noProof, { aud: AUD, grant })).reason).toBe('no proof-carrying action attached to this task');
    expect((await verifyA2ATask(noProof, { aud: AUD, expectedRootIssuer: 'x' })).reason).toBe('no proof-carrying action attached to this task');
  });
  it('the payment-mandate verifier checks it first as well', async () => {
    const p = mk();
    const m = a2aPaymentMandateFromPca(p, { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' } as never });
    await expect(verifyA2APaymentMandate(m, p, { aud: AUD } as never)).rejects.toBeInstanceOf(A2AAuthorityError);
    await expect(verifyA2APaymentMandate({} as never, p, { aud: AUD, grant: 5 } as never)).rejects.toBeInstanceOf(A2AAuthorityError);
  });
  it('the middleware factory requires one too (at construction)', () => {
    expect(() => pcaA2AMiddleware({ aud: AUD } as never)).toThrow(A2AAuthorityError);
  });
});

describe('a successful verification result', () => {
  it('has no reason key (neither on the result nor on the verdict it carries)', async () => {
    const r = await verifyA2ATask(attachPcaToA2ATask(bare() as never, mk()), { ...FULL, aud: AUD, now: NOW });
    expect(r.ok).toBe(true);
    expect(Object.keys(r.result ?? {})).not.toContain('reason');
  });
});

describe('verifyA2APaymentMandate on hostile PCActn / mandate shapes', () => {
  const OPTS = { ...FULL, aud: AUD, now: NOW };
  const mandateFor = (p: PCActn): A2APaymentMandate => a2aPaymentMandateFromPca(p, { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' } as never });
  /** A mandate bound (by digest) to `p2`, with every other x_pca field copied from the genuine PCActn. */
  const boundTo = (p2: unknown, over: Record<string, unknown> = {}): A2APaymentMandate => {
    const m = mandateFor(mk());
    return { ...m, credentialSubject: { ...m.credentialSubject, x_pca: { ...m.credentialSubject.x_pca, pcactn_digest: pcactnDigest(p2 as PCActn), ...over } } } as A2APaymentMandate;
  };
  const without = (k: string): PCActn => { const { [k]: _gone, ...rest } = mk() as unknown as Record<string, unknown>; void _gone; return rest as unknown as PCActn; };

  it('x_pca that is an array carrying pcactn_digest is not a binding record', async () => {
    const p = mk();
    const m = mandateFor(p);
    const arr = Object.assign([], { ...m.credentialSubject.x_pca });
    const bad = { ...m, credentialSubject: { ...m.credentialSubject, x_pca: arr } } as unknown as A2APaymentMandate;
    expect(await verifyA2APaymentMandate(bad, p, OPTS)).toStrictEqual({ ok: false, reason: 'payment mandate carries no x_pca binding', pcActn: p });
  });
  it('a PCActn with no action cannot be bound: a refusal naming the first bound field, never an exception', async () => {
    const p = without('action');
    const r = await verifyA2APaymentMandate(boundTo(p), p, OPTS);
    expect(r).toStrictEqual({ ok: false, reason: "payment mandate x_pca.verb is not the PCActn's", pcActn: p });
  });
  it('a PCActn with no capability chain has no leaf holder: x_pca.leaf_holder is not the PCActn\'s', async () => {
    const p = without('cap_chain');
    const r = await verifyA2APaymentMandate(boundTo(p), p, OPTS);
    expect(r).toStrictEqual({ ok: false, reason: "payment mandate x_pca.leaf_holder is not the PCActn's", pcActn: p });
  });
  it('an x_pca field that is absent while the PCActn side is absent too is still a mismatch', async () => {
    const p = without('cap_chain');
    const m = boundTo(p);
    const { leaf_holder: _l, ...noLeaf } = m.credentialSubject.x_pca as unknown as Record<string, unknown>;
    void _l;
    const bad = { ...m, credentialSubject: { ...m.credentialSubject, x_pca: noLeaf } } as unknown as A2APaymentMandate;
    expect((await verifyA2APaymentMandate(bad, p, OPTS)).reason).toBe("payment mandate x_pca.leaf_holder is not the PCActn's");
  });
  it('a non-string x_pca field never equals a non-string PCActn field', async () => {
    const p = { ...mk(), aud: 5 } as unknown as PCActn;
    const r = await verifyA2APaymentMandate(boundTo(p, { aud: 5 }), p, OPTS);
    expect(r.reason).toBe("payment mandate x_pca.aud is not the PCActn's");
  });
  it('the mandate verifier takes the params context as a function too', async () => {
    const p = mk();
    const m = mandateFor(p);
    const viaFn = await verifyA2APaymentMandate(m, p, { ...OPTS, context: (_p: PCActn) => ({ ...FULL.context }) } as never);
    const viaObj = await verifyA2APaymentMandate(m, p, OPTS);
    expect(viaObj.ok, viaObj.reason).toBe(true);
    expect(viaFn.ok, viaFn.reason).toBe(true);
    // the function receives the PCActn being verified
    let seen: unknown;
    await verifyA2APaymentMandate(m, p, { ...OPTS, context: (x: PCActn) => { seen = x; return { ...FULL.context }; } } as never);
    expect(seen).toBe(p);
  });
  it('the default required checks still apply on the mandate path (no revocation hook enforced: refused)', async () => {
    const p = mk();
    const m = mandateFor(p);
    const { hooks: _h, ...noHooks } = OPTS;
    void _h;
    expect((await verifyA2APaymentMandate(m, p, noHooks)).ok).toBe(false);
    expect((await verifyA2APaymentMandate(m, p, OPTS)).ok).toBe(true);
  });
  it('params_digest is required even when the caller lists other checks (or none): params that do not open the committed digest are refused', async () => {
    const p = mk();
    const m = mandateFor(p);
    const wrong = { ...OPTS, context: { ...FULL.context, params: { ...PAY, extra: 'x' } } };
    for (const requireChecks of [[], ['audience'], ['params_digest']]) {
      const r = await verifyA2APaymentMandate(m, p, { ...wrong, requireChecks });
      expect(r.ok, JSON.stringify(requireChecks)).toBe(false);
      expect(r.result?.checks.params_digest).toBe('fail');
    }
    expect((await verifyA2APaymentMandate(m, p, { ...OPTS, requireChecks: [] })).ok).toBe(true);
  });
  it('a missing params plaintext is a refusal (ok:false) with the exact reason', async () => {
    const p = mk();
    const { params: _p, ...ctx } = FULL.context;
    void _p;
    expect(await verifyA2APaymentMandate(mandateFor(p), p, { ...OPTS, context: ctx })).toStrictEqual({
      ok: false,
      reason: 'context.params (the PCActn params plaintext) is required to bind the payment mandate',
      pcActn: p,
    });
  });
  it('the params amount and currency must be OWN properties of the committed params (an inherited value is not committed)', async () => {
    const p = mk();
    const m = mandateFor(p);
    const withParams = (params: unknown) => ({ ...OPTS, context: { ...FULL.context, params } });
    const noAmount = 'the PCActn params carry no integer minor-unit amount to bind the mandate amount to';
    const noCurrency = 'the PCActn params carry no currency to bind the mandate currency to';
    expect((await verifyA2APaymentMandate(m, p, withParams(Object.create({ amount: 5, currency: 'USD' })))).reason).toBe(noAmount);
    expect((await verifyA2APaymentMandate(m, p, withParams(Object.assign(Object.create({ currency: 'USD' }), { amount: 5 })))).reason).toBe(noCurrency);
    expect((await verifyA2APaymentMandate(m, p, withParams({ amount: 5, currency: 5 }))).reason).toBe(noCurrency);
    expect((await verifyA2APaymentMandate(m, p, withParams({ amount: Number.POSITIVE_INFINITY, currency: 'USD' }))).reason).toBe(noAmount);
  });
});
