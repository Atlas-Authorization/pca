/** Mutation-kill suite for chain.ts: issuance wire shape, hop-by-hop refusal reasons, time boundaries, purchase cross-checks. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  Ap2Error,
  disclosureBuilder,
  generateAp2KeyPair,
  issueOpenCheckoutMandate,
  issueOpenPaymentMandate,
  issuerJwtHashOf,
  openCheckoutMandateProblems,
  openPaymentMandateProblems,
  parseSdJwtHop,
  presentClosedCheckout,
  presentClosedPayment,
  processDisclosures,
  sdDigest,
  sdHashOf,
  signJwtEs256,
  signSdJwt,
  splitChain,
  verifyCheckoutChain,
  verifyKbHop,
  verifyDelegationChain,
  verifyPaymentChain,
  verifyPurchase,
  type Ap2KeyPair,
  type CheckoutConstraint,
  type Json,
  type JsonObject,
  type Merchant,
  type PaymentConstraint,
  type SdAlg,
} from './index';
import { NOW_S } from './testkit';

const M1: Merchant = { id: 'm1', name: 'Merchant One', website: 'https://m1.example' };
const M2: Merchant = { id: 'm2', name: 'Merchant Two' };
const AUD = 'aud-1';
const NONCE = 'nonce-1';
const NOW = NOW_S + 10;

afterEach(() => vi.useRealTimers());

interface Keys {
  issuer: Ap2KeyPair;
  agent: Ap2KeyPair;
  merchant: Ap2KeyPair;
}
const keys = (): Keys => ({ issuer: generateAp2KeyPair('iss-kid'), agent: generateAp2KeyPair(), merchant: generateAp2KeyPair('mk-kid') });
const salter = (): (() => string) => {
  let n = 0;
  return () => `salt-${++n}`;
};

const payCons = (ref = 'REF'): PaymentConstraint[] => [
  { type: 'payment.amount_range', currency: 'USD', min: 0, max: 50000 },
  { type: 'payment.allowed_payees', allowed: [M1, M2] },
  { type: 'payment.reference', conditional_transaction_id: ref },
];
const chkCons = (): CheckoutConstraint[] => [
  { type: 'checkout.line_items', items: [{ id: 'li', acceptable_items: [{ id: 'sku', title: 'Sku' }], quantity: 2 }] },
  { type: 'checkout.allowed_merchants', allowed: [M1] },
];

const openPay = (k: Keys, over: Record<string, unknown> = {}): string =>
  issueOpenPaymentMandate({ issuer: { privateKey: k.issuer.privateKey, kid: 'iss-kid' }, agentJwk: k.agent.publicJwk, iat: NOW_S, exp: NOW_S + 1000, constraints: payCons(), ...over } as never);
const openChk = (k: Keys, over: Record<string, unknown> = {}): string =>
  issueOpenCheckoutMandate({ issuer: { privateKey: k.issuer.privateKey, kid: 'iss-kid' }, agentJwk: k.agent.publicJwk, iat: NOW_S, exp: NOW_S + 1000, constraints: chkCons(), ...over } as never);

const checkoutJwt = (k: Keys, over: Record<string, unknown> = {}, header: Record<string, Json> = { kid: 'mk-kid' }): string =>
  signJwtEs256({
    header,
    privateKey: k.merchant.privateKey,
    payload: {
      id: 'chk',
      merchant: M1 as unknown as JsonObject,
      currency: 'USD',
      line_items: [{ id: 'l', item: { id: 'sku', title: 'Sku', price: 2000 }, quantity: 2 }],
      totals: [{ type: 'total', amount: 4000 }],
      ...over,
    } as JsonObject,
  });

const mandateOf = (token: string): JsonObject => {
  const hop = parseSdJwtHop(token);
  return (processDisclosures(hop.payload, hop.disclosures, hop.sdAlg).delegate_payload as JsonObject[])[0] as JsonObject;
};

/** Hand-signed root with full control of header, payload and the mandate. */
function root(k: Keys, o: { mandate?: JsonObject; header?: Record<string, Json>; payload?: JsonObject; delegate?: (b: ReturnType<typeof disclosureBuilder>) => Json; alg?: SdAlg } = {}): string {
  const b = disclosureBuilder(o.alg ?? 'sha-256', salter());
  const mandate = o.mandate ?? { vct: 'mandate.payment.open.1', cnf: { jwk: k.agent.publicJwk as unknown as JsonObject }, exp: NOW_S + 1000, iat: NOW_S };
  const dp = o.delegate ? o.delegate(b) : [b.element(mandate)];
  return signSdJwt({
    header: { typ: 'dc+sd-jwt', ...(o.header ?? {}) } as never,
    payload: { ...(dp === undefined ? {} : { delegate_payload: dp }), _sd_alg: o.alg ?? 'sha-256', ...(o.payload ?? {}) } as JsonObject,
    disclosures: b.disclosures,
    privateKey: k.issuer.privateKey,
  });
}

/** Hand-signed key-binding hop over `prev` (a token ending in "~"). */
function hop(prev: string, signer: Ap2KeyPair, o: {
  typ?: unknown; header?: Record<string, Json>; mandate?: JsonObject; mode?: 'sd' | 'iss' | 'both' | 'none'; hash?: string;
  aud?: string; nonce?: string; iat?: number | null; extra?: JsonObject; delegate?: (b: ReturnType<typeof disclosureBuilder>) => Json;
} = {}): string {
  const prevHop = parseSdJwtHop(splitChain(prev).pop() as string);
  const b = disclosureBuilder(prevHop.sdAlg, salter());
  const mandate = o.mandate ?? { vct: 'mandate.payment.1' };
  const payload: JsonObject = {
    delegate_payload: (o.delegate ? o.delegate(b) : [b.element(mandate)]) as Json,
    aud: o.aud ?? AUD,
    nonce: o.nonce ?? NONCE,
    _sd_alg: prevHop.sdAlg,
    ...(o.iat === null ? {} : { iat: o.iat ?? NOW_S + 1 }),
    ...o.extra,
  };
  const mode = o.mode ?? 'sd';
  if (mode === 'sd' || mode === 'both') payload.sd_hash = o.hash ?? sdHashOf(prevHop);
  if (mode === 'iss' || mode === 'both') payload.issuer_jwt_hash = o.hash ?? issuerJwtHashOf(prevHop);
  const h = signSdJwt({ header: { typ: (o.typ ?? 'kb+sd-jwt') as string, ...(o.header ?? {}) } as never, payload, disclosures: b.disclosures, privateKey: signer.privateKey });
  return `${prev}~${h}`;
}

const vopts = (k: Keys, over: Record<string, unknown> = {}) => ({
  resolveIssuerKey: () => k.issuer.publicJwk,
  expectedAudience: AUD,
  expectedNonce: NONCE,
  now: NOW,
  ...over,
});
const vchain = (token: string, k: Keys, over: Record<string, unknown> = {}) => verifyDelegationChain(token, vopts(k, over));
const why = (r: { ok: boolean; reason?: string }): string => (r.ok ? 'ACCEPTED' : (r.reason as string));

describe('issuing open mandates', () => {
  it('root header and payload shape', () => {
    const k = keys();
    const tok = openPay(k, { salt: salter() });
    const h = parseSdJwtHop(tok);
    expect(h.header).toEqual({ alg: 'ES256', typ: 'dc+sd-jwt', kid: 'iss-kid' });
    expect(Object.keys(h.payload).sort()).toEqual(['_sd_alg', 'delegate_payload']);
    expect(h.payload._sd_alg).toBe('sha-256');
    expect((h.payload.delegate_payload as unknown[]).length).toBe(1);
    expect(h.disclosures.length).toBe(1 + 2); // the mandate plus the two payees
    const m = mandateOf(tok);
    expect(m.vct).toBe('mandate.payment.open.1');
    expect(m.cnf).toEqual({ jwk: { crv: 'P-256', kty: 'EC', x: k.agent.publicJwk.x, y: k.agent.publicJwk.y } });
    expect(m.iat).toBe(NOW_S);
    expect(m.exp).toBe(NOW_S + 1000);
    expect(Object.keys(m).sort()).toEqual(['cnf', 'constraints', 'exp', 'iat', 'vct']);
    expect(m.constraints).toEqual(payCons());
  });
  it('typ, x5c, sdAlg and kid options', () => {
    const k = keys();
    const noKid = issueOpenPaymentMandate({ issuer: { privateKey: k.issuer.privateKey }, agentJwk: k.agent.publicJwk, iat: NOW_S, exp: NOW_S + 5, constraints: payCons() });
    expect(parseSdJwtHop(noKid).header).toEqual({ alg: 'ES256', typ: 'dc+sd-jwt' });
    const full = openPay(k, { typ: 'vc+sd-jwt', issuer: { privateKey: k.issuer.privateKey, kid: 'k2', x5c: ['QUJD'] }, sdAlg: 'sha-384' });
    const h = parseSdJwtHop(full);
    expect(h.header).toEqual({ alg: 'ES256', typ: 'vc+sd-jwt', kid: 'k2', x5c: ['QUJD'] });
    expect(h.payload._sd_alg).toBe('sha-384');
    expect(h.sdAlg).toBe('sha-384');
    expect(h.disclosures.every((d) => sdDigest(d, 'sha-384').length === 64)).toBe(true);
    expect((processDisclosures(h.payload, h.disclosures, h.sdAlg).delegate_payload as unknown[]).length).toBe(1);
    const c = openChk(k, { sdAlg: 'sha-512' });
    expect(parseSdJwtHop(c).payload._sd_alg).toBe('sha-512');
    const ch = parseSdJwtHop(c);
    expect((processDisclosures(ch.payload, ch.disclosures, ch.sdAlg).delegate_payload as unknown[]).length).toBe(1);
    expect(parseSdJwtHop(openChk(k)).payload._sd_alg).toBe('sha-256');
  });
  it('salt source is used', () => {
    const k = keys();
    const a = openPay(k, { salt: () => 'FIXED' });
    const decoded = parseSdJwtHop(a).disclosures.map((d) => JSON.parse(Buffer.from(d, 'base64url').toString()) as unknown[]);
    expect(decoded.every((d) => d[0] === 'FIXED')).toBe(true);
    const c = openChk(k, { salt: () => 'CFIXED' });
    expect(parseSdJwtHop(c).disclosures.map((d) => (JSON.parse(Buffer.from(d, 'base64url').toString()) as unknown[])[0]).every((x) => x === 'CFIXED')).toBe(true);
  });
  it('optional pre-set claims are embedded', () => {
    const k = keys();
    const tok = openPay(k, {
      payee: M1, paymentAmount: { amount: 5, currency: 'USD' }, paymentInstrument: { id: 'pi', type: 'card' },
      pisp: { legal_name: 'L', brand_name: 'B', domain_name: 'd.example' }, executionDate: '2027-01-01T00:00:00Z', pca: { v: 1 },
    });
    const m = mandateOf(tok);
    expect(m.payee).toEqual(M1);
    expect(m.payment_amount).toEqual({ amount: 5, currency: 'USD' });
    expect(m.payment_instrument).toEqual({ id: 'pi', type: 'card' });
    expect(m.pisp).toEqual({ legal_name: 'L', brand_name: 'B', domain_name: 'd.example' });
    expect(m.execution_date).toBe('2027-01-01T00:00:00Z');
    expect(m.x_pca).toEqual({ v: 1 });
    const plain = mandateOf(openPay(k));
    for (const f of ['payee', 'payment_amount', 'payment_instrument', 'pisp', 'execution_date', 'x_pca']) expect(plain, f).not.toHaveProperty(f);
    expect(mandateOf(openPay(k, { executionDate: '' })).execution_date).toBe('');
  });
  it('allowed payees and instruments are selectively disclosable, other constraints plain', () => {
    const k = keys();
    const tok = openPay(k, {
      constraints: [...payCons(), { type: 'payment.allowed_payment_instruments', allowed: [{ id: 'pi1', type: 'card' }] }, { type: 'payment.allowed_pisps', allowed: [{ legal_name: 'L', brand_name: 'B', domain_name: 'd' }] }],
    });
    const h = parseSdJwtHop(tok);
    const dp = (h.payload.delegate_payload as { '...': string }[])[0] as { '...': string };
    const rawRoot = h.disclosures.find((d) => sdDigest(d, h.sdAlg) === dp['...']) as string;
    const mandate = (JSON.parse(Buffer.from(rawRoot, 'base64url').toString()) as [string, JsonObject])[1];
    const cs = mandate.constraints as JsonObject[];
    expect(cs[0]).toEqual({ type: 'payment.amount_range', currency: 'USD', min: 0, max: 50000 });
    expect((cs[1]?.allowed as unknown[]).every((e) => Object.keys(e as object).join() === '...')).toBe(true);
    expect((cs[3]?.allowed as unknown[]).every((e) => Object.keys(e as object).join() === '...')).toBe(true);
    expect(cs[4]?.allowed).toEqual([{ legal_name: 'L', brand_name: 'B', domain_name: 'd' }]);
    expect(h.disclosures.length).toBe(1 + 2 + 1);
    const c = openChk(k);
    const ch = parseSdJwtHop(c);
    const cdp = (ch.payload.delegate_payload as { '...': string }[])[0] as { '...': string };
    const croot = ch.disclosures.find((d) => sdDigest(d, ch.sdAlg) === cdp['...']) as string;
    const cm = (JSON.parse(Buffer.from(croot, 'base64url').toString()) as [string, JsonObject])[1];
    const cc = cm.constraints as JsonObject[];
    expect(cc[0]?.type).toBe('checkout.line_items');
    const item = (cc[0]?.items as JsonObject[])[0] as JsonObject;
    expect(Object.keys(item).sort()).toEqual(['acceptable_items', 'id', 'quantity']);
    expect((item.acceptable_items as JsonObject[])[0]).toHaveProperty('...');
    expect(item.quantity).toBe(2);
    expect(cc[1]?.type).toBe('checkout.allowed_merchants');
    expect((cc[1]?.allowed as JsonObject[])[0]).toHaveProperty('...');
    expect(ch.disclosures.length).toBe(1 + 1 + 1);
  });
  it('iat < exp are integers: boundaries and messages', () => {
    const k = keys();
    const want = 'open mandate: need integer iat < exp (epoch seconds)';
    for (const [iat, exp] of [[10, 10], [10, 9], [1.5, 20], [10, 20.5], [Number.NaN, 20], [10, Number.POSITIVE_INFINITY], [10, undefined]]) {
      expect(() => openPay(k, { iat, exp }), `${iat},${exp}`).toThrow(new Ap2Error(want));
      expect(() => openChk(k, { iat, exp }), `${iat},${exp}`).toThrow(new Ap2Error(want));
    }
    expect(() => openPay(k, { iat: 10, exp: 11 })).not.toThrow();
    expect(() => openPay(k, { agentJwk: 'x' })).toThrow('agentJwk: JWK must be an object');
  });
  it('malformed constraints fail at issuance with every problem listed', () => {
    const k = keys();
    expect(() => openPay(k, { constraints: [{ type: 'payment.amount_range', currency: 'usd', max: -1 }] })).toThrow(
      new Ap2Error('open payment mandate: constraints[0].currency: must be an ISO 4217 alpha-3 code; constraints[0].max: must be a non-negative integer (minor units); constraints: must contain a payment.reference constraint'),
    );
    expect(() => openChk(k, { constraints: [{ type: 'checkout.line_items', items: [] }] })).toThrow(
      new Ap2Error('open checkout mandate: constraints[0].items: must be a non-empty array'),
    );
    expect(() => openChk(k, { constraints: [{ type: 'checkout.allowed_merchants', allowed: [{ id: '', name: '' }] }] })).toThrow(
      /^open checkout mandate: constraints\[0\]\.allowed\[0\]\.id: required string; constraints\[0\]\.allowed\[0\]\.name: required string; constraints: must contain a checkout\.line_items constraint$/,
    );
    expect(openPaymentMandateProblems({}).length).toBeGreaterThan(0);
    expect(openCheckoutMandateProblems({}).length).toBeGreaterThan(0);
  });
});

describe('presenting closed mandates', () => {
  const closedPay = (k: Keys, open: string, over: Record<string, unknown> = {}): string =>
    presentClosedPayment({
      open, agentKey: { privateKey: k.agent.privateKey, publicJwk: k.agent.publicJwk }, aud: AUD, nonce: NONCE, iat: NOW_S + 5, transactionId: 'T', payee: M1,
      paymentAmount: { amount: 4000, currency: 'USD' }, paymentInstrument: { id: 'pi', type: 'card' }, ...over,
    } as never);
  it('hop wire shape: typ, hash claim, aud, nonce, iat and the joiner', () => {
    const k = keys();
    const open = openPay(k);
    const tok = closedPay(k, open, { salt: salter() });
    expect(tok.startsWith(`${open}~`)).toBe(true);
    const parts = splitChain(tok);
    expect(parts.length).toBe(2);
    const h = parseSdJwtHop(parts[1] as string);
    expect(h.header).toEqual({ alg: 'ES256', typ: 'kb+sd-jwt' });
    expect(Object.keys(h.payload).sort()).toEqual(['_sd_alg', 'aud', 'delegate_payload', 'iat', 'nonce', 'sd_hash']);
    expect(h.payload).toMatchObject({ aud: AUD, nonce: NONCE, iat: NOW_S + 5, _sd_alg: 'sha-256' });
    expect(h.payload.sd_hash).toBe(sdHashOf(parseSdJwtHop(parts[0] as string)));
    const iss = parseSdJwtHop(splitChain(closedPay(k, open, { hashMode: 'issuer_jwt_hash' }))[1] as string);
    expect(iss.payload.issuer_jwt_hash).toBe(issuerJwtHashOf(parseSdJwtHop(open)));
    expect(iss.payload).not.toHaveProperty('sd_hash');
    const sdm = parseSdJwtHop(splitChain(closedPay(k, open, { hashMode: 'sd_hash' }))[1] as string);
    expect(sdm.payload).not.toHaveProperty('issuer_jwt_hash');
    const decoded = h.disclosures.map((d) => (JSON.parse(Buffer.from(d, 'base64url').toString()) as unknown[])[0]);
    expect(decoded).toEqual(['salt-1']);
  });
  it('inherits the preceding hop sd_alg', () => {
    const k = keys();
    const open = openPay(k, { sdAlg: 'sha-512' });
    const h = parseSdJwtHop(splitChain(closedPay(k, open))[1] as string);
    expect(h.sdAlg).toBe('sha-512');
    expect(h.payload._sd_alg).toBe('sha-512');
  });
  it('required inputs', () => {
    const k = keys();
    const open = openPay(k);
    expect(() => closedPay(k, open, { aud: '' })).toThrow(new Ap2Error('closed mandate: aud and nonce are required'));
    expect(() => closedPay(k, open, { nonce: '' })).toThrow(new Ap2Error('closed mandate: aud and nonce are required'));
    expect(() => closedPay(k, open, { iat: 1.5 })).toThrow(new Ap2Error('closed mandate: iat must be an integer'));
    expect(() => closedPay(k, open, { iat: Number.NaN })).toThrow(new Ap2Error('closed mandate: iat must be an integer'));
    expect(() => closedPay(k, open, { iat: 0 })).not.toThrow();
  });
  it('closed payment mandate fields and problems', () => {
    const k = keys();
    const open = openPay(k);
    const closed = mandateOf(splitChain(closedPay(k, open, { pisp: { legal_name: 'L', brand_name: 'B', domain_name: 'd' }, executionDate: '2027-02-02', riskData: { a: 1 }, exp: NOW_S + 50, pca: { v: 1 } }))[1] as string);
    expect(closed).toEqual({
      vct: 'mandate.payment.1', transaction_id: 'T', payee: M1, payment_amount: { amount: 4000, currency: 'USD' }, payment_instrument: { id: 'pi', type: 'card' },
      pisp: { legal_name: 'L', brand_name: 'B', domain_name: 'd' }, execution_date: '2027-02-02', risk_data: { a: 1 }, exp: NOW_S + 50, x_pca: { v: 1 },
    });
    const plain = mandateOf(splitChain(closedPay(k, open))[1] as string);
    for (const f of ['pisp', 'execution_date', 'risk_data', 'exp', 'x_pca']) expect(plain, f).not.toHaveProperty(f);
    expect(() => closedPay(k, open, { transactionId: '', payee: { id: '', name: '' } })).toThrow(
      new Ap2Error('closed payment mandate: transaction_id: required string; payee.id: required string; payee.name: required string'),
    );
  });
  it('closed checkout mandate', () => {
    const k = keys();
    const open = openChk(k);
    const jwt = checkoutJwt(k);
    const mk = (over: Record<string, unknown> = {}) =>
      presentClosedCheckout({ open, agentKey: { privateKey: k.agent.privateKey, publicJwk: k.agent.publicJwk }, aud: AUD, nonce: NONCE, iat: NOW_S + 5, checkoutJwt: jwt, ...over } as never);
    const tok = mk({ exp: NOW_S + 60, pca: { v: 1 } });
    const hopTok = parseSdJwtHop(splitChain(tok)[1] as string);
    const claims = processDisclosures(hopTok.payload, hopTok.disclosures, hopTok.sdAlg);
    const m = (claims.delegate_payload as JsonObject[])[0] as JsonObject;
    expect(m.vct).toBe('mandate.checkout.1');
    expect(m.checkout_jwt).toBe(jwt);
    expect(m.checkout_hash).toBe(sdDigest(jwt, 'sha-256'));
    expect(m.exp).toBe(NOW_S + 60);
    expect(m.x_pca).toEqual({ v: 1 });
    const plain = mandateOf(splitChain(mk())[1] as string);
    expect(plain).not.toHaveProperty('exp');
    expect(plain).not.toHaveProperty('x_pca');
    expect(() => mk({ checkoutJwt: '', exp: 1.5 })).toThrow(new Ap2Error('closed checkout mandate: exp: must be an integer epoch-seconds; checkout_jwt: required string'));
    const sha512 = presentClosedCheckout({ open: openChk(k, { sdAlg: 'sha-512' }), agentKey: { privateKey: k.agent.privateKey, publicJwk: k.agent.publicJwk }, aud: AUD, nonce: NONCE, iat: NOW_S + 5, checkoutJwt: jwt });
    const h5 = parseSdJwtHop(splitChain(sha512)[1] as string);
    const m5 = (processDisclosures(h5.payload, h5.disclosures, h5.sdAlg).delegate_payload as JsonObject[])[0] as JsonObject;
    expect(m5.checkout_hash).toBe(sdDigest(jwt, 'sha-512'));
  });
});

describe('splitChain', () => {
  it('empty / non-string / too many hops', () => {
    expect(() => splitChain('')).toThrow(new Ap2Error('chain: empty'));
    expect(() => splitChain(undefined as never)).toThrow(new Ap2Error('chain: empty'));
    expect(() => splitChain(5 as never)).toThrow(new Ap2Error('chain: empty'));
    expect(splitChain(Array(8).fill('a').join('~~')).length).toBe(8);
    expect(() => splitChain(Array(9).fill('a').join('~~'))).toThrow(new Ap2Error('chain: more than 8 hops'));
    expect(splitChain('a~~b~c')).toEqual(['a~', 'b~c']);
  });
});

describe('verifyDelegationChain: root', () => {
  it('requires audience and nonce', () => {
    const k = keys();
    const t = hop(root(k), k.agent);
    for (const o of [{ expectedAudience: '' }, { expectedNonce: '' }, { expectedAudience: '', expectedNonce: '' }]) {
      expect(why(vchain(t, k, o))).toBe('verify: expectedAudience and expectedNonce are required');
    }
    expect(why(vchain(t, k))).toBe('ACCEPTED');
  });
  it('default clock is the wall clock in seconds', () => {
    const k = keys();
    const t = hop(root(k), k.agent);
    vi.useFakeTimers();
    vi.setSystemTime((NOW_S + 10) * 1000 + 500);
    expect(why(verifyDelegationChain(t, { ...vopts(k), now: undefined }))).toBe('ACCEPTED');
    vi.setSystemTime((NOW_S + 1000 + 61) * 1000);
    expect(why(verifyDelegationChain(t, { ...vopts(k), now: undefined }))).toMatch(/^root mandate: expired at /);
    vi.setSystemTime((NOW_S - 3600) * 1000);
    expect(why(verifyDelegationChain(t, { ...vopts(k), now: undefined }))).toMatch(/iat is in the future$/);
  });
  it('root header and key resolution', () => {
    const k = keys();
    expect(why(vchain(hop(root(k, { header: { crit: ['x'] } }), k.agent), k))).toBe('root: crit headers are not supported');
    expect(why(vchain(hop(root(k), k.agent), k, { resolveIssuerKey: () => undefined }))).toBe('root: no issuer key for this header');
    const seen: unknown[] = [];
    vchain(hop(root(k, { header: { kid: 'abc' } }), k.agent), k, { resolveIssuerKey: (h: unknown) => { seen.push(h); return k.issuer.publicJwk; } });
    expect((seen[0] as { kid: string }).kid).toBe('abc');
    expect(why(vchain(hop(root(k), k.agent), k, { resolveIssuerKey: () => generateAp2KeyPair().publicJwk }))).toBe('root: signature does not verify under the issuer key');
  });
  it('root claim times with the default skew of 60 s and an explicit skew', () => {
    const k = keys();
    const exp = NOW_S + 100;
    const t = (payload: JsonObject) => hop(root(k, { payload }), k.agent);
    expect(why(vchain(t({ exp }), k, { now: exp + 60 }))).toBe('ACCEPTED');
    expect(why(vchain(t({ exp }), k, { now: exp + 61 }))).toBe(`root: expired at ${exp}`);
    expect(why(vchain(t({ exp }), k, { now: exp + 5, clockSkewSeconds: 5 }))).toBe('ACCEPTED');
    expect(why(vchain(t({ exp }), k, { now: exp + 6, clockSkewSeconds: 5 }))).toBe(`root: expired at ${exp}`);
    expect(why(vchain(t({ exp }), k, { now: exp, clockSkewSeconds: 0 }))).toBe('ACCEPTED');
    expect(why(vchain(t({ exp: 1.5 }), k))).toBe('root: exp must be an integer');
    expect(why(vchain(t({ exp: '5' as never }), k))).toBe('root: exp must be an integer');
    const iat = NOW + 60;
    expect(why(vchain(t({ iat }), k))).toBe('ACCEPTED');
    expect(why(vchain(t({ iat: iat + 1 }), k))).toBe('root: iat is in the future');
    expect(why(vchain(t({ iat: NOW + 5 }), k, { clockSkewSeconds: 5 }))).toBe('ACCEPTED');
    expect(why(vchain(t({ iat: NOW + 6 }), k, { clockSkewSeconds: 5 }))).toBe('root: iat is in the future');
    expect(why(vchain(t({ iat: 1.5 }), k))).toBe('root: iat must be an integer');
  });
  it('root mandate times use the same bounds and the "root mandate" label', () => {
    const k = keys();
    const mand = (extra: JsonObject): JsonObject => ({ vct: 'v', cnf: { jwk: k.agent.publicJwk as unknown as JsonObject }, ...extra });
    const t = (extra: JsonObject) => hop(root(k, { mandate: mand(extra) }), k.agent);
    expect(why(vchain(t({ exp: NOW - 60 }), k))).toBe('ACCEPTED');
    expect(why(vchain(t({ exp: NOW - 61 }), k))).toBe(`root mandate: expired at ${NOW - 61}`);
    expect(why(vchain(t({ exp: 2.5 }), k))).toBe('root mandate: exp must be an integer');
    expect(why(vchain(t({ iat: NOW + 61 }), k))).toBe('root mandate: iat is in the future');
    expect(why(vchain(t({ iat: NOW + 60 }), k))).toBe('ACCEPTED');
    expect(why(vchain(t({ iat: 0.5 }), k))).toBe('root mandate: iat must be an integer');
  });
  it('delegate_payload shape', () => {
    const k = keys();
    const prev = (delegate?: (b: ReturnType<typeof disclosureBuilder>) => Json) => root(k, { delegate });
    const noDp = signSdJwt({ header: { typ: 'dc+sd-jwt' }, payload: { _sd_alg: 'sha-256' }, disclosures: [], privateKey: k.issuer.privateKey });
    expect(why(vchain(hop(noDp, k.agent), k))).toBe('root: delegate_payload missing');
    expect(why(vchain(hop(prev(() => 'str'), k.agent), k))).toBe('root: delegate_payload missing');
    expect(why(vchain(hop(prev(() => []), k.agent), k))).toBe('root: delegate_payload must disclose exactly one mandate (got 0)');
    expect(why(vchain(hop(prev((b) => [b.element({ a: 1 }), b.element({ b: 2 })]), k.agent), k))).toBe('root: delegate_payload must disclose exactly one mandate (got 2)');
    expect(why(vchain(hop(prev(() => ['x']), k.agent), k))).toBe('root: delegate_payload must disclose exactly one mandate (got 1)');
    expect(why(vchain(hop(prev((b) => [b.element([1])]), k.agent), k))).toBe('root: delegate_payload must disclose exactly one mandate (got 1)');
  });
});

describe('verifyDelegationChain: key-binding hops', () => {
  it('typ rules: terminal vs intermediate lists', () => {
    const k = keys();
    const r = root(k);
    expect(why(vchain(hop(r, k.agent, { typ: 'JWT' }), k))).toBe('hop 1: typ must be one of kb+sd-jwt, kb-sd-jwt');
    expect(why(vchain(hop(r, k.agent, { typ: 'kb+sd-jwt+kb' }), k))).toBe('hop 1: typ must be one of kb+sd-jwt, kb-sd-jwt');
    expect(why(vchain(hop(r, k.agent, { typ: 5 as never }), k))).toBe('hop 1: typ must be one of kb+sd-jwt, kb-sd-jwt');
    expect(why(vchain(hop(r, k.agent, { typ: 'kb-sd-jwt' }), k))).toBe('ACCEPTED');
    const midMandate = { vct: 'mid', cnf: { jwk: k.agent.publicJwk as unknown as JsonObject } };
    const mid = hop(r, k.agent, { typ: 'kb+sd-jwt+kb', mandate: midMandate });
    expect(why(vchain(hop(mid, k.agent), k))).toBe('ACCEPTED');
    expect(why(vchain(hop(hop(r, k.agent, { typ: 'kb-sd-jwt+kb', mandate: midMandate }), k.agent), k))).toBe('ACCEPTED');
    expect(why(vchain(hop(hop(r, k.agent, { typ: 'kb+sd-jwt', mandate: midMandate }), k.agent), k))).toBe('hop 1: typ must be one of kb+sd-jwt+kb, kb-sd-jwt+kb');
  });
  it('three hops: kinds, indexes, intermediate needs cnf, terminal must not carry it', () => {
    const k = keys();
    const r = root(k);
    const midMandate = { vct: 'mid', cnf: { jwk: k.agent.publicJwk as unknown as JsonObject } };
    const mid = hop(r, k.agent, { typ: 'kb+sd-jwt+kb', mandate: midMandate, aud: undefined });
    const res = vchain(hop(mid, k.agent), k);
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.hops.map((h) => [h.index, h.kind])).toEqual([[0, 'root'], [1, 'intermediate'], [2, 'terminal']]);
    }
    expect(why(vchain(hop(hop(r, k.agent, { typ: 'kb+sd-jwt+kb' }), k.agent), k))).toBe('hop 1: an intermediate hop requires cnf');
    const withCnfTerminal = hop(r, k.agent, { mandate: midMandate });
    expect(why(vchain(withCnfTerminal, k))).toBe('hop 1: a terminal hop must not carry cnf');
  });
  it('an intermediate hop is not held to the audience and nonce', () => {
    const k = keys();
    const midMandate = { vct: 'mid', cnf: { jwk: k.agent.publicJwk as unknown as JsonObject } };
    const mid = hop(root(k), k.agent, { typ: 'kb+sd-jwt+kb', mandate: midMandate, aud: 'other', nonce: 'other' });
    expect(why(vchain(hop(mid, k.agent), k))).toBe('ACCEPTED');
  });
  it('crit header, preceding cnf, signature', () => {
    const k = keys();
    const r = root(k);
    expect(why(vchain(hop(r, k.agent, { header: { crit: ['x'] } }), k))).toBe('hop 1: crit headers are not supported');
    const noCnf = root(k, { mandate: { vct: 'v' } });
    expect(why(vchain(hop(noCnf, k.agent), k))).toBe('preceding mandate: no cnf.jwk to delegate to');
    const cnfNotObj = root(k, { mandate: { vct: 'v', cnf: 'x' } });
    expect(why(vchain(hop(cnfNotObj, k.agent), k))).toBe('preceding mandate: no cnf.jwk to delegate to');
    const jwkNotObj = root(k, { mandate: { vct: 'v', cnf: { jwk: 'x' } } });
    expect(why(vchain(hop(jwkNotObj, k.agent), k))).toBe('preceding mandate: no cnf.jwk to delegate to');
    const badJwk = root(k, { mandate: { vct: 'v', cnf: { jwk: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' } } } });
    expect(why(vchain(hop(badJwk, k.agent), k))).toBe('preceding mandate cnf.jwk: bad JWK x');
    expect(why(vchain(hop(r, generateAp2KeyPair()), k))).toBe("hop 1: signature does not verify under the preceding mandate's cnf.jwk");
  });
  it('binding hash claims: exactly one, and it must match', () => {
    const k = keys();
    const r = root(k);
    expect(why(vchain(hop(r, k.agent, { mode: 'both' }), k))).toBe('hop 1: exactly one of sd_hash / issuer_jwt_hash is required');
    expect(why(vchain(hop(r, k.agent, { mode: 'none' }), k))).toBe('hop 1: exactly one of sd_hash / issuer_jwt_hash is required');
    expect(why(vchain(hop(r, k.agent, { mode: 'iss' }), k))).toBe('ACCEPTED');
    expect(why(vchain(hop(r, k.agent, { mode: 'sd', hash: 'x' }), k))).toBe('hop 1: sd_hash does not match the preceding hop');
    expect(why(vchain(hop(r, k.agent, { mode: 'iss', hash: 'x' }), k))).toBe('hop 1: issuer_jwt_hash does not match the preceding hop');
    // each hash is bound to the right preceding bytes
    const other = root(k);
    expect(why(vchain(hop(r, k.agent, { mode: 'sd', hash: sdHashOf(parseSdJwtHop(other)) }), k))).toBe('hop 1: sd_hash does not match the preceding hop');
    expect(why(vchain(hop(r, k.agent, { mode: 'iss', hash: sdHashOf(parseSdJwtHop(r)) }), k))).toBe('hop 1: issuer_jwt_hash does not match the preceding hop');
  });
  it('hop claim times, iat required, mandate times', () => {
    const k = keys();
    const r = root(k);
    expect(why(vchain(hop(r, k.agent, { iat: null }), k))).toBe('hop 1: iat is required');
    expect(why(vchain(hop(r, k.agent, { iat: NOW + 60 }), k))).toBe('ACCEPTED');
    expect(why(vchain(hop(r, k.agent, { iat: NOW + 61 }), k))).toBe('hop 1: iat is in the future');
    expect(why(vchain(hop(r, k.agent, { iat: 1.5 }), k))).toBe('hop 1: iat must be an integer');
    const e = NOW - 20;
    expect(why(vchain(hop(r, k.agent, { extra: { exp: e } }), k, { now: e + 60 }))).toBe('ACCEPTED');
    expect(why(vchain(hop(r, k.agent, { extra: { exp: e } }), k, { now: e + 61 }))).toBe(`hop 1: expired at ${e}`);
    expect(why(vchain(hop(r, k.agent, { extra: { exp: 2.5 } }), k))).toBe('hop 1: exp must be an integer');
    expect(why(vchain(hop(r, k.agent, { mandate: { vct: 'v', exp: e } }), k, { now: e + 61 }))).toBe(`hop 1 mandate: expired at ${e}`);
    expect(why(vchain(hop(r, k.agent, { mandate: { vct: 'v', iat: NOW + 61 } }), k))).toBe('hop 1 mandate: iat is in the future');
  });
  it('terminal audience and nonce', () => {
    const k = keys();
    const r = root(k);
    expect(why(vchain(hop(r, k.agent, { aud: 'x' }), k))).toBe('hop 1: aud mismatch');
    expect(why(vchain(hop(r, k.agent, { nonce: 'x' }), k))).toBe('hop 1: nonce mismatch');
    expect(why(vchain(hop(r, k.agent, { aud: AUD, nonce: NONCE }), k, { expectedAudience: AUD.toUpperCase() }))).toBe('hop 1: aud mismatch');
  });
  it('numbering: the second hop of a three-hop chain is labelled "hop 2"', () => {
    const k = keys();
    const midMandate = { vct: 'mid', cnf: { jwk: k.agent.publicJwk as unknown as JsonObject } };
    const mid = hop(root(k), k.agent, { typ: 'kb+sd-jwt+kb', mandate: midMandate });
    expect(why(vchain(hop(mid, k.agent, { aud: 'x' }), k))).toBe('hop 2: aud mismatch');
  });
  it('a non-Error throw is stringified', () => {
    const k = keys();
    const r = vchain(hop(root(k), k.agent), k, { resolveIssuerKey: () => { throw 'plain'; } });
    expect(r).toEqual({ ok: false, reason: 'plain' });
  });
});

/** A complete, hand-built purchase with overridable parts. */
function purchase(k: Keys, o: {
  checkoutOpen?: string; paymentOpen?: (ref: string) => string; jwt?: string; payee?: Merchant; amount?: { amount: number; currency: string }; transactionId?: string;
} = {}) {
  const open = o.checkoutOpen ?? openChk(k);
  const jwt = o.jwt ?? checkoutJwt(k);
  const agentKey = { privateKey: k.agent.privateKey, publicJwk: k.agent.publicJwk };
  const checkoutChain = presentClosedCheckout({ open, agentKey, aud: 'merchant', nonce: 'cn', iat: NOW_S + 5, checkoutJwt: jwt });
  const openHash = sdHashOf(parseSdJwtHop(open));
  const popen = o.paymentOpen ? o.paymentOpen(openHash) : openPay(k, { constraints: payCons(openHash) });
  const paymentChain = presentClosedPayment({
    open: popen, agentKey, aud: 'cp', nonce: 'pn', iat: NOW_S + 6, transactionId: o.transactionId ?? sdDigest(jwt),
    payee: o.payee ?? M1, paymentAmount: o.amount ?? { amount: 4000, currency: 'USD' }, paymentInstrument: { id: 'pi', type: 'card' },
  });
  const popts = (over: Record<string, unknown> = {}) => ({
    resolveIssuerKey: () => k.issuer.publicJwk,
    resolveMerchantKey: () => k.merchant.publicJwk,
    checkout: { expectedAudience: 'merchant', expectedNonce: 'cn' },
    payment: { expectedAudience: 'cp', expectedNonce: 'pn' },
    now: NOW,
    ...over,
  });
  return { checkoutChain, paymentChain, popts, openHash };
}
const bad = (r: { ok: boolean; reason?: string }): string => (r.ok ? 'ACCEPTED' : (r.reason as string));
const buy = (p: ReturnType<typeof purchase>, over: Record<string, unknown> = {}) => verifyPurchase(p.checkoutChain, p.paymentChain, p.popts(over) as never);

describe('verifyPurchase end to end and cross-checks', () => {
  it('a hand-built purchase verifies', () => {
    const k = keys();
    const r = buy(purchase(k));
    expect(bad(r)).toBe('ACCEPTED');
    if (r.ok) {
      expect(r.checkout.openHash).toBeTruthy();
      expect(r.payment.hops.length).toBe(2);
    }
  });
  it('failure prefixes', () => {
    const k = keys();
    const p = purchase(k);
    expect(bad(buy(p, { checkout: { expectedAudience: 'x', expectedNonce: 'cn' } }))).toBe('checkout: hop 1: aud mismatch');
    expect(bad(buy(p, { payment: { expectedAudience: 'x', expectedNonce: 'pn' } }))).toBe('payment: hop 1: aud mismatch');
  });
  it('now and clock skew are forwarded to both chains', () => {
    const k = keys();
    const p = purchase(k);
    expect(bad(buy(p, { now: NOW_S + 1000 + 61 }))).toMatch(/^checkout: root mandate: expired at /);
    expect(bad(buy(p, { now: NOW_S + 1000 + 61, clockSkewSeconds: 61 }))).toBe('ACCEPTED');
    expect(bad(buy(p, { now: NOW_S + 1000 + 5, clockSkewSeconds: 5 }))).toBe('ACCEPTED');
    expect(bad(buy(p, { now: NOW_S + 1000 + 6, clockSkewSeconds: 5 }))).toMatch(/^checkout: root mandate: expired/);
    // a payment-only skew problem: mandate stays valid for the checkout hop but not for the payment one
    const k2 = keys();
    const short = purchase(k2, { paymentOpen: (ref) => openPay(k2, { constraints: payCons(ref), exp: NOW_S + 100 }) });
    expect(bad(buy(short, { now: NOW_S + 100 + 61 }))).toMatch(/^payment: root mandate: expired at /);
    vi.useFakeTimers();
    vi.setSystemTime(NOW * 1000);
    expect(bad(verifyPurchase(p.checkoutChain, p.paymentChain, { ...p.popts(), now: undefined } as never))).toBe('ACCEPTED');
  });
  it('the default clock also drives payment constraint evaluation', () => {
    const k = keys();
    const p = purchase(k, { paymentOpen: (ref) => openPay(k, { constraints: [...payCons(ref), { type: 'payment.execution_date', not_before: '2999-01-01T00:00:00Z' }] }) });
    vi.useFakeTimers();
    vi.setSystemTime(NOW * 1000);
    const r = verifyPaymentChain(p.paymentChain, { ...vopts(k, { expectedAudience: 'cp', expectedNonce: 'pn' }), now: undefined, openCheckoutHash: p.openHash } as never);
    expect(r.ok).toBe(false);
    expect(why(r)).toBe('open payment constraints violated: execution date is before the allowed window (not_before 2999-01-01T00:00:00Z)');
  });
  it('totals, currency, merchant and payee cross-checks', () => {
    const k = keys();
    expect(bad(buy(purchase(k, { jwt: checkoutJwt(k, { totals: [{ type: 'total', amount: 4000 }, { type: 'total', amount: 4000 }] }) })))).toBe('checkout: needs exactly one total entry');
    expect(bad(buy(purchase(k, { jwt: checkoutJwt(k, { totals: [{ type: 'subtotal', amount: 4000 }] }) })))).toBe('checkout: needs exactly one total entry');
    expect(bad(buy(purchase(k, { jwt: checkoutJwt(k, { currency: 'EUR' }) })))).toBe('payment currency differs from the checkout currency');
    expect(bad(buy(purchase(k, { jwt: checkoutJwt(k, { totals: [{ type: 'total', amount: 4001 }] }) })))).toBe('payment amount 4000 differs from the checkout total 4001');
    const k2 = keys();
    const noMerchant = purchase(k2, {
      checkoutOpen: openChk(k2, { constraints: [chkCons()[0]] }),
      jwt: checkoutJwt(k2, { merchant: undefined }),
    });
    expect(bad(buy(noMerchant))).toBe('checkout: no merchant to compare the payee with');
    const k3 = keys();
    const other = purchase(k3, { payee: M2 });
    expect(bad(buy(other))).toBe('payee differs from the checkout merchant');
  });
});

describe('verifyCheckoutChain', () => {
  const ck = (token: string, k: Keys, over: Record<string, unknown> = {}) =>
    verifyCheckoutChain(token, { ...vopts(k, { expectedAudience: 'merchant', expectedNonce: 'cn' }), resolveMerchantKey: () => k.merchant.publicJwk, ...over } as never);
  const full = (k: Keys, open = openChk(k), jwt = checkoutJwt(k)) =>
    presentClosedCheckout({ open, agentKey: { privateKey: k.agent.privateKey, publicJwk: k.agent.publicJwk }, aud: 'merchant', nonce: 'cn', iat: NOW_S + 5, checkoutJwt: jwt });
  it('a good chain returns the parsed pieces', () => {
    const k = keys();
    const open = openChk(k);
    const jwt = checkoutJwt(k);
    const r = ck(full(k, open, jwt), k);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.checkoutJwt).toBe(jwt);
      expect(r.checkout.id).toBe('chk');
      expect(r.openHash).toBe(sdHashOf(parseSdJwtHop(open)));
      expect(r.hops.length).toBe(2);
      expect(r.open.vct).toBe('mandate.checkout.open.1');
      expect(r.closed.vct).toBe('mandate.checkout.1');
    }
  });
  it('chain-level failures pass straight through', () => {
    const k = keys();
    expect(why(ck(full(k), k, { expectedAudience: 'x' }))).toBe('hop 1: aud mismatch');
  });
  it('hop count', () => {
    const k = keys();
    expect(why(ck(root(k), k))).toBe('expected an open mandate followed by one closed mandate, got 1 hop(s)');
    const midMandate = { vct: 'mid', cnf: { jwk: k.agent.publicJwk as unknown as JsonObject } };
    const mid = hop(root(k), k.agent, { typ: 'kb+sd-jwt+kb', mandate: midMandate });
    expect(why(ck(hop(mid, k.agent, { aud: 'merchant', nonce: 'cn' }), k))).toBe('expected an open mandate followed by one closed mandate, got 3 hop(s)');
  });
  it('open mandate problems, missing exp', () => {
    const k = keys();
    const chk = (mandate: JsonObject) => ck(hop(root(k, { mandate }), k.agent, { aud: 'merchant', nonce: 'cn', mandate: { vct: 'mandate.checkout.1' } }), k);
    const cnf = { jwk: k.agent.publicJwk as unknown as JsonObject };
    const m = { vct: 'x', cnf, constraints: 'nope' } as JsonObject;
    expect(why(chk(m))).toBe(`open checkout mandate: ${openCheckoutMandateProblems(m).join('; ')}`);
    expect(openCheckoutMandateProblems(m).length).toBeGreaterThan(1);
    const noExp = { vct: 'mandate.checkout.open.1', cnf, constraints: [chkCons()[0]] } as unknown as JsonObject;
    expect(openCheckoutMandateProblems(noExp)).toEqual([]);
    expect(why(chk(noExp))).toBe('open checkout mandate: an open mandate must carry exp');
  });
  it('closed mandate problems, hash and merchant jwt', () => {
    const k = keys();
    const open = openChk(k);
    const mk = (closed: JsonObject) => ck(hop(open, k.agent, { aud: 'merchant', nonce: 'cn', mandate: closed }), k);
    const jwt = checkoutJwt(k);
    const bad2 = { vct: 'nope', checkout_jwt: '', checkout_hash: '' } as JsonObject;
    expect(why(mk(bad2))).toBe('closed checkout mandate: vct: must be mandate.checkout.1; checkout_jwt: required string; checkout_hash: required string');
    expect(why(mk({ vct: 'mandate.checkout.1', checkout_jwt: jwt, checkout_hash: 'zzz' }))).toBe('checkout_hash does not match checkout_jwt');
    expect(why(mk({ vct: 'mandate.checkout.1', checkout_jwt: 'abc', checkout_hash: sdDigest('abc') }))).toBe('checkout_jwt: must header.payload.signature'.replace('must', 'must be'));
    expect(why(ck(full(k, open, jwt), k, { resolveMerchantKey: () => undefined }))).toBe('checkout_jwt: no merchant key for this header');
    expect(why(ck(full(k, open, jwt), k, { resolveMerchantKey: () => generateAp2KeyPair().publicJwk }))).toBe('checkout_jwt: merchant signature does not verify');
    const seen: unknown[] = [];
    ck(full(k, open, jwt), k, { resolveMerchantKey: (h: unknown) => { seen.push(h); return k.merchant.publicJwk; } });
    expect((seen[0] as { kid: string }).kid).toBe('mk-kid');
  });
  it('constraint violations are listed and returned', () => {
    const k = keys();
    const jwt = checkoutJwt(k, { merchant: M2 as unknown as JsonObject, line_items: [{ id: 'l', item: { id: 'other', title: 'O', price: 1 }, quantity: 1 }] });
    const r = ck(full(k, openChk(k), jwt), k);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.violations?.length).toBe(2);
      expect(r.reason).toBe(`open checkout constraints violated: ${(r.violations as string[]).join('; ')}`);
      expect(r.violations).toEqual(['line items do not satisfy the constraint: assigned 0 of 2 required and 1 carted units', 'merchant Merchant Two is not in the allowed list']);
    }
  });
  it('a chain whose mandates are not of this kind fails with the problem list', () => {
    const k = keys();
    const r = ck(hop(openPay(k), k.agent, { aud: 'merchant', nonce: 'cn' }), k);
    expect(r.ok).toBe(false);
    expect(why(r)).toMatch(/^open checkout mandate: vct: must be mandate\.checkout\.open\.1; /);
  });
});

describe('verifyPaymentChain', () => {
  const pc = (token: string, k: Keys, over: Record<string, unknown> = {}) =>
    verifyPaymentChain(token, { ...vopts(k, { expectedAudience: 'cp', expectedNonce: 'pn' }), openCheckoutHash: 'REF', ...over } as never);
  const full = (k: Keys, over: Record<string, unknown> = {}, open = openPay(k)) =>
    presentClosedPayment({
      open, agentKey: { privateKey: k.agent.privateKey, publicJwk: k.agent.publicJwk }, aud: 'cp', nonce: 'pn', iat: NOW_S + 5, transactionId: 'T', payee: M1,
      paymentAmount: { amount: 4000, currency: 'USD' }, paymentInstrument: { id: 'pi', type: 'card' }, ...over,
    } as never);
  it('a good chain', () => {
    const k = keys();
    const r = pc(full(k), k);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.closed.transaction_id).toBe('T');
      expect(r.hops.length).toBe(2);
      expect(r.openHash.length).toBe(43);
    }
  });
  it('hop count and chain-level failures', () => {
    const k = keys();
    expect(why(pc(root(k), k))).toBe('expected an open mandate followed by one closed mandate, got 1 hop(s)');
    expect(why(pc(full(k), k, { expectedNonce: 'x' }))).toBe('hop 1: nonce mismatch');
  });
  it('open / closed problems and missing exp', () => {
    const k = keys();
    const cnf = { jwk: k.agent.publicJwk as unknown as JsonObject };
    const closedOk = { vct: 'mandate.payment.1', transaction_id: 'T', payee: M1 as unknown as JsonObject, payment_amount: { amount: 1, currency: 'USD' }, payment_instrument: { id: 'p', type: 'card' } } as JsonObject;
    const run = (open: JsonObject, closed: JsonObject) => pc(hop(root(k, { mandate: open }), k.agent, { aud: 'cp', nonce: 'pn', mandate: closed }), k);
    const badOpen = { vct: 'x', cnf, constraints: 5 } as JsonObject;
    expect(why(run(badOpen, closedOk))).toBe(`open payment mandate: ${openPaymentMandateProblems(badOpen).join('; ')}`);
    const noExp = { vct: 'mandate.payment.open.1', cnf, constraints: payCons('REF') } as unknown as JsonObject;
    expect(openPaymentMandateProblems(noExp)).toEqual([]);
    expect(why(run(noExp, closedOk))).toBe('open payment mandate: an open mandate must carry exp');
    const okOpen = { ...noExp, exp: NOW_S + 100 } as JsonObject;
    const badClosed = { vct: 'y', transaction_id: '', payee: M1, payment_amount: { amount: 1, currency: 'USD' }, payment_instrument: { id: 'p', type: 'card' } } as unknown as JsonObject;
    expect(why(run(okOpen, badClosed))).toBe('closed payment mandate: vct: must be mandate.payment.1; transaction_id: required string');
  });
  it('expectedTransactionId', () => {
    const k = keys();
    const t = full(k);
    expect(why(pc(t, k, { expectedTransactionId: 'T' }))).toBe('ACCEPTED');
    expect(why(pc(t, k, { expectedTransactionId: 'U' }))).toBe('transaction_id does not match the checkout being settled');
  });
  it('constraint violations are listed, with the context forwarded', () => {
    const k = keys();
    const t = full(k, { paymentAmount: { amount: 60000, currency: 'EUR' } });
    const r = pc(t, k);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.violations).toEqual(['currency mismatch: expected USD, got EUR', 'amount 60000 exceeds maximum 50000']);
      expect(r.reason).toBe('open payment constraints violated: currency mismatch: expected USD, got EUR; amount 60000 exceeds maximum 50000');
    }
    const budgeted = full(k, {}, openPay(k, { constraints: [...payCons('REF'), { type: 'payment.budget', currency: 'USD', max: 50 }] }));
    expect(why(pc(budgeted, k, { context: { totalAmount: 1500, totalUses: 0 } }))).toBe('open payment constraints violated: cumulative spend 5500 exceeds budget 5000 (past spend 1500)');
    expect(why(pc(budgeted, k, { context: { totalAmount: 1000, totalUses: 0 } }))).toBe('ACCEPTED');
    expect(why(pc(budgeted, k))).toBe('open payment constraints violated: mandate context is required to evaluate a budget');
  });
  it('wrong reference hash is a violation', () => {
    const k = keys();
    expect(why(pc(full(k), k, { openCheckoutHash: 'OTHER' }))).toBe('open payment constraints violated: payment.reference does not match the open checkout mandate hash');
  });
});

describe('verifyKbHop called directly', () => {
  it('index is -1 until the chain verifier numbers it, and a terminal hop needs an expected audience and nonce to compare', () => {
    const k = keys();
    const r = root(k);
    const prevHop = parseSdJwtHop(r);
    const prev = { hop: prevHop, mandate: mandateOf(r) };
    const tok = hop(r, k.agent, { aud: undefined as never, nonce: undefined as never });
    const h = parseSdJwtHop(splitChain(tok)[1] as string);
    const ok = verifyKbHop(h, prev, { terminal: true, expectedAudience: AUD, expectedNonce: NONCE, now: NOW, skew: 60 }, 'h');
    expect(ok.index).toBe(-1);
    expect(ok.kind).toBe('terminal');
    // a hop with no aud claim must not pass when the verifier names no audience either
    const noAud = parseSdJwtHop(splitChain(hopWithoutClaims(r, k, ['aud']))[1] as string);
    expect(() => verifyKbHop(noAud, prev, { terminal: true, expectedNonce: NONCE, now: NOW, skew: 60 }, 'h')).toThrow(new Ap2Error('h: aud mismatch'));
    const noNonce = parseSdJwtHop(splitChain(hopWithoutClaims(r, k, ['nonce']))[1] as string);
    expect(() => verifyKbHop(noNonce, prev, { terminal: true, expectedAudience: AUD, now: NOW, skew: 60 }, 'h')).toThrow(new Ap2Error('h: nonce mismatch'));
  });
});

function hopWithoutClaims(prev: string, k: Keys, omit: string[]): string {
  const prevHop = parseSdJwtHop(prev);
  const b = disclosureBuilder(prevHop.sdAlg, salter());
  const payload: JsonObject = { delegate_payload: [b.element({ vct: 'v' })], aud: AUD, nonce: NONCE, iat: NOW_S + 1, sd_hash: sdHashOf(prevHop), _sd_alg: prevHop.sdAlg };
  for (const o of omit) delete payload[o];
  return `${prev}~${signSdJwt({ header: { typ: 'kb+sd-jwt' }, payload, disclosures: b.disclosures, privateKey: k.agent.privateKey })}`;
}
