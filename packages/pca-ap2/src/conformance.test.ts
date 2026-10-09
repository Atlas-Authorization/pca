/**
 * Conformance tests against the published AP2 (Agent Payments Protocol) and x402 materials.
 *
 *  - The official AP2 JSON Schemas and the example payloads from the AP2 documentation are committed
 *    as fixtures (fixtures/PROVENANCE.json: repository, commit, sha256) and checked with an
 *    independent JSON Schema validator (Ajv, draft 2020-12). The fixtures themselves are validated
 *    first (schema accepts the documented examples; SD-JWT disclosure digests match).
 *  - This package's mandate chain is then checked against the same schemas. It is a PCA rendition
 *    modelled on the Intent / Cart / Payment concepts as W3C-style credentials; the current AP2
 *    schemas define SD-JWT based mandates with different claims. Those tests pin that difference
 *    (known-gap tests) so it cannot be mistaken for wire compatibility.
 *  - x402: the v1 HTTP transport examples and the PaymentRequirements field table from the x402
 *    specification are used to check the structural settlement output. Settlement is STRUCTURAL: no
 *    network, no signing; the X-PAYMENT payload is a placeholder envelope, not a signed authorization.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv2020 from 'ajv/dist/2020';
import type { ErrorObject, ValidateFunction } from 'ajv/dist/2020';
import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import { buildPaymentMandate, type PaymentMandateParams } from '@atlasauth/pca-payments';
import {
  stripeSptSettlement,
  toAP2CartMandate,
  toAP2IntentMandate,
  toAP2PaymentMandate,
  x402Settlement,
  type CartItem,
  type PaymentMandate,
} from './index';

const FIX = join(__dirname, '..', 'fixtures');
const readText = (rel: string): string => readFileSync(join(FIX, rel), 'utf8');
const readJson = <T>(rel: string): T => JSON.parse(readText(rel)) as T;

interface Provenance {
  ap2Commit: string;
  x402Commit: string;
  files: { file: string; sha256: string; kind: string; source: string | string[] }[];
}
const PROV = readJson<Provenance>('PROVENANCE.json');

describe('fixtures', () => {
  it('match the sha256 recorded in PROVENANCE.json and cite a pinned upstream commit', () => {
    expect(PROV.ap2Commit).toMatch(/^[0-9a-f]{40}$/);
    expect(PROV.x402Commit).toMatch(/^[0-9a-f]{40}$/);
    expect(PROV.files.length).toBeGreaterThanOrEqual(13);
    for (const f of PROV.files) {
      expect(createHash('sha256').update(readFileSync(join(FIX, f.file))).digest('hex'), f.file).toBe(f.sha256);
      expect(f.kind).toMatch(/^official-/);
      expect(JSON.stringify(f.source)).toMatch(/[0-9a-f]{40}/);
    }
  });
});

// ---------------------------------------------------------------------------
// Official AP2 schemas + documented examples
// ---------------------------------------------------------------------------

function loadAjv(): Ajv2020 {
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  for (const f of PROV.files.filter((x) => x.file.startsWith('ap2-schemas/'))) ajv.addSchema(readJson<object>(f.file));
  return ajv;
}
const ajv = loadAjv();
const validator = (id: string): ValidateFunction => {
  const v = ajv.getSchema(id);
  if (!v) throw new Error(`schema ${id} not loaded`);
  return v;
};
const PAYMENT_MANDATE = 'https://ap2-protocol.org/schemas/payment_mandate.json';
const OPEN_PAYMENT_MANDATE = 'https://ap2-protocol.org/schemas/payment_mandate_open.json';
const CHECKOUT_MANDATE = 'https://ap2-protocol.org/schemas/checkout_mandate.json';

interface DocExample {
  doc: string;
  heading: string;
  example: {
    issuer_signed_jwt?: { header: Record<string, unknown>; payload: Record<string, unknown> };
    disclosures?: { digest: string; decoded: unknown[] }[];
  } & Record<string, unknown>;
}
const DOC_EXAMPLES = readJson<DocExample[]>('ap2-doc-examples.json');
const TOKENS = readJson<{ doc: string; heading: string; token: string }[]>('ap2-doc-encoded-tokens.json');

/**
 * SD-JWT processing for array elements: replace every `{ "...": <digest> }` placeholder with the
 * disclosed value whose digest it names (recursively), so the claims can be validated as a verifier
 * would see them after processing the disclosures.
 */
function resolveSd(value: unknown, byDigest: Map<string, unknown>): unknown {
  if (Array.isArray(value)) return value.map((v) => resolveSd(v, byDigest));
  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj);
    if (keys.length === 1 && keys[0] === '...') {
      const digest = obj['...'];
      if (typeof digest !== 'string' || !byDigest.has(digest)) throw new Error(`unresolvable SD-JWT digest ${String(digest)}`);
      return resolveSd(byDigest.get(digest), byDigest);
    }
    return Object.fromEntries(keys.map((k) => [k, resolveSd(obj[k], byDigest)]));
  }
  return value;
}

/** Every disclosed claim set whose `vct` equals `vct`, with array-element disclosures resolved. */
function disclosedClaims(vct: string): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const ex of DOC_EXAMPLES) {
    const byDigest = new Map<string, unknown>();
    for (const d of ex.example.disclosures ?? []) byDigest.set(d.digest, d.decoded[1]);
    for (const d of ex.example.disclosures ?? []) {
      const claims = d.decoded[1];
      if (claims !== null && typeof claims === 'object' && (claims as { vct?: unknown }).vct === vct) {
        out.push(resolveSd(claims, byDigest) as Record<string, unknown>);
      }
    }
  }
  return out;
}

const failures = (v: ValidateFunction): ErrorObject[] => v.errors ?? [];
const missing = (errs: ErrorObject[]): string[] =>
  errs.filter((e) => e.keyword === 'required').map((e) => String((e.params as { missingProperty: string }).missingProperty)).sort();

describe('official AP2 documentation examples validate against the official schemas', () => {
  it('the closed Payment Mandate disclosed in the documentation is valid', () => {
    const claims = disclosedClaims('mandate.payment.1');
    expect(claims.length).toBeGreaterThanOrEqual(1);
    const v = validator(PAYMENT_MANDATE);
    for (const c of claims) expect(v(c), JSON.stringify(failures(v))).toBe(true);
  });

  it('the open Payment Mandate disclosed in the documentation is valid', () => {
    const claims = disclosedClaims('mandate.payment.open.1');
    expect(claims.length).toBeGreaterThanOrEqual(1);
    const v = validator(OPEN_PAYMENT_MANDATE);
    for (const c of claims) expect(v(c), JSON.stringify(failures(v))).toBe(true);
  });

  it('a closed Payment Mandate with an amount that is not integer minor units is rejected by the schema (negative control)', () => {
    const [claims] = disclosedClaims('mandate.payment.1');
    const bad = { ...(claims as object), payment_amount: { amount: 199.0 + 0.5, currency: 'USD' } };
    const v = validator(PAYMENT_MANDATE);
    expect(v(bad)).toBe(false);
    expect(failures(v).some((e) => e.keyword === 'type' && e.instancePath === '/payment_amount/amount')).toBe(true);
  });

  it('the documented encoded SD-JWTs are internally consistent: each disclosure hashes to a digest in the issuer-signed payload', () => {
    expect(TOKENS.length).toBeGreaterThanOrEqual(4);
    for (const t of TOKENS) {
      const [jwt, ...rest] = t.token.split('~');
      const disclosures = rest.filter((x) => x.length > 0);
      const payloadPart = (jwt ?? '').split('.')[1];
      expect(payloadPart, t.heading).toBeDefined();
      const payloadText = Buffer.from(payloadPart ?? '', 'base64url').toString('utf8');
      expect(disclosures.length, t.heading).toBeGreaterThanOrEqual(1);
      const digestOf = (d: string): string => createHash('sha256').update(d, 'ascii').digest('base64url');
      // Every disclosure must be referenced by digest from the issuer-signed payload or from a sibling disclosure.
      const haystack = [payloadText, ...disclosures.map((d) => Buffer.from(d, 'base64url').toString('utf8'))].join('\n');
      // (A "chained" example carries the previous SD-JWT as one extra element, which is not digest-referenced.)
      const referenced = disclosures.filter((d) => haystack.includes(digestOf(d)));
      if (/chained/i.test(t.heading)) expect(referenced.length, t.heading).toBeGreaterThanOrEqual(1);
      else expect(referenced.length, t.heading).toBe(disclosures.length);
    }
  });
});

// ---------------------------------------------------------------------------
// This package's mandates against the same schemas (known gap)
// ---------------------------------------------------------------------------

const principal = generateKeyPair();
const merchantKey = generateKeyPair();
const payerKey = generateKeyPair();
const agentKey = generateKeyPair();
const pub = (k: { publicKey: Uint8Array }): string => encodeKey(k.publicKey);
const NOW = 1_700_000_000_000;

const params: PaymentMandateParams = {
  principalSecret: principal.secretKey,
  principalPublic: pub(principal),
  agentPublic: pub(agentKey),
  merchants: ['acme'],
  categories: ['saas'],
  currency: 'USD',
  perTransactionCap: 500,
  autoApproveThreshold: 50,
  cumulativeCap: 1000,
  periodMs: 30 * 24 * 3_600_000,
  now: NOW,
};
const items: CartItem[] = [{ sku: 'sku-1', name: 'Widget', quantity: 1, unit_price: { currency: 'USD', value: 120 } }];

function chain(): { payment: PaymentMandate } & ReturnType<typeof build> {
  return build();
}
function build() {
  const intent = toAP2IntentMandate(buildPaymentMandate(params), { issuerPublic: pub(principal), issuerSecret: principal.secretKey, now: NOW });
  const cart = toAP2CartMandate(intent, { merchant: 'acme', items, now: NOW }, { issuerPublic: pub(merchantKey), issuerSecret: merchantKey.secretKey });
  const payment = toAP2PaymentMandate(cart, {
    issuerPublic: pub(payerKey),
    issuerSecret: payerKey.secretKey,
    paymentMethod: { type: 'card', display: 'Visa 4242' },
    intent,
    now: NOW,
    humanPresent: true,
  });
  return { intent, cart, payment };
}

describe('known gap: this package\'s mandates are NOT the current official AP2 wire format', () => {
  it('a Payment Mandate VDC fails the official payment_mandate schema: every required SD-JWT claim is absent', () => {
    const { payment } = chain();
    const v = validator(PAYMENT_MANDATE);
    expect(v(payment)).toBe(false);
    expect(missing(failures(v))).toEqual(['payee', 'payment_amount', 'payment_instrument', 'transaction_id', 'vct']);
  });

  it('even the credentialSubject content fails: decimal amounts and the credential-style payment method do not fit the schema', () => {
    const { payment } = chain();
    const v = validator(PAYMENT_MANDATE);
    expect(v(payment.credentialSubject)).toBe(false);
    // The schema counts integer MINOR units under `payment_amount.amount`; this package carries a decimal `amount.value`.
    expect(missing(failures(v))).toContain('payment_amount');
    expect(payment.credentialSubject.amount.value).toBe(120);
    expect(Number.isInteger(payment.credentialSubject.amount.value * 100)).toBe(true); // convertible, but not converted
  });

  it('an Intent Mandate VDC is not an official open payment mandate (no vct / constraints / cnf)', () => {
    const { intent } = chain();
    const v = validator(OPEN_PAYMENT_MANDATE);
    expect(v(intent)).toBe(false);
    expect(missing(failures(v))).toEqual(['cnf', 'constraints', 'vct']);
  });

  it('a Cart Mandate VDC is not an official checkout mandate (no vct / checkout_jwt / checkout_hash)', () => {
    const { cart } = chain();
    const v = validator(CHECKOUT_MANDATE);
    expect(v(cart)).toBe(false);
    expect(missing(failures(v))).toEqual(['checkout_hash', 'checkout_jwt', 'vct']);
  });
});

// ---------------------------------------------------------------------------
// x402 v1 (structural settlement)
// ---------------------------------------------------------------------------

interface X402Fixture {
  transportHttpV1: {
    paymentRequiredBody: { x402Version: number; error: string; accepts: Record<string, unknown>[] };
    xPaymentHeader: string;
    paymentPayloadDecoded: Record<string, unknown>;
    settlementResponseDecoded: Record<string, unknown>;
  };
  specificationV1: {
    paymentRequirementsResponseRequiredFields: string[];
    paymentRequirementsFields: { field: string; type: string; required: boolean }[];
  };
}
const X402 = readJson<X402Fixture>('x402-v1-examples.json');

describe('x402 v1 structural settlement against the specification examples', () => {
  const run = (over?: Parameters<typeof x402Settlement.settle>[1]): {
    httpStatus: number;
    x402Version: number;
    error: string;
    accepts: Record<string, unknown>[];
    header: Record<string, string>;
  } => {
    const { payment } = chain();
    return x402Settlement.settle(payment, {
      resourceUrl: 'https://api.example.com/premium-data',
      payTo: '0x209693Bc6afc0C5328bA36FaF03C514EF312287C',
      network: 'base-sepolia',
      asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
      ...over,
    }).payload as never;
  };

  it('the specification\'s X-PAYMENT example decodes (standard base64) to the documented payload', () => {
    const decoded = JSON.parse(Buffer.from(X402.transportHttpV1.xPaymentHeader, 'base64').toString('utf8')) as unknown;
    expect(decoded).toEqual(X402.transportHttpV1.paymentPayloadDecoded);
  });

  it('the 402 body carries every required top-level field of PaymentRequirementsResponse', () => {
    const body = run();
    for (const f of X402.specificationV1.paymentRequirementsResponseRequiredFields) expect(body, f).toHaveProperty(f);
    expect(body.httpStatus).toBe(402);
    expect(body.x402Version).toBe(X402.transportHttpV1.paymentRequiredBody.x402Version);
  });

  it('each accepts[] entry has every Required PaymentRequirements field with the documented type', () => {
    const req = run().accepts[0];
    expect(req).toBeDefined();
    for (const f of X402.specificationV1.paymentRequirementsFields) {
      if (f.required) expect(req, f.field).toHaveProperty(f.field);
      if (req !== undefined && f.field in req) expect(typeof req[f.field], f.field).toBe(f.type);
    }
    // Same keys the specification's own example uses (ours may omit its optional outputSchema / extra).
    const specKeys = Object.keys(X402.transportHttpV1.paymentRequiredBody.accepts[0] ?? {});
    for (const k of Object.keys(req ?? {})) expect(specKeys).toContain(k);
  });

  it('maxAmountRequired is a string of ATOMIC units: 120 USD at 6 decimals is "120000000", not "120"', () => {
    const req = run().accepts[0];
    expect(req?.maxAmountRequired).toBe('120000000');
    expect(req?.maxAmountRequired).toMatch(/^\d+$/);
    expect(run({ decimals: 2 }).accepts[0]?.maxAmountRequired).toBe('12000');
    expect(run({ decimals: 0 }).accepts[0]?.maxAmountRequired).toBe('120');
  });

  it('asset and payTo are passed through when supplied (contract / wallet addresses as in the specification example)', () => {
    const req = run().accepts[0];
    expect(req?.asset).toBe(X402.transportHttpV1.paymentRequiredBody.accepts[0]?.asset);
    expect(req?.payTo).toBe(X402.transportHttpV1.paymentRequiredBody.accepts[0]?.payTo);
  });

  it('maxTimeoutSeconds is present and overridable', () => {
    expect(run().accepts[0]?.maxTimeoutSeconds).toBe(60);
    expect(run({ maxTimeoutSeconds: 15 }).accepts[0]?.maxTimeoutSeconds).toBe(15);
  });

  it('X-PAYMENT is standard base64 (not base64url) of JSON with the specification\'s envelope keys', () => {
    const header = run().header['X-PAYMENT'] ?? '';
    expect(header).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    expect(header.length % 4).toBe(0); // standard base64 is padded to a multiple of 4
    const decoded = JSON.parse(Buffer.from(header, 'base64').toString('utf8')) as Record<string, unknown>;
    for (const k of ['x402Version', 'scheme', 'network', 'payload']) expect(decoded).toHaveProperty(k);
    expect(Object.keys(decoded).sort()).toEqual(Object.keys(X402.transportHttpV1.paymentPayloadDecoded).sort());
  });

  it('known limit: the payload is a placeholder envelope, not a signed authorization', () => {
    const header = run().header['X-PAYMENT'] ?? '';
    const decoded = JSON.parse(Buffer.from(header, 'base64').toString('utf8')) as { payload: Record<string, unknown> };
    expect(decoded.payload).not.toHaveProperty('signature');
    expect(decoded.payload).not.toHaveProperty('authorization');
  });

  it('refuses amounts and decimals that cannot be expressed exactly in atomic units (fail closed)', () => {
    const { payment } = chain();
    const bad = (value: number): PaymentMandate => ({
      ...payment,
      credentialSubject: { ...payment.credentialSubject, amount: { currency: 'USD', value } },
    });
    expect(() => x402Settlement.settle(bad(-1))).toThrow(/atomic units/);
    expect(() => x402Settlement.settle(bad(Number.NaN))).toThrow(/atomic units/);
    expect(() => x402Settlement.settle(bad(Number.POSITIVE_INFINITY))).toThrow(/atomic units/);
    expect(() => x402Settlement.settle(bad(1e300))).toThrow(/atomic units/);
    expect(() => x402Settlement.settle(payment, { decimals: 19 })).toThrow(/decimals/);
    expect(() => x402Settlement.settle(payment, { decimals: -1 })).toThrow(/decimals/);
    expect(() => x402Settlement.settle(payment, { decimals: 1.5 })).toThrow(/decimals/);
  });
});

describe('Stripe Shared Payment Token settlement', () => {
  it('is structural only: no official Stripe vector is committed, so only the minor-unit conversion is asserted', () => {
    const { payment } = chain();
    const inst = stripeSptSettlement.settle(payment, { payTo: 'acct_merchant' });
    const p = inst.payload as { amount: number; currency: string };
    expect(p.amount).toBe(12000);
    expect(p.currency).toBe('usd');
  });
});
