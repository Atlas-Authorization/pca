/**
 * Replay of the official AP2 documentation examples (fixtures/ap2-doc-encoded-tokens.json, extracted
 * verbatim from docs/ap2/{payment,checkout}_mandate.md at the pinned commit) through this package's
 * parser and verifier, byte for byte:
 *   - each encoded token re-serialises to exactly the published bytes;
 *   - every disclosure digest, `sd_hash`, `checkout_hash`, `transaction_id` and `payment.reference`
 *     recomputes to the published value;
 *   - the closed hops' ES256 signatures (made by Google's reference code) verify under the `cnf.jwk`
 *     of the open mandate, using this package's verifier;
 *   - every processed mandate validates against the official JSON Schemas (Ajv).
 * The root (open) signatures cannot be checked: the documentation never publishes the issuer key
 * ("agent-provider-key-1" is generated per run by the sample code).
 */
import { describe, expect, it } from 'vitest';
import {
  Ap2Error,
  assertP256Jwk,
  checkoutMandateProblems,
  generateAp2KeyPair,
  openCheckoutMandateProblems,
  openPaymentMandateProblems,
  paymentMandateProblems,
  parseSdJwtHop,
  processDisclosures,
  sdDigest,
  sdHashOf,
  splitChain,
  verifyDelegationChain,
  verifyHopSignature,
  verifyKbHop,
  verifyJwtEs256,
  projectCheckout,
  checkoutTotal,
  checkCheckoutConstraints,
  checkPaymentConstraints,
  type OpenCheckoutMandateClaims,
  type OpenPaymentMandateClaims,
  type PaymentMandateClaims,
  parseJwt,
  type JsonObject,
  type SdJwtHop,
} from './index';
import { PROV, readJson, schema, SCHEMA_ID, sha256hex } from './testkit';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const TOKENS = readJson<{ doc: string; heading: string; token: string }[]>('ap2-doc-encoded-tokens.json');
const DOC_EXAMPLES = readJson<{ doc: string; heading: string; example: { disclosures?: { digest: string; decoded: unknown[] }[] } }[]>('ap2-doc-examples.json');
const tokenOf = (doc: string, headingStart: string): string => {
  const t = TOKENS.find((x) => x.doc.endsWith(doc) && x.heading.startsWith(headingStart));
  if (!t) throw new Error(`no token ${doc} / ${headingStart}`);
  return t.token;
};

// The documented values the examples were produced with (taken from the same documents).
const DOC_TIME = 1_777_342_400; // inside every documented iat..exp window
interface Replayed {
  hops: SdJwtHop[];
  claims: JsonObject[];
  mandates: JsonObject[];
}
function replay(token: string): Replayed {
  const hops = splitChain(token).map(parseSdJwtHop);
  const claims = hops.map((h) => processDisclosures(h.payload, h.disclosures, h.sdAlg));
  const mandates = claims.map((c) => (c.delegate_payload as JsonObject[])[0] as JsonObject);
  return { hops, claims, mandates };
}

describe('fixtures', () => {
  it('match the sha256 recorded in PROVENANCE.json and cite the pinned upstream commits', () => {
    expect(PROV.ap2Commit).toMatch(/^[0-9a-f]{40}$/);
    expect(PROV.x402Commit).toMatch(/^[0-9a-f]{40}$/);
    for (const f of PROV.files) {
      expect(sha256hex(readFileSync(join(__dirname, '..', 'fixtures', f.file))), f.file).toBe(f.sha256);
      expect(JSON.stringify(f.source)).toMatch(/[0-9a-f]{40}/);
    }
  });
});

const AGENT_CNF = (replay(tokenOf('payment_mandate.md', 'Open Payment Mandate SD-JWT')).mandates[0] as { cnf: { jwk: unknown } }).cnf.jwk as { crv: string; kty: string; x: string; y: string };

describe('official documentation tokens, byte for byte', () => {
  it('all six documented encoded tokens are present', () => {
    expect(TOKENS).toHaveLength(6);
  });

  for (const t of TOKENS) {
    describe(t.heading, () => {
      it('re-serialises to exactly the published bytes', () => {
        const hops = splitChain(t.token).map(parseSdJwtHop);
        expect(hops.map((h) => h.raw).join('~')).toBe(t.token);
        for (const h of hops) {
          expect(h.raw).toBe(`${h.jwt}~${h.disclosures.map((d) => `${d}~`).join('')}`);
          expect(h.header.alg).toBe('ES256');
          expect(h.sdAlg).toBe('sha-256');
          expect(h.signature).toHaveLength(64);
        }
      });

      it('every disclosure is referenced and digests resolve (strict RFC 9901 processing)', () => {
        const { claims } = replay(t.token);
        for (const c of claims) {
          expect(c.delegate_payload).toHaveLength(1);
          expect(JSON.stringify(c)).not.toContain('"..."');
          expect(JSON.stringify(c)).not.toContain('"_sd"');
        }
      });

      it('each processed mandate validates against the official JSON Schemas (Ajv) and this package\'s validators', () => {
        const { mandates } = replay(t.token);
        const table: Record<string, [string, (v: unknown) => string[]]> = {
          'mandate.payment.open.1': [SCHEMA_ID.openPayment, openPaymentMandateProblems],
          'mandate.payment.1': [SCHEMA_ID.payment, paymentMandateProblems],
          'mandate.checkout.open.1': [SCHEMA_ID.openCheckout, openCheckoutMandateProblems],
          'mandate.checkout.1': [SCHEMA_ID.checkout, checkoutMandateProblems],
        };
        for (const m of mandates) {
          const entry = table[String(m.vct)];
          expect(entry, String(m.vct)).toBeDefined();
          const [id, problems] = entry as [string, (v: unknown) => string[]];
          const v = schema(id);
          expect(v(m), JSON.stringify(v.errors)).toBe(true);
          expect(problems(m)).toEqual([]);
        }
      });
    });
  }

  it('the open payment mandate: structure, constraints and agent key', () => {
    const { mandates, hops } = replay(tokenOf('payment_mandate.md', 'Open Payment Mandate SD-JWT'));
    const m = mandates[0] as JsonObject;
    expect(hops[0]?.header).toEqual({ alg: 'ES256', typ: 'example+sd-jwt', kid: 'agent-provider-key-1' });
    expect(m.vct).toBe('mandate.payment.open.1');
    expect((m.cnf as { jwk: unknown }).jwk).toEqual(AGENT_CNF);
    expect(m.iat).toBe(1_777_342_357);
    expect(m.exp).toBe(1_777_345_957);
    const [range, payees, ref] = m.constraints as JsonObject[];
    expect(range).toEqual({ type: 'payment.amount_range', currency: 'USD', max: 20000, min: 0 });
    expect(payees).toEqual({ type: 'payment.allowed_payees', allowed: [{ id: 'merchant_1', name: 'Demo Merchant', website: 'https://demo-merchant.example' }] });
    expect((ref as JsonObject).type).toBe('payment.reference');
  });

  it('the closed hop signatures (made by Google\'s reference SDK) verify under the open mandate\'s cnf.jwk with this verifier', () => {
    const cases: [string, string, string, string][] = [
      ['payment_mandate.md', 'Open Payment Mandate chained', 'credential-provider', 'a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3'],
      ['checkout_mandate.md', 'Open Checkout Mandate chained', 'merchant', 'b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4'],
    ];
    for (const [doc, heading, aud, nonce] of cases) {
      const r = replay(tokenOf(doc, heading));
      expect(r.hops).toHaveLength(2);
      const root = { hop: r.hops[0] as SdJwtHop, mandate: r.mandates[0] as JsonObject };
      const v = verifyKbHop(r.hops[1] as SdJwtHop, root, { terminal: true, expectedAudience: aud, expectedNonce: nonce, now: DOC_TIME, skew: 60 }, 'doc hop');
      expect(v.kind).toBe('terminal');
      // and directly:
      expect(verifyHopSignature(r.hops[1] as SdJwtHop, assertP256Jwk(AGENT_CNF, 'doc'))).toBe(true);
    }
  });

  it('sd_hash of each open token equals the documented value, recomputed from the bytes', () => {
    const pay = replay(tokenOf('payment_mandate.md', 'Open Payment Mandate chained'));
    expect(sdHashOf(pay.hops[0] as SdJwtHop)).toBe('uixoHemmfrrCSbPREo9j-ziLuMkqExsPeWrwA-PK0Ck');
    expect(pay.claims[1]?.sd_hash).toBe('uixoHemmfrrCSbPREo9j-ziLuMkqExsPeWrwA-PK0Ck');
    const co = replay(tokenOf('checkout_mandate.md', 'Open Checkout Mandate chained'));
    expect(sdHashOf(co.hops[0] as SdJwtHop)).toBe('FzLoxbbtgQGYZxoSM2NJYJtkFTSsdfUBoVEQ12k7JN8');
    expect(co.claims[1]?.sd_hash).toBe('FzLoxbbtgQGYZxoSM2NJYJtkFTSsdfUBoVEQ12k7JN8');
  });

  it('the documented purchase is internally bound: reference = open checkout sd_hash, transaction_id = checkout_hash = hash(checkout_jwt)', () => {
    const pay = replay(tokenOf('payment_mandate.md', 'Open Payment Mandate chained'));
    const co = replay(tokenOf('checkout_mandate.md', 'Open Checkout Mandate chained'));
    const ref = ((pay.mandates[0] as JsonObject).constraints as JsonObject[]).find((c) => c.type === 'payment.reference');
    expect(ref?.conditional_transaction_id).toBe(sdHashOf(co.hops[0] as SdJwtHop));
    const closedCheckout = co.mandates[1] as JsonObject;
    const closedPayment = pay.mandates[1] as JsonObject;
    expect(sdDigest(String(closedCheckout.checkout_jwt))).toBe(closedCheckout.checkout_hash);
    expect(closedPayment.transaction_id).toBe(closedCheckout.checkout_hash);
    expect(closedPayment.payment_amount).toEqual({ amount: 19900, currency: 'USD' });
  });

  it('the documented checkout_jwt is a three-part ES256 JWT whose payload is the documented checkout', () => {
    const co = replay(tokenOf('checkout_mandate.md', 'Closed Checkout Mandate'));
    const jwt = parseJwt(String((co.mandates[0] as JsonObject).checkout_jwt), 'doc checkout_jwt');
    expect(jwt.header).toEqual({ alg: 'ES256', typ: 'JWT', kid: 'merchant-key-1' });
    expect(jwt.payload.id).toBe('09414145-b70b-483a-b85c-aa0fa0c45800');
    const checkout = projectCheckout(jwt.payload);
    expect(checkoutTotal(checkout)).toBe(19900);
    expect(checkout.line_items[0]?.item.price).toBe(19900); // integer minor units (the documentation's JSON block shows 199.0)
    // The merchant key is not published, so a signature check against an unrelated key must fail closed.
    expect(verifyJwtEs256(jwt, generateAp2KeyPair().publicJwk)).toBe(false);
  });

  it('the documented purchase satisfies its own open constraints, evaluated from the real tokens', () => {
    const pay = replay(tokenOf('payment_mandate.md', 'Open Payment Mandate chained'));
    const co = replay(tokenOf('checkout_mandate.md', 'Open Checkout Mandate chained'));
    const jwt = parseJwt(String((co.mandates[1] as JsonObject).checkout_jwt), 'checkout_jwt');
    const checkout = projectCheckout(jwt.payload);
    expect(checkCheckoutConstraints(co.mandates[0] as unknown as OpenCheckoutMandateClaims, checkout)).toEqual([]);
    const openHash = sdHashOf(co.hops[0] as SdJwtHop);
    const open = pay.mandates[0] as unknown as OpenPaymentMandateClaims;
    const closed = pay.mandates[1] as unknown as PaymentMandateClaims;
    expect(checkPaymentConstraints(open, closed, { openCheckoutHash: openHash, now: DOC_TIME })).toEqual([]);
    // amount over the documented 20000 cap, a different payee, a different checkout: each is a violation
    const over = { ...closed, payment_amount: { amount: 20001, currency: 'USD' } };
    expect(checkPaymentConstraints(open, over, { openCheckoutHash: openHash, now: DOC_TIME })).toEqual(['amount 20001 exceeds maximum 20000']);
    const other = { ...closed, payee: { id: 'merchant_9', name: 'Other', website: 'https://other.example' } };
    expect(checkPaymentConstraints(open, other, { openCheckoutHash: openHash, now: DOC_TIME })).toHaveLength(1);
    expect(checkPaymentConstraints(open, closed, { openCheckoutHash: 'not-the-hash', now: DOC_TIME })).toEqual(['payment.reference does not match the open checkout mandate hash']);
  });

  it('documentation finding: the decoded JSON blocks in the docs differ from the encoded tokens; the tokens are the source of truth', () => {
    const tok = replay(tokenOf('payment_mandate.md', 'Open Payment Mandate SD-JWT')).mandates[0] as JsonObject;
    const ex = DOC_EXAMPLES.find((e) => e.heading.startsWith('Open Payment Mandate SD-JWT'));
    const docMandate = ex?.example.disclosures?.find((d) => (d.decoded[1] as { vct?: string }).vct === 'mandate.payment.open.1')?.decoded[1] as JsonObject;
    const leaves = (v: unknown, p = ''): [string, unknown][] =>
      typeof v === 'object' && v !== null ? Object.entries(v).flatMap(([k, x]) => leaves(x, `${p}/${k}`)) : [[p, v]];
    const a = new Map(leaves(tok));
    const b = new Map(leaves(docMandate).filter(([p]) => !p.includes('/allowed/')));
    const differing = [...b].filter(([p, v]) => a.get(p) !== v && !p.includes('/allowed/')).map(([p]) => p);
    // the only differences are single-character slips in the agent key coordinates
    expect(differing.sort()).toEqual(['/cnf/jwk/x', '/cnf/jwk/y']);
    // ...and the documented key is not even a point on P-256, so only the token's key verifies the signature
    expect(() => assertP256Jwk({ kty: 'EC', crv: 'P-256', ...(docMandate.cnf as { jwk: object }).jwk }, 'doc json')).toThrow(/valid P-256 point/);
  });

  describe('negative controls on the real tokens', () => {
    const open = tokenOf('payment_mandate.md', 'Open Payment Mandate chained');
    const flip = (s: string, at: number): string => s.slice(0, at) + (s[at] === 'A' ? 'B' : 'A') + s.slice(at + 1);

    it('a tampered disclosure is detected (digest no longer referenced)', () => {
      const hops = splitChain(open);
      const first = hops[0] as string;
      const parts = first.split('~');
      parts[2] = flip(parts[2] as string, 20);
      expect(() => replay([parts.join('~'), hops[1]].join('~'))).toThrow(Ap2Error);
    });

    it('a removed disclosure breaks the closed hop\'s sd_hash', () => {
      const hops = splitChain(open);
      const parts = (hops[0] as string).split('~');
      const dropped = `${parts[0]}~${parts[2]}~`; // payee disclosure withheld after the closed hop signed over everything
      const r = replay(open);
      const root = parseSdJwtHop(dropped);
      expect(() => verifyKbHop(r.hops[1] as SdJwtHop, { hop: root, mandate: r.mandates[0] as JsonObject }, { terminal: true, expectedAudience: 'credential-provider', expectedNonce: 'a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3', now: DOC_TIME, skew: 60 }, 'hop')).toThrow(/sd_hash/);
    });

    it('wrong audience / nonce / time are rejected', () => {
      const r = replay(open);
      const root = { hop: r.hops[0] as SdJwtHop, mandate: r.mandates[0] as JsonObject };
      const base = { terminal: true, expectedAudience: 'credential-provider', expectedNonce: 'a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3', now: DOC_TIME, skew: 60 };
      expect(() => verifyKbHop(r.hops[1] as SdJwtHop, root, { ...base, expectedAudience: 'someone-else' }, 'hop')).toThrow(/aud/);
      expect(() => verifyKbHop(r.hops[1] as SdJwtHop, root, { ...base, expectedNonce: 'replayed' }, 'hop')).toThrow(/nonce/);
      expect(() => verifyKbHop(r.hops[1] as SdJwtHop, root, { ...base, now: 1_777_000_000 }, 'hop')).toThrow(/future/);
    });

    it('a different agent key (not the cnf) cannot have signed the closed hop', () => {
      const r = replay(open);
      const other = generateAp2KeyPair();
      const root = { hop: r.hops[0] as SdJwtHop, mandate: { ...(r.mandates[0] as JsonObject), cnf: { jwk: other.publicJwk } } as unknown as JsonObject };
      expect(() => verifyKbHop(r.hops[1] as SdJwtHop, root, { terminal: true, expectedAudience: 'credential-provider', expectedNonce: 'a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3', now: DOC_TIME, skew: 60 }, 'hop')).toThrow(/signature/);
    });

    it('whole-chain verification fails closed at the root when the issuer key is not the signer', () => {
      const r = verifyDelegationChain(open, { resolveIssuerKey: () => generateAp2KeyPair().publicJwk, expectedAudience: 'credential-provider', expectedNonce: 'a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3', now: DOC_TIME });
      expect(r).toEqual({ ok: false, reason: 'root: signature does not verify under the issuer key' });
      const none = verifyDelegationChain(open, { resolveIssuerKey: () => undefined, expectedAudience: 'credential-provider', expectedNonce: 'x', now: DOC_TIME });
      expect(none.ok).toBe(false);
    });
  });
});
