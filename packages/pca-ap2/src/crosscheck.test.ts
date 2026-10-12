/**
 * Independent-implementation cross-checks. The fixtures under fixtures/crosscheck/ were produced by running
 * the scripts in crosscheck/ against two implementations this package shares no code with:
 *
 *   - Google's official AP2 Python SDK at the pinned commit (MandateClient, PaymentMandateChain,
 *     CheckoutMandateChain, pydantic models, jwcrypto, py-sd-jwt);
 *   - the `@sd-jwt/core` JavaScript library.
 *
 * Both directions are exercised: tokens made by pca-ap2 verified by them (recorded results), and tokens made by
 * them verified here (live, with the real root signature).
 */
import { describe, expect, it } from 'vitest';
import {
  jwkThumbprint,
  parseSdJwtHop,
  processDisclosures,
  splitChain,
  verifyHopSignature,
  verifyPcaBinding,
  verifyPaymentChain,
  verifyCheckoutChain,
  verifyPurchase,
  type JsonObject,
  type P256Jwk,
  type VerifyPurchaseOptions,
} from './index';
import { readJson } from './testkit';
import { readEnvelope, type Capability } from '@atlasauth/pca';
import type { MandateTerms } from '@atlasauth/pca-payments';

interface Purchase {
  now: number;
  keys: { issuer: P256Jwk; merchant: P256Jwk; agent: P256Jwk };
  checkout: { token: string; aud: string; nonce: string; checkout_jwt: string; open_hash: string };
  payment: { token: string; aud: string; nonce: string };
  transaction_id: string;
  amount_minor: number;
}
interface Mine extends Purchase {
  ap2_commit: string;
  pca: { principal_public: string; audience: string };
  probes: Record<string, { token: string; description: string }>;
  thumbprints: { jwk: P256Jwk; jkt: string }[];
}
interface OfficialSdk {
  sdk: { commit: string; python: string; deps: Record<string, string> };
  mine_verified_by_official_sdk: {
    checkout_chain: { violations: string[]; checkout_hash: string };
    payment_chain: { violations: string[]; transaction_id: string; amount: number; currency: string };
    x_pca_ignored_by_pydantic: boolean;
  };
  sdk_rejects_tampering: Record<string, string | false>;
  probes: Record<string, { sdk_accepts: boolean; sdk_violations?: string[]; sdk_error?: string }>;
  thumbprints: { jwk: P256Jwk; jkt: string; mine: string }[];
  sdk_cannot_issue_agent_recurrence: string | null;
  sdk_issued: Purchase & { open_checkout_token: string; open_payment_token: string };
}
interface JsHop { source: string; index: number; claims: JsonObject; verified: { ok: boolean; header: Record<string, unknown> } | null }
interface SdJwtJs {
  generator: string;
  mine: JsHop[];
  docs: JsHop[];
  issued_by_sdjwt_js: Purchase;
}

const mine = readJson<Mine>('crosscheck/mine.json');
const sdk = readJson<OfficialSdk>('crosscheck/official-sdk.json');
const js = readJson<SdJwtJs>('crosscheck/sdjwt-js.json');

const optionsFor = (p: Purchase, now = p.now): VerifyPurchaseOptions => ({
  resolveIssuerKey: (h) => (h.kid === p.keys.issuer.kid ? p.keys.issuer : undefined),
  resolveMerchantKey: (h) => (h.kid === p.keys.merchant.kid ? p.keys.merchant : undefined),
  checkout: { expectedAudience: p.checkout.aud, expectedNonce: p.checkout.nonce },
  payment: { expectedAudience: p.payment.aud, expectedNonce: p.payment.nonce },
  context: { totalAmount: 0, totalUses: 0 },
  now,
});

describe('provenance of the cross-check runs', () => {
  it('ran against the pinned AP2 commit', () => {
    expect(sdk.sdk.commit).toBe(mine.ap2_commit);
    expect(sdk.sdk.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(sdk.sdk.deps).toMatchObject({ jwcrypto: '1.5.6', pydantic: '2.12.5', 'sd-jwt': '0.10.4' });
    expect(js.generator).toMatch(/@sd-jwt\/core 0\.22\.0/);
  });
});

describe('official AP2 Python SDK verifies what pca-ap2 issues (recorded run)', () => {
  it('accepts the PCA-bound purchase: signatures, key binding, sd_hash, merchant checkout, every open constraint', () => {
    const r = sdk.mine_verified_by_official_sdk;
    expect(r.checkout_chain.violations).toEqual([]);
    expect(r.payment_chain.violations).toEqual([]);
    expect(r.payment_chain.transaction_id).toBe(r.checkout_chain.checkout_hash);
    expect(r.payment_chain.transaction_id).toBe(mine.transaction_id);
    expect(r.payment_chain.amount).toBe(mine.amount_minor);
    expect(r.x_pca_ignored_by_pydantic).toBe(true); // the namespaced extension does not break the SDK's models
  });

  it('the SDK itself rejects a wrong nonce, a wrong audience and a flipped character', () => {
    for (const [k, v] of Object.entries(sdk.sdk_rejects_tampering)) expect(v, k).not.toBe(false);
  });

  it('RFC 7638 thumbprints agree with jwcrypto for every sampled key', () => {
    expect(sdk.thumbprints.length).toBeGreaterThanOrEqual(8);
    for (const t of sdk.thumbprints) {
      expect(t.jkt).toBe(t.mine);
      expect(jwkThumbprint(t.jwk)).toBe(t.jkt);
    }
  });
});

describe('the snapshot of that purchase still verifies here (regression), including the PCA binding', () => {
  it('verifyPurchase accepts it', () => {
    const r = verifyPurchase(mine.checkout.token, mine.payment.token, optionsFor(mine));
    expect(r.ok, r.ok ? '' : r.reason).toBe(true);
  });

  it('the PCA grant and PCActn inside verify against the recorded principal', async () => {
    const r = verifyPurchase(mine.checkout.token, mine.payment.token, optionsFor(mine));
    if (!r.ok) throw new Error(r.reason);
    // The verifier's held mandate state for this recorded purchase: the grant + terms it registered, a full budget.
    const xp = (r.payment.open as unknown as { x_pca: { grant: Capability; terms: MandateTerms } }).x_pca;
    const policy = readEnvelope(xp.grant)!.risk_policy;
    const held = { grant: xp.grant, terms: xp.terms, policy, budget: { B: policy.bMax, tau: mine.now * 1000, asOf: mine.now * 1000 } };
    const pcaRes = await verifyPcaBinding({
      open: r.payment.open, closed: r.payment.closed, openHash: r.payment.openHash,
      expectedPrincipal: mine.pca.principal_public, audience: mine.pca.audience, now: mine.now * 1000,
      mandate: held as never, recentChargeTimes: [],
    });
    expect(pcaRes.ok, pcaRes.ok ? '' : pcaRes.reason).toBe(true);
  });
});

describe('probes: where the official SDK is more permissive than pca-ap2 (both facts are pinned)', () => {
  const checkoutOpts = { resolveIssuerKey: optionsFor(mine).resolveIssuerKey, resolveMerchantKey: optionsFor(mine).resolveMerchantKey, expectedAudience: mine.checkout.aud, expectedNonce: mine.checkout.nonce, now: mine.now };

  it('control: an item the user never allowed is refused by both when the open mandate is intact', () => {
    expect(sdk.probes.forbidden_item_intact?.sdk_accepts).toBe(false);
    expect(verifyCheckoutChain((mine.probes.forbidden_item_intact as { token: string }).token, checkoutOpts).ok).toBe(false);
  });

  it('UPSTREAM FINDING: the SDK accepts a cart with fewer units than the open mandate requires; pca-ap2 refuses it (documented max-flow rule)', () => {
    expect(sdk.probes.under_quantity?.sdk_accepts).toBe(true);
    const r = verifyCheckoutChain((mine.probes.under_quantity as { token: string }).token, checkoutOpts);
    expect(!r.ok && r.reason).toMatch(/assigned 1 of 2 required/);
  });

  it('UPSTREAM FINDING: withholding every acceptable_items disclosure turns the requirement into a wildcard in the SDK; pca-ap2 refuses it', () => {
    expect(sdk.probes.withheld_acceptable_items?.sdk_accepts).toBe(true);
    const r = verifyCheckoutChain((mine.probes.withheld_acceptable_items as { token: string }).token, checkoutOpts);
    expect(!r.ok && r.reason).toMatch(/line items do not satisfy/);
  });

  it('UPSTREAM FINDING: the SDK cannot issue an open payment mandate containing payment.agent_recurrence (enum not JSON-serialisable)', () => {
    expect(sdk.sdk_cannot_issue_agent_recurrence).toMatch(/Frequency is not JSON serializable/);
  });
});

describe('tokens ISSUED by the official Python SDK verify here, end to end including the root signature', () => {
  const p = sdk.sdk_issued;

  it('verifyPurchase accepts the complete SDK-issued purchase', () => {
    const r = verifyPurchase(p.checkout.token, p.payment.token, optionsFor(p));
    expect(r.ok, r.ok ? '' : r.reason).toBe(true);
    if (r.ok) {
      expect(r.payment.closed.transaction_id).toBe(p.transaction_id);
      expect(r.payment.closed.payment_amount).toEqual({ amount: p.amount_minor, currency: 'USD' });
      expect(r.checkout.openHash).toBe(p.checkout.open_hash);
    }
  });

  it('and refuses it under the wrong issuer key, wrong nonce, or after expiry', () => {
    const wrongKey = { ...optionsFor(p), resolveIssuerKey: () => sdk.sdk_issued.keys.agent };
    expect(verifyPurchase(p.checkout.token, p.payment.token, wrongKey).ok).toBe(false);
    expect(verifyPurchase(p.checkout.token, p.payment.token, { ...optionsFor(p), payment: { expectedAudience: p.payment.aud, expectedNonce: 'x' } }).ok).toBe(false);
    expect(verifyPurchase(p.checkout.token, p.payment.token, optionsFor(p, p.now + 7200)).ok).toBe(false);
  });

  it('the SDK emits float-spelled budgets (1000.0); they parse and evaluate as 100000 minor units', () => {
    const [open] = splitChain(p.payment.token);
    const hop = parseSdJwtHop(open as string);
    const claims = processDisclosures(hop.payload, hop.disclosures, hop.sdAlg);
    const m = (claims.delegate_payload as JsonObject[])[0] as JsonObject;
    expect((m.constraints as JsonObject[]).find((c) => c.type === 'payment.budget')?.max).toBe(1000);
    const spent = verifyPurchase(p.checkout.token, p.payment.token, { ...optionsFor(p), context: { totalAmount: 96_001, totalUses: 1 } });
    expect(!spent.ok && spent.reason).toMatch(/exceeds budget 100000/);
    expect(verifyPaymentChain).toBeDefined();
  });
});

describe('@sd-jwt/core (independent JavaScript implementation)', () => {
  const hopsOf = (rows: JsHop[], source: string): JsHop[] => rows.filter((r) => r.source === source);

  it('every hop of the purchase made by pca-ap2 verified under @sd-jwt/core (signature, digests, array disclosures)', () => {
    expect(js.mine).toHaveLength(4);
    for (const h of js.mine) expect(h.verified?.ok, `${h.source}#${h.index}`).toBe(true);
    // the closed hops carry the AP2 key-binding type
    expect(js.mine.filter((h) => h.index === 1).every((h) => h.verified?.header.typ === 'kb+sd-jwt')).toBe(true);
  });

  it('disclosure processing gives the same claims as @sd-jwt/core for every hop (mine and the six official tokens)', () => {
    const compare = (token: string, rows: JsHop[]): void => {
      const parts = splitChain(token).map(parseSdJwtHop);
      expect(rows).toHaveLength(parts.length);
      parts.forEach((hop, i) => {
        const ours = processDisclosures(hop.payload, hop.disclosures, hop.sdAlg);
        const theirs = { ...(rows[i] as JsHop).claims } as Record<string, unknown>;
        delete theirs._sd_alg;
        expect(ours, rows[i]?.source).toEqual(theirs);
      });
    };
    compare(mine.checkout.token, hopsOf(js.mine, 'checkout'));
    compare(mine.payment.token, hopsOf(js.mine, 'payment'));
    const docTokens = readJson<{ heading: string; token: string }[]>('ap2-doc-encoded-tokens.json');
    for (const t of docTokens) compare(t.token, hopsOf(js.docs, t.heading));
  });

  it('the official documentation\'s closed hops verify under @sd-jwt/core and under this package with the same key', () => {
    const verifiedDocs = js.docs.filter((h) => h.verified);
    expect(verifiedDocs.length).toBe(4);
    const docTokens = readJson<{ heading: string; token: string }[]>('ap2-doc-encoded-tokens.json');
    const open = parseSdJwtHop(splitChain(docTokens[0]?.token ?? '')[0] as string);
    const agent = ((processDisclosures(open.payload, open.disclosures, open.sdAlg).delegate_payload as JsonObject[])[0] as { cnf: { jwk: P256Jwk } }).cnf.jwk;
    for (const h of verifiedDocs) {
      const t = docTokens.find((x) => x.heading === h.source);
      const hop = parseSdJwtHop(splitChain(t?.token ?? '').pop() as string);
      expect(verifyHopSignature(hop, agent), h.source).toBe(true);
    }
  });

  it('an AP2-shaped purchase ISSUED by @sd-jwt/core verifies here end to end', () => {
    const p = js.issued_by_sdjwt_js;
    const r = verifyPurchase(p.checkout.token, p.payment.token, optionsFor(p));
    expect(r.ok, r.ok ? '' : r.reason).toBe(true);
    if (r.ok) expect(r.payment.closed.transaction_id).toBe(p.transaction_id);
  });
});
