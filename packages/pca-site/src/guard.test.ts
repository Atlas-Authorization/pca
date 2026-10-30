import { describe, expect, it } from 'vitest';
import {
  agent,
  generateKeyPair,
  hashCanonical,
  memoryPcaStore,
  pcaHeaders,
  pcactnDigest,
  type Capability,
  type PCActn,
} from '@atlasauth/pca';
import {
  PROBLEM_BASE,
  actionSchemaKeyOf,
  intentActionDigest,
  verifyIntentRequired,
  type ActionSchemaKey,
  type SignedIntentRequired,
} from '@atlasauth/pca/ext/intent';
import { buildKeyDirectory, jwkThumbprint, signRequest, signRequestWithProof } from '@atlasauth/pca-webbotauth';
import { PROBLEM_INSUFFICIENT_TIER, siteGuard, type IntentPort, type SiteGuardOptions, type SiteRequest } from './index';

const AUD = 'ins_shop';
const ORIGIN = 'https://shop.example';
const URL_REFUND = `${ORIGIN}/v1/refunds`;

const botKey = generateKeyPair();
const keyid = jwkThumbprint(botKey.publicKey);
const jwks = buildKeyDirectory([{ publicKey: botKey.publicKey, keyid }]);
const site = generateKeyPair();
const siteKey = { kid: 'shop-2026', secret: site.secretKey };
const siteKeys: ActionSchemaKey[] = [actionSchemaKeyOf('shop-2026', site.secretKey)];

const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
// the user's own instruction is the agent's only context, so its calls pass the provenance gate (authorize's default)
a.provenance?.principal('refund charge ch_1');
const grant = a.grant as Capability;
const act = (counter: number) => a.act('stripe.refund', 'charge:ch_1', { amount: 20, currency: 'usd' }, { counter });

const pca: NonNullable<SiteGuardOptions['pca']> = {
  resolveGrant: async () => grant,
  context: async () => ({
    params: { amount: 20, currency: 'usd' },
    budget: { B: 500, tau: 0 },
    risk: { semanticDistance: 0, reversibility: 0, blastRadius: 0.04, taint: 0, confidence: 1, age: 0 },
    planAuthorized: true,
  }),
  insecureAllowUnenforced: true, // full default-deny enforcement is requirePCA's own test suite
  insecureAllowUnboundOperation: true, // operation binding has its own tests below
};

const lower = (h: Record<string, string>) => Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), v]));
const D = (s: string) => hashCanonical({ t: s });

const QUESTION = {
  session: D('session'),
  map_digest: D('map'),
  schema: D('schema'),
  cell: { verb: 'stripe.refund', coords: { 'action.params.amount': [1, 2] as [number, number] } },
  question_id: 'q_7Hk2',
  friction: 'typed' as const,
};

function guardFor(tier: 0 | 1 | 2 | 3 | 4, extra: Partial<SiteGuardOptions> = {}, rule: Record<string, unknown> = {}) {
  return siteGuard({
    audience: AUD,
    policy: { tiers: { 'site.page': { tier: 0 }, 'stripe.refund': { tier, ...rule } }, web_bot_auth: { accept: true } },
    verbOf: (r) => (new URL(r.url).pathname === '/' ? 'site.page' : new URL(r.url).pathname === '/v1/refunds' ? 'stripe.refund' : null),
    webBotAuth: { jwks },
    pca,
    siteKey,
    ...extra,
  });
}

const pcaReq = (p: { encoded: string; provenance?: Parameters<typeof pcaHeaders>[1] }, url = URL_REFUND): SiteRequest => ({ method: 'POST', url, headers: lower(pcaHeaders(p.encoded, p.provenance)) });
const admit: IntentPort = async () => ({ kind: 'admit' });

describe('siteGuard construction (§5: configuration errors fail closed)', () => {
  it('refuses unknown options, unknown policy members and unreachable tiers', () => {
    expect(() => siteGuard({ audience: AUD, verbOf: () => null, bogus: 1 } as unknown as SiteGuardOptions)).toThrow(/unknown option/);
    expect(() => siteGuard({ audience: AUD, verbOf: () => null, policy: { tierz: {} } })).toThrow(/unknown member/);
    expect(() => siteGuard({ audience: AUD, verbOf: () => null, policy: { tiers: { x: { tier: 1 } } } })).toThrow(/web_bot_auth/);
    expect(() => siteGuard({ audience: AUD, verbOf: () => null, policy: { tiers: { x: { tier: 2 } } } })).toThrow(/requirePCA/);
    expect(() => siteGuard({ audience: AUD, verbOf: () => null, pca, intent: admit })).toThrow(/siteKey/);
    expect(() => siteGuard({ audience: AUD, verbOf: () => null, policy: { web_bot_auth: { accept: true } } })).toThrow(/jwks/);
    expect(() => siteGuard({ audience: AUD, verbOf: () => null, pca, policy: { tiers: { x: { tier: 2, rate: { max: 1, per_secs: 1 } } } } })).toThrow(/rateLimiter/);
  });
});

describe('Tier 2 operation binding (0.5)', () => {
  const policy = { tiers: { 'stripe.refund': { tier: 2 } } };
  const verbOf = () => 'stripe.refund';
  const bound: NonNullable<SiteGuardOptions['pca']> = { resolveGrant: pca.resolveGrant, context: pca.context, budgetStore: memoryPcaStore(), hooks: { revocation: async () => ({ enforced: true, ok: true }) }, plan: 'single-step' };
  it('pca without operation is refused at construction', () => {
    expect(() => siteGuard({ audience: AUD, verbOf, policy, pca: bound })).toThrow(/operation/);
  });
  it('the proof must be for the operation operation names', async () => {
    const mk = (amount: number) => siteGuard({ audience: AUD, verbOf, policy, pca: bound, operation: (_r, verb) => ({ verb, resource: 'charge:ch_1', params: { amount, currency: 'usd' } }) });
    expect(await mk(20)(pcaReq(act(1)))).toMatchObject({ allow: true, tier: 2 });
    const d = await mk(2000)(pcaReq(act(2)));
    expect(d.allow).toBe(false);
    expect(d.verdict?.checks.operation).toBe('fail');
  });
  it('operation returning null denies', async () => {
    const g = siteGuard({ audience: AUD, verbOf, policy, pca: bound, operation: () => null });
    expect((await g(pcaReq(act(3)))).allow).toBe(false);
  });
});

describe('Tier 0 and unmapped routes', () => {
  it('a public page passes with nothing presented', async () => {
    const d = await guardFor(2)({ method: 'GET', url: `${ORIGIN}/`, headers: {} });
    expect(d).toMatchObject({ allow: true, tier: 0, presentedTier: 0, status: 200 });
  });
  it('an unmapped route is denied', async () => {
    const d = await guardFor(2)({ method: 'GET', url: `${ORIGIN}/admin`, headers: {} });
    expect(d).toMatchObject({ allow: false, status: 403 });
    expect(d.checks.route).toBe('fail');
  });
});

describe('Tier 1: Web Bot Auth (RFC 9421)', () => {
  it('a valid signature from a directory key is Tier 1', async () => {
    const s = signRequest({ method: 'GET', url: URL_REFUND, key: botKey, keyid, agentDirectoryUrl: 'https://bots.example' });
    const d = await guardFor(1)({ method: 'GET', url: URL_REFUND, headers: lower(s.headers) });
    expect(d).toMatchObject({ allow: true, tier: 1, presentedTier: 1, agentKeyId: keyid });
  });
  it('no signature is insufficient_tier (401 + challenge + problem)', async () => {
    const d = await guardFor(1)({ method: 'GET', url: URL_REFUND, headers: {} });
    expect(d.status).toBe(401);
    expect(d.headers['WWW-Authenticate']).toBe('PCA error="insufficient_tier", tier="1"');
    expect(d.headers['Content-Type']).toBe('application/problem+json');
    expect((d.body as { type: string }).type).toBe(PROBLEM_INSUFFICIENT_TIER);
  });
  it('a signature for another path does not verify', async () => {
    const s = signRequest({ method: 'GET', url: `${ORIGIN}/v1/other`, key: botKey, keyid });
    const d = await guardFor(1)({ method: 'GET', url: URL_REFUND, headers: lower(s.headers) });
    expect(d).toMatchObject({ allow: false, status: 401 });
    expect(d.checks.web_bot_auth).toBe('fail');
  });
  it('per-key rate limits apply', async () => {
    const { memoryRateLimiter } = await import('./index');
    const g = guardFor(1, { rateLimiter: memoryRateLimiter() }, { rate: { max: 1, per_secs: 60, key: 'agent' } });
    const req = () => ({ method: 'GET', url: URL_REFUND, headers: lower(signRequest({ method: 'GET', url: URL_REFUND, key: botKey, keyid }).headers) });
    expect((await g(req())).allow).toBe(true);
    expect((await g(req())).status).toBe(429);
  });
});

describe('Tier 2: accountable (requirePCA)', () => {
  it('a verified PCActn for this verb is Tier 2', async () => {
    const d = await guardFor(2)(pcaReq(act(1)));
    expect(d).toMatchObject({ allow: true, tier: 2, presentedTier: 2 });
    expect(d.pcactn?.action.verb).toBe('stripe.refund');
  });
  it('no PCActn is insufficient_tier', async () => {
    const d = await guardFor(2)({ method: 'POST', url: URL_REFUND, headers: {} });
    expect(d.headers['WWW-Authenticate']).toBe('PCA error="insufficient_tier", tier="2"');
  });
  it('a PCActn for another verb is refused', async () => {
    const g = siteGuard({ audience: AUD, policy: { tiers: { 'stripe.charge': { tier: 2 } } }, verbOf: () => 'stripe.charge', pca });
    const d = await g(pcaReq(act(2)));
    expect(d).toMatchObject({ allow: false, status: 403 });
  });
  it('a signature covering PCA-Action pins that proof (a body proof cannot replace it)', async () => {
    const pinned = act(3);
    const other = act(4);
    const s = signRequestWithProof({ method: 'POST', url: URL_REFUND, key: botKey, keyid, pcactn: pinned.pcactn });
    const d = await guardFor(2)({ method: 'POST', url: URL_REFUND, headers: lower(s.headers), body: { pcactn: other.encoded } });
    expect(d.allow).toBe(true);
    expect(pcactnDigest(d.pcactn as PCActn)).toBe(pcactnDigest(pinned.pcactn));
    expect(d.presentedTier).toBe(2);
    expect(d.agentKeyId).toBe(keyid);
  });
});

describe('Tier 3: intent-bound', () => {
  it('intent_required is a site-signed RFC 9457 problem the wallet can verify; relayed by the agent without a deliver hook', async () => {
    const g = guardFor(3, { intent: async () => ({ kind: 'intent_required', question: QUESTION }) });
    const p = act(5);
    const d = await g(pcaReq(p));
    expect(d.status).toBe(403);
    expect(d.headers['Content-Type']).toBe('application/problem+json');
    expect(d.headers['WWW-Authenticate']).toBe(`PCA error="intent_required", session="${QUESTION.session}", question="q_7Hk2"`);
    const body = d.body as { type: string; status: number; pca: SignedIntentRequired };
    expect(body.type).toBe(`${PROBLEM_BASE}intent-required`);
    expect(body.pca.delivered_to).toBe('agent');
    expect(body.pca.sig.kid).toBe('shop-2026');
    // the guard binds the question to the verified PCActn itself (the port cannot name another action)
    expect(body.pca.pcactn_digest).toBe(pcactnDigest(p.pcactn));
    expect(body.pca.action_digest).toBe(intentActionDigest(p.pcactn.action));
    expect(verifyIntentRequired(body.pca, siteKeys, Date.now())).toEqual({ ok: true });
    // default expiry = now + lazy.question_ttl_s (900 s)
    expect(body.pca.expires_at).toBeGreaterThan(Date.now() + 800_000);
    // tampering with the cell breaks the site signature
    const forged = { ...body.pca, cell: { verb: 'stripe.refund', coords: { 'action.params.amount': [0, 3] } } };
    expect(verifyIntentRequired(forged, siteKeys, Date.now()).ok).toBe(false);
  });
  it('delivered straight to the wallet when the deliver hook succeeds', async () => {
    let got: SignedIntentRequired | undefined;
    const g = guardFor(3, { intent: async () => ({ kind: 'intent_required', question: QUESTION, deliver: async (s) => ((got = s), true) }) });
    const d = await g(pcaReq(act(6)));
    expect(d.intentRequired?.delivered_to).toBe('wallet');
    expect(got).toEqual(d.intentRequired);
    const failing = guardFor(3, { intent: async () => ({ kind: 'intent_required', question: QUESTION, deliver: async () => { throw new Error('down'); } }) });
    expect((await failing(pcaReq(act(7)))).intentRequired?.delivered_to).toBe('agent');
  });
  it('agent_relay policy never calls the deliver hook', async () => {
    let called = false;
    const g = siteGuard({
      audience: AUD, verbOf: () => 'stripe.refund', pca, siteKey,
      policy: { tiers: { 'stripe.refund': { tier: 3 } }, lazy: { deliver: 'agent_relay' } },
      intent: async () => ({ kind: 'intent_required', question: QUESTION, deliver: async () => ((called = true), true) }),
    });
    expect((await g(pcaReq(act(8)))).intentRequired?.delivered_to).toBe('agent');
    expect(called).toBe(false);
  });
  it('a deny from the intent checks maps to its sibling problem type', async () => {
    const d = await guardFor(3, { intent: async () => ({ kind: 'deny', problem: 'ceiling', reason: 'outside the org ceiling' }) })(pcaReq(act(9)));
    expect(d.status).toBe(403);
    expect((d.body as { type: string }).type).toBe(`${PROBLEM_BASE}ceiling`);
    expect(d.headers['WWW-Authenticate']).toBe('PCA error="ceiling"');
  });
  it('no intent port: fail closed', async () => {
    const g = siteGuard({ audience: AUD, verbOf: () => 'stripe.refund', pca, policy: { tiers: { 'stripe.refund': { tier: 3 } } } });
    expect((await g(pcaReq(act(10)))).allow).toBe(false);
  });
  it('admitted, then JIT consent at the rule tier or above', async () => {
    const rule = { jit: { reversible: 'typed', irreversible: 'device' } }; // stripe.refund is irreversible (catalog) -> the `irreversible` entry
    const low = guardFor(3, { intent: admit, jit: async () => ({ tier: 'tap' }) }, rule);
    const dl = await low(pcaReq(act(11)));
    expect(dl).toMatchObject({ allow: false, status: 403 });
    expect((dl.body as { type: string }).type).toBe(`${PROBLEM_BASE}intent-denied`);
    expect(dl.headers['WWW-Authenticate']).toBe('PCA error="consent_required", tier="device"');
    const none = guardFor(3, { intent: admit }, rule);
    expect((await none(pcaReq(act(12)))).checks.jit).toBe('fail');
    const ok = guardFor(3, { intent: admit, jit: async ({ minTier }) => ({ tier: minTier === 'device' ? 'device' : 'tap' }) }, rule);
    const d = await ok(pcaReq(act(13)));
    expect(d).toMatchObject({ allow: true, tier: 3, presentedTier: 3 });
  });
});

describe('Tier 4: dispute-grade', () => {
  const rule = { bond_min_cents: 10000 };
  it('no bond port, or a bond below the minimum, fails closed', async () => {
    expect((await guardFor(4, { intent: admit }, rule)(pcaReq(act(14)))).checks.bond).toBe('fail');
    expect((await guardFor(4, { intent: admit, bond: async () => ({ posted_cents: 9999 }) }, rule)(pcaReq(act(15)))).checks.bond).toBe('fail');
  });
  it('a missing or failing evidence store fails closed', async () => {
    const d = await guardFor(4, { intent: admit, bond: async () => ({ posted_cents: 10000 }) }, rule)(pcaReq(act(16)));
    expect(d).toMatchObject({ allow: false, presentedTier: 3 });
    expect(d.checks.evidence).toBe('fail');
    const broken = await guardFor(4, { intent: admit, bond: async () => ({ posted_cents: 10000 }), evidence: { record: async () => { throw new Error('disk full'); } } }, rule)(pcaReq(act(17)));
    expect(broken.status).toBe(503);
  });
  it('bond + stored evidence is Tier 4', async () => {
    const stored: unknown[] = [];
    const d = await guardFor(4, { intent: admit, bond: async () => ({ posted_cents: 12000 }), evidence: { record: async (e) => void stored.push(e) } }, rule)(pcaReq(act(18)));
    expect(d).toMatchObject({ allow: true, tier: 4, presentedTier: 4 });
    expect(stored).toHaveLength(1);
  });
});
