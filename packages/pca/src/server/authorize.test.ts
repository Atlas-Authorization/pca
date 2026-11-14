import { describe, expect, it } from 'vitest';
import { mintRoot, type Capability, type Caveat } from '../capability';
import { mintGrant } from '../envelope';
import { hashCanonical } from '../hash';
import { encodeKey, generateKeyPair } from '../keys';
import { paramsDigest, type PlanNode } from '../merkle';
import { buildPCActn, encodePCActn, type PCActn } from '../pcactn';
import { DEFAULT_RISK_POLICY, type RiskPolicy } from '../risk';
import { authorize, createAuthorizer, isAuthorizedFor, missingAuthorizeComponents, requireAuthorized, type AuthorizeOptions, type AuthorizeResult } from './authorize';
import { memoryPcaStore, requirePCA } from './require-pca';
import type { PcaOperation } from './verify';
import { principalDirect } from '../test-support/provenance';

const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'payments-rs';
const VERB = 'payments.send';
const RES = 'payments';

/** "spend = risk": r = amount / 100 and the budget is debited by the amount (bMax far away). */
const SPEND_POLICY: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 };

type Limit = 'predicate' | 'max_spend' | 'root_max_spend';

function setup(limit: Limit = 'predicate', policy: RiskPolicy = SPEND_POLICY) {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const pPub = encodeKey(principal.publicKey);
  const hPub = encodeKey(holder.publicKey);
  const where = limit === 'predicate' ? [{ field: 'action.params.amount', op: 'lte' as const, value: 100 }] : [];
  const minted = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: pPub,
    holder: hPub,
    goal: 'pay invoices',
    envelope: {
      predicates: [{ verb: [VERB, 'payments.refund'], resource: '*', where }],
      caveats: limit === 'max_spend' ? [{ type: 'max_spend', usd: 100 }] : [],
      agent_binding: {},
      risk_policy: policy,
    },
  }).grant;
  // root caveat outside the envelope: enforced like a delegated one (0.4.1 root-caveat semantics)
  const grant: Capability =
    limit === 'root_max_spend'
      ? mintRoot({ principalSecret: principal.secretKey, principalPublic: pPub, holder: hPub, caveats: [...minted.caveats, { type: 'max_spend', usd: 100 } as Caveat] })
      : minted;
  let counter = 0;
  const sign = (params: Record<string, unknown>, o: { verb?: string; resource?: string; counter?: number; extra?: Partial<Parameters<typeof buildPCActn>[0]> } = {}): PCActn => {
    const node: PlanNode = { id: 'n1', verb: o.verb ?? VERB, resource: o.resource ?? RES, params_digest: paramsDigest(params), reversibility_class: 'irreversible' };
    return buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params, counter: o.counter ?? ++counter, signerSecret: holder.secretKey, aud: AUD, now: NOW, ...o.extra });
  };
  return { grant, sign };
}

const op = (amount: number, o: Partial<PcaOperation> = {}): PcaOperation => ({ verb: VERB, resource: RES, params: { payee: 'acme', amount }, ...o });

function options(grant: Capability, over: Partial<AuthorizeOptions> = {}): AuthorizeOptions {
  return {
    provenance: principalDirect(),
    audience: AUD,
    resolveGrant: async (ref) => (ref === grant.id ? grant : null),
    budgetStore: memoryPcaStore(),
    hooks: { revocation: () => ({ enforced: true, ok: true }) },
    plan: 'single-step',
    now: () => NOW,
    // server-side pricing from the operation the handler will execute
    risk: (o) => ({ blastRadius: Math.min(1, Number(o?.params?.amount) / 100), semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }),
    ...over,
  };
}

/** Exact outcome: allow, status and the failing checks (sorted). */
const settle = (r: AuthorizeResult) => ({
  allow: r.allow,
  status: r.status,
  failed: Object.entries(r.verdict.checks)
    .filter(([, s]) => s === 'fail')
    .map(([k]) => k)
    .sort(),
});

describe('authorize: the reviewer acceptance cases', () => {
  for (const limit of ['predicate', 'max_spend', 'root_max_spend'] as const) {
    it(`a validly signed $400 payment under a $100 grant (${limit}) is refused; $50 is allowed`, async () => {
      const { grant, sign } = setup(limit);
      const az = createAuthorizer(options(grant));
      const over = await az({ pcactn: sign(op(400).params!), operation: op(400) });
      expect(settle(over)).toEqual({ allow: false, status: 403, failed: limit === 'predicate' ? ['policy'] : ['policy'] });
      const ok = await az({ pcactn: sign(op(50).params!), operation: op(50) });
      expect(settle(ok)).toEqual({ allow: true, status: 200, failed: [] });
    });
  }

  it('the operation params are what the policy reads: a $50 proof used to execute $400 is refused (operation + digest)', async () => {
    const { grant, sign } = setup('predicate');
    const r = await authorize({ pcactn: sign(op(50).params!), operation: op(400) }, options(grant));
    expect(settle(r)).toEqual({ allow: false, status: 403, failed: ['operation', 'params_digest', 'plan_root_authorized', 'policy'] });
    expect(r.allow ? '' : r.reason).toBe("operation: the proof's params_digest does not match the params of this payments.send operation");
  });

  it('a proof for operation X used to execute operation Y is refused (verb, and resource)', async () => {
    const { grant, sign } = setup('predicate');
    const az = createAuthorizer(options(grant));
    const verb = await az({ pcactn: sign(op(50).params!), operation: op(50, { verb: 'payments.refund' }) });
    expect(settle(verb).failed).toContain('operation');
    expect(verb.allow ? '' : verb.reason).toBe('operation: the proof is for payments.send on payments, but this operation is payments.refund on payments');
    const res = await az({ pcactn: sign(op(50).params!), operation: op(50, { resource: 'payouts' }) });
    expect(res.allow ? '' : res.reason).toBe('operation: the proof is for payments.send on payments, but this operation is payments.send on payouts');
  });

  it('allows a valid operation once, binds the result to it, and refuses the second presentation (replay)', async () => {
    const { grant, sign } = setup('predicate');
    const az = createAuthorizer(options(grant));
    const p = sign(op(50).params!);
    const first = await az({ pcactn: encodePCActn(p), operation: op(50) });
    expect(first.allow && first.operation).toEqual({ verb: VERB, resource: RES, params_digest: paramsDigest(op(50).params), id: hashCanonical(p) });
    expect([isAuthorizedFor(first, op(50)), isAuthorizedFor(first, op(400)), isAuthorizedFor(first, op(50, { verb: 'payments.refund' }))]).toEqual([true, false, false]);
    const again = await az({ pcactn: encodePCActn(p), operation: op(50) });
    expect(settle(again)).toEqual({ allow: false, status: 403, failed: ['replay'] });
    expect(isAuthorizedFor(again, op(50))).toBe(false);
  });

  it('reads the PCActn from the request (header) when none is passed', async () => {
    const { grant, sign } = setup('predicate');
    const p = sign(op(50).params!);
    const r = await authorize({ request: { headers: { 'pca-action': Buffer.from(encodePCActn(p)).toString('base64url') } }, operation: op(50) }, options(grant));
    expect(settle(r)).toEqual({ allow: true, status: 200, failed: [] });
  });
});

describe('authorize: fail closed on a missing component', () => {
  const { grant, sign } = setup('predicate');
  const cases: [string, Partial<AuthorizeOptions> & Record<string, unknown>, string[]][] = [
    ['budgetStore', { budgetStore: undefined }, ['budgetStore']],
    ['revocation', { hooks: {} }, ['hooks.revocation']],
    ['audience', { audience: '' }, ['audience']],
    ['resolveGrant', { resolveGrant: undefined }, ['resolveGrant']],
    ['insecure opt-out', { insecureAllowUnenforced: true }, ['insecureAllowUnenforced is not accepted by authorize']],
  ];
  for (const [name, over, missing] of cases) {
    it(`no ${name}: refused before verification, naming it`, async () => {
      const r = await authorize({ pcactn: sign(op(50).params!), operation: op(50) }, options(grant, over as Partial<AuthorizeOptions>));
      expect({ ...settle(r), missing: r.allow ? null : r.missing }).toEqual({ allow: false, status: 403, failed: ['authorize_config'], missing });
      expect(missingAuthorizeComponents(options(grant, over as Partial<AuthorizeOptions>))).toEqual(missing);
    });
  }

  it('no operation, or one without params: refused', async () => {
    for (const bad of [undefined, { verb: VERB, resource: RES }, { verb: '', resource: RES, params: {} }, { verb: VERB, resource: RES, params: [] }]) {
      const r = await authorize({ pcactn: sign(op(50).params!), operation: bad as never }, options(grant));
      expect(settle(r)).toEqual({ allow: false, status: 403, failed: ['operation'] });
    }
  });

  it('a revoked grant is refused', async () => {
    const r = await authorize({ pcactn: sign(op(50).params!), operation: op(50) }, options(grant, { hooks: { revocation: () => ({ enforced: true, ok: false, reason: 'revoked' }) } }));
    expect(settle(r)).toEqual({ allow: false, status: 403, failed: ['revocation'] });
  });

  it('without single-step or a principal-authorized plan, plan_root_authorized is required', async () => {
    const r = await authorize({ pcactn: sign(op(50).params!), operation: op(50) }, options(grant, { plan: undefined }));
    expect(settle(r)).toEqual({ allow: false, status: 403, failed: ['plan_root_authorized'] });
  });

  it('`require` adds checks but cannot remove the defaults', async () => {
    const r = await authorize({ pcactn: sign(op(50).params!), operation: op(50) }, options(grant, { hooks: {}, require: [] }));
    expect(settle(r).failed).toEqual(['authorize_config']);
    const extra = await authorize({ pcactn: sign(op(50).params!), operation: op(50) }, options(grant, { require: ['beacon'] }));
    expect(settle(extra)).toEqual({ allow: false, status: 403, failed: ['beacon'] });
  });

  it('a step-up the server requires (risk above the auto threshold) is refused with no threshold verifier', async () => {
    const { grant: g, sign: s } = setup('predicate', { ...DEFAULT_RISK_POLICY, bMax: 1000 });
    const r = await authorize({ pcactn: s(op(50).params!), operation: op(50) }, options(g, { risk: () => ({ blastRadius: 1, semanticDistance: 1, reversibility: 0, taint: 1, confidence: 0 }) }));
    expect(settle(r)).toEqual({ allow: false, status: 403, failed: ['threshold'] });
    expect(r.verdict.requiredThreshold.t).toBe(3);
  });

  it('an unsigned / forged proof is a 401', async () => {
    const { grant: g, sign: s } = setup('predicate');
    const p = s(op(50).params!);
    const forged = { ...p, counter: p.counter + 1 };
    const r = await authorize({ pcactn: forged, operation: op(50) }, options(g));
    expect([r.allow, r.status]).toEqual([false, 401]);
  });
});

describe('requirePCA `operation` and requireAuthorized', () => {
  it('requirePCA binds to the mapped operation (additive option) and returns it', async () => {
    const { grant, sign } = setup('predicate');
    const store = memoryPcaStore();
    const guard = requirePCA({
      audience: AUD,
      resolveGrant: async () => grant,
      budgetStore: store,
      hooks: { revocation: () => ({ enforced: true, ok: true }) },
      now: () => NOW,
      operation: (req) => ({ verb: VERB, resource: RES, params: req.body as Record<string, unknown> }),
      context: async (_req, p) => ({ plan: [{ id: 'n1', verb: VERB, resource: RES, params_digest: p.action.params_digest, reversibility_class: 'irreversible' }], planAuthorized: true, budget: { B: 1000, tau: NOW, asOf: NOW }, risk: { blastRadius: 0.5 } }),
    });
    const p = sign(op(50).params!);
    const hdr = { 'pca-action': Buffer.from(encodePCActn(p)).toString('base64url') };
    const bad = await guard({ headers: hdr, body: op(400).params });
    expect(bad.ok ? 'ok' : bad.verdict.checks.operation).toBe('fail');
    const good = await guard({ headers: hdr, body: op(50).params });
    expect(good.ok && good.operation).toEqual({ verb: VERB, resource: RES, params_digest: p.action.params_digest, id: hashCanonical(p) });
  });

  it('requirePCA: an operation mapping that returns null or throws denies', async () => {
    const { grant, sign } = setup('predicate');
    for (const mapping of [() => null, () => { throw new Error('no route'); }]) {
      const guard = requirePCA({ audience: AUD, resolveGrant: async () => grant, insecureAllowUnenforced: true, now: () => NOW, operation: mapping });
      const r = await guard({ headers: { 'pca-action': Buffer.from(encodePCActn(sign(op(50).params!))).toString('base64url') } });
      expect(r.ok ? 'ok' : r.verdict.checks.operation).toBe('fail');
    }
  });

  it('requireAuthorized: the guard shape adapters use, strict like authorize', async () => {
    const { grant, sign } = setup('predicate');
    const guard = requireAuthorized({ ...options(grant), operation: (req) => ({ verb: VERB, resource: RES, params: req.body as Record<string, unknown> }) });
    const hdr = (p: PCActn) => ({ 'pca-action': Buffer.from(encodePCActn(p)).toString('base64url') });
    const p = sign(op(50).params!);
    expect((await guard({ headers: hdr(p), body: op(400).params })).ok).toBe(false);
    const ok = await guard({ headers: hdr(p), body: op(50).params });
    expect(ok.ok && ok.operation?.params_digest).toBe(p.action.params_digest);
    const loose = requireAuthorized({ ...options(grant, { budgetStore: undefined as never }), operation: () => op(50) });
    const r = await loose({ headers: hdr(sign(op(50).params!)) });
    expect(r.ok ? 'ok' : r.verdict.reasons).toEqual(['authorize: missing required component(s): budgetStore (fail closed)']);
  });
});
