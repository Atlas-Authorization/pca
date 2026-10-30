import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  b64u,
  buildPCActn,
  encodePCActn,
  generateKeyPair,
  hashCanonical,
  paramsDigest,
  type PlanNode,
} from '../index';
import {
  actionSchemaDigest,
  actionSchemaKeyOf,
  labelsRef,
  mintSessionGrant,
  sessionRootDigest,
  signActionSchema,
  signLabels,
  signSessionRoot,
  type IntentV2Context,
  type PcaLabels,
  type ProvenancePolicy,
} from '../ext/intent';
import { authorize, type AuthorizeOptions } from './authorize';
import { memoryPcaStore, requirePCA, type PcaRequestLike } from './require-pca';
import { principalDirect } from '../test-support/provenance';

/**
 * Per-parameter provenance (Intent Layer v2) inside the one pipeline: a payment's payee and amount must be vouched for
 * by a pinned system of record (value-bound `pca-labels` receipts); the grant's predicates read the verifier-computed
 * `env.prov`. Same construction as the attack suite's A2 (poisoned approval).
 */
const AUD = 'payments-rs';
const VERB = 'payments.send';
const MAIL = 'mail:inbox/msg-17';
const LEVELS = ['trusted', 'first_party', 'tool'];
const d32 = () => b64u(randomBytes(32));

function setup() {
  const now = Date.now();
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const site = generateKeyPair();
  const records = generateKeyPair();
  const schema = signActionSchema(
    {
      v: 1,
      kind: 'pca-action-schema',
      site: `https://${AUD}.example`,
      aud: AUD,
      version: '2026-10-01',
      verbs: [
        {
          verb: VERB,
          kind: 'write',
          params: {
            'action.params.payee': { type: 'string', semantic: 'party.payee', sensitivity: 'material' },
            'action.params.amount': { type: 'integer', min: 0, max: 1_000_000, semantic: 'money.amount', sensitivity: 'material' },
          },
          reversibility: 'irreversible',
        },
      ],
    },
    'site-1',
    site.secretKey,
  );
  const session = d32();
  const intentRef = d32();
  const map = d32();
  const root = signSessionRoot(
    {
      v: 1,
      kind: 'pca-intent-session',
      session,
      principals: [{ key: b64u(principal.publicKey) }],
      intent_ref: intentRef,
      schema: { aud: AUD, digest: actionSchemaDigest(schema) },
      layers: { task: { map_digest: map } },
      accumulators: [],
      monitors: [],
      question_uri: `https://${AUD}.example/questions`,
      expires_at: now + 86_400_000,
    },
    principal.secretKey,
  );
  const { grant, goalSalt } = mintSessionGrant({
    principalSecret: principal.secretKey,
    principalPublic: b64u(principal.publicKey),
    holder: b64u(holder.publicKey),
    session,
    seq: 0,
    root: sessionRootDigest(root),
    mapDigest: map,
    predicates: [
      {
        verb: VERB,
        resource: '*',
        where: [
          { field: 'action.params.amount', op: 'lte', value: 1000 },
          { field: 'env.prov.action.params.payee', op: 'in', value: LEVELS },
          { field: 'env.prov.action.params.amount', op: 'in', value: LEVELS },
        ],
      },
    ],
    riskPolicy: { weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 1000, lambda: 0, rho: 0.5, bMax: 1_000_000 },
  });
  const receipt = signLabels(
    {
      site: 'records.example',
      session,
      response_digest: d32(),
      fields: { payee: { class: 'public', value_digest: hashCanonical('acme') }, amount: { class: 'public', value_digest: hashCanonical(120) } },
      issued_at: now,
      kid: 'records-1',
    },
    records.secretKey,
  );
  const provenance: ProvenancePolicy = {
    params: { 'action.params.payee': 'material', 'action.params.amount': 'material' },
    registry: { [MAIL]: 'web' },
    label_keys: [{ site: 'records.example', kid: 'records-1', pk: b64u(records.publicKey) }],
    material_tainted: 'allow',
  };
  let counter = 0;
  /** A payment request; `cite` = the records receipt (vouched) or the injected mail. */
  const request = (params: { payee: string; amount: number }, cite: 'receipt' | 'mail'): PcaRequestLike => {
    const ref = labelsRef(receipt);
    const node: PlanNode = { id: 'n0', verb: VERB, resource: 'payments', params_digest: paramsDigest(params), reversibility_class: 'irreversible' };
    const p = buildPCActn({
      grant,
      chain: [grant],
      plan: [node],
      nodeId: 'n0',
      params,
      counter: ++counter,
      signerSecret: holder.secretKey,
      aud: AUD,
      intent: { ref: intentRef, map_digest: map, goal_salt: goalSalt, fidelity_ppm: 1_000_000, residual_risk_ppm: 0 },
      intentSession: {
        session,
        root: sessionRootDigest(root),
        seq: 0,
        schema: actionSchemaDigest(schema),
        prov:
          cite === 'receipt'
            ? { 'action.params.payee': [`pca-labels:${ref}#payee`], 'action.params.amount': [`pca-labels:${ref}#amount`] }
            : { 'action.params.payee': [MAIL], 'action.params.amount': [MAIL] },
        ...(cite === 'receipt' ? { labels: [ref] } : {}),
      },
    });
    return { headers: { 'pca-action': Buffer.from(encodePCActn(p)).toString('base64url') }, body: { ...params, ...(cite === 'receipt' ? { labels: [receipt] } : {}) } };
  };
  const intentV2 = (req: PcaRequestLike): IntentV2Context => ({
    // the grant's predicates read env.prov (model-derived): rule 21 refuses that unless the verifier opts into the compatibility mode
    policy: { model_polarity: 'legacy' },
    schema: { docs: [schema], keys: [actionSchemaKeyOf('site-1', site.secretKey)] },
    session: { root, grants: [] },
    acc: { state: {}, monitors: {} },
    wb: { artifacts: { labels: ((req.body as { labels?: PcaLabels[] }).labels ?? []) as never }, policy: { provenance } },
  });
  const opts = (over: Partial<AuthorizeOptions> = {}): AuthorizeOptions => ({
    provenance: principalDirect(),
    audience: AUD,
    resolveGrant: async (ref) => (ref === grant.id ? grant : null),
    budgetStore: memoryPcaStore(),
    hooks: { revocation: () => ({ enforced: true, ok: true }) },
    plan: 'single-step',
    // 0.5: a risk input the server does not supply is priced at the worst case, so supply them all
    risk: (o) => ({ blastRadius: Number(o?.params?.amount) / 1000, semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }),
    intentV2,
    ...over,
  });
  return { grant, request, intentV2, opts };
}

const operationOf = (req: PcaRequestLike) => {
  const { payee, amount } = req.body as { payee: string; amount: number };
  return { verb: VERB, resource: 'payments', params: { payee, amount } };
};

describe('Intent Layer v2 inside authorize / requirePCA', () => {
  it('authorize: a payment vouched for by the records receipt is allowed; the same payment citing the injected mail is refused by the provenance predicates', async () => {
    const { request, opts } = setup();
    const o = opts();
    const good = request({ payee: 'acme', amount: 120 }, 'receipt');
    const r1 = await authorize({ request: good, operation: operationOf(good) }, o);
    expect([r1.allow, r1.verdict.checks.policy]).toEqual([true, 'pass']);
    const steered = request({ payee: 'acme', amount: 120 }, 'mail');
    const r2 = await authorize({ request: steered, operation: operationOf(steered) }, o);
    expect([r2.allow, r2.verdict.checks.policy]).toEqual([false, 'fail']);
  });

  it('a receipt is value-bound: citing it for a different payee is refused', async () => {
    const { request, opts } = setup();
    const req = request({ payee: 'mallory', amount: 120 }, 'receipt');
    const r = await authorize({ request: req, operation: operationOf(req) }, opts());
    expect(r.allow).toBe(false);
  });

  it('requirePCA: the vouched payment needs the intentV2 passthrough (without it the v2 checks cannot pass)', async () => {
    const { grant, request, intentV2 } = setup();
    const base = {
      audience: AUD,
      resolveGrant: async () => grant,
      insecureAllowUnboundOperation: true, // this test is about the intentV2 passthrough, not operation binding
      budgetStore: memoryPcaStore(),
      hooks: { revocation: () => ({ enforced: true, ok: true as const }) },
      context: async (req: PcaRequestLike, p: { plan: { node_id: string; root: string }; action: { params_digest: string } }) => ({
        params: operationOf(req).params,
        plan: [{ id: p.plan.node_id, verb: VERB, resource: 'payments', params_digest: p.action.params_digest, reversibility_class: 'irreversible' as const }],
        planAuthorized: true,
        budget: { B: 1_000_000, tau: Date.now(), asOf: Date.now() },
        risk: { blastRadius: 0.12, semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 },
      }),
    };
    const without = await requirePCA(base as never)(request({ payee: 'acme', amount: 120 }, 'receipt'));
    expect(without.ok).toBe(false);
    const withV2 = await requirePCA({ ...base, intentV2 } as never)(request({ payee: 'acme', amount: 120 }, 'receipt'));
    expect(withV2.ok).toBe(true);
    const steered = await requirePCA({ ...base, intentV2 } as never)(request({ payee: 'acme', amount: 120 }, 'mail'));
    expect(steered.ok ? 'ok' : steered.verdict.checks.policy).toBe('fail');
  });
});
