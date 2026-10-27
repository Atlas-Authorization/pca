/**
 * (e) Proof-Carrying Authority, using the real `@atlasauth/pca` library on both sides.
 *
 *  - The principal signs a Root Intent Grant to the agent's key: predicates (payee allowlist, per-payment
 *    ceiling) and a risk policy whose trust budget is denominated in dollars (each payment debits its amount,
 *    so `bMax` is the cumulative ceiling).
 *  - When the payments are known before approval, the agent commits them as a plan and the principal
 *    authorizes the plan root with the resource server. Otherwise the server accepts any plan the agent
 *    commits and relies on the grant alone (the weaker configuration).
 *  - Each action is a PCActn signed by the agent's key, carrying the capability chain, the plan-inclusion
 *    proof, a digest of the params, the audience and a strictly increasing counter.
 *  - The resource server runs `requirePCA` (default-deny) with an in-memory replay + budget store.
 *
 * When the authority says a separate system of record must vouch for each payment (`vouchedBy`), this approach
 * uses the Intent Layer v2 extension (not PCA Core): per-parameter provenance (`intent_session.prov`) with
 * value-bound label receipts signed by that system. See `vouchedGrant` below. In that mode the server runs
 * `authorize`, the library's one authorization pipeline (requirePCA with every component required), bound to the
 * payment it is about to execute and given the Intent Layer context.
 */
import {
  b64u as pb64u,
  buildPCActn,
  createAuthorizer,
  hashCanonical,
  decodePCActn,
  delegate,
  encodePCActn,
  generateKeyPair,
  memoryPcaStore,
  merkleRoot,
  mintGrant,
  paramsDigest,
  planNodeLeaf,
  readEnvelope,
  requirePCA,
  agentNative,
  DEFAULT_RISK_POLICY,
  type Capability,
  type CapabilityChain,
  type KeyPair,
  type PCActn,
  type PlanNode,
  type Predicate,
  type RiskPolicy,
} from '@atlasauth/pca';
// The Intent Layer API is an extension: it lives in the `@atlasauth/pca/ext/intent` subpath (0.5.0), not in the root entry.
import * as pcaLib from '@atlasauth/pca/ext/intent';
import { randomBytes } from 'node:crypto';
import { SetupError } from '../attacks.js';
import { RS, type Approach, type Authority, type Payment, type Req, type Server, type Stolen } from '../common.js';

const VERB = 'payments.send';
/** Where the steered agent read the injected text (the server's registry classifies it as web content). */
export const INJECTED_SOURCE = 'mail:inbox/msg-17';
/** Provenance labels the principal accepts for a payment's payee and amount (taint.ts levels, least tainted first). */
const VOUCHED_LEVELS = ['trusted', 'first_party', 'tool'];

/** Intent Layer v2 material for a grant whose payments must be vouched for by a system of record. */
interface Vouched {
  root: pcaLib.SessionRoot;
  schema: pcaLib.ActionSchema;
  schemaKeys: pcaLib.ActionSchemaKey[];
  session: string;
  intentRef: string;
  map: string;
  goalSalt: string;
  /** The system of record's signed receipts, by payee (what the agent gets when it reads an invoice there). */
  receipts: Map<string, pcaLib.PcaLabels>;
  provenance: pcaLib.ProvenancePolicy;
}

interface Inner {
  grant: Capability;
  chain: CapabilityChain;
  holder: KeyPair;
  counter: { n: number };
  /** The principal-approved plan, when the payments were known up front. */
  plan?: PlanNode[];
  kappa: number;
  vouched?: Vouched;
}

/** Risk in [0,1], rounded: canonical hashing rejects numbers with more than 15 significant digits. */
const riskOf = (amount: number, kappa: number): number => Math.round(Math.max(0, Math.min(1, amount / kappa)) * 1e6) / 1e6;
const paramsOf = (p: Payment): Record<string, unknown> => ({ payee: p.payee, amount: p.amount });
const nodeFor = (id: string, p: Payment): PlanNode => ({ id, verb: VERB, resource: 'payments', params_digest: paramsDigest(paramsOf(p)), reversibility_class: 'irreversible' });
const digest32 = (): string => pb64u(randomBytes(32));

function predicatesFor(a: Authority): Predicate[] {
  return [
    {
      verb: VERB,
      resource: '*',
      where: [
        { field: 'action.params.payee', op: 'in', value: [...a.payees] },
        { field: 'action.params.amount', op: 'lte', value: a.maxPerCall },
        { field: 'action.params.amount', op: 'gte', value: 0 },
        // Vouched mode: the payee and amount must come from a source the verifier vouches for. `env.prov` is computed
        // by the verifier from the declared refs and the label receipts; a host cannot supply it.
        ...(a.vouchedBy
          ? [
              { field: 'env.prov.action.params.payee', op: 'in' as const, value: VOUCHED_LEVELS },
              { field: 'env.prov.action.params.amount', op: 'in' as const, value: VOUCHED_LEVELS },
            ]
          : []),
      ],
    },
  ];
}

function riskPolicyFor(a: Authority): RiskPolicy {
  // "spend = risk": the server rates each payment at amount / kappa, and the budget is debited kappa * r = amount.
  return {
    weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 },
    theta1: 1,
    theta2: 1,
    kappa: a.maxPerCall,
    lambda: 0,
    rho: DEFAULT_RISK_POLICY.rho,
    // no cumulative ceiling requested: a budget no realistic run reaches
    bMax: a.maxTotal ?? a.maxPerCall * 1_000_000,
  };
}

/**
 * Vouched mode (Intent Layer v2, rules 13 and 17). The pieces, each signed by whoever owns it:
 *  - the payments server publishes a signed action schema for `payments.send`;
 *  - the principal signs a session root and a session grant (G_0) whose predicates require `env.prov` of the payee
 *    and amount to be at least `tool` level, i.e. vouched for by a pinned label signer;
 *  - the system of record (an accounts-payable system) signs a `pca-labels` receipt per invoice, binding the digest
 *    of each field's VALUE to the session. A parameter that cites a receipt counts as vouched only if its value
 *    hashes to the receipt's digest; a parameter that cites anything else is classified by the verifier's registry
 *    (the injected mail is `web`) or is `agent`.
 */
function vouchedGrant(a: Authority, principal: KeyPair, holder: KeyPair): { grant: Capability; vouched: Vouched } {
  if (typeof pcaLib.mintSessionGrant !== 'function' || typeof pcaLib.signLabels !== 'function') {
    throw new SetupError('this scenario uses the Intent Layer v2 extension, which needs @atlasauth/pca 0.5 or later');
  }
  const now = Date.now();
  const site = generateKeyPair(); // the payments server's schema-signing key
  const recordKey = generateKeyPair(); // the system of record's receipt-signing key
  const source = a.vouchedBy!.source;
  const schema = pcaLib.signActionSchema(
    {
      v: 1,
      kind: 'pca-action-schema',
      site: `https://${RS}.example`,
      aud: RS,
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
  const schemaKeys = [pcaLib.actionSchemaKeyOf('site-1', site.secretKey)];
  const session = digest32();
  const intentRef = digest32();
  const map = digest32();
  const root = pcaLib.signSessionRoot(
    {
      v: 1,
      kind: 'pca-intent-session',
      session,
      principals: [{ key: pb64u(principal.publicKey) }],
      intent_ref: intentRef,
      schema: { aud: RS, digest: pcaLib.actionSchemaDigest(schema) },
      layers: { task: { map_digest: map } },
      accumulators: [],
      monitors: [],
      question_uri: `https://${RS}.example/questions`,
      expires_at: now + 86_400_000,
    },
    principal.secretKey,
  );
  const { grant, goalSalt } = pcaLib.mintSessionGrant({
    principalSecret: principal.secretKey,
    principalPublic: pb64u(principal.publicKey),
    holder: pb64u(holder.publicKey),
    session,
    seq: 0,
    root: pcaLib.sessionRootDigest(root),
    mapDigest: map,
    predicates: predicatesFor(a),
    riskPolicy: riskPolicyFor(a),
  });
  const receipts = new Map<string, pcaLib.PcaLabels>();
  for (const r of a.vouchedBy!.records) {
    receipts.set(
      r.payee,
      pcaLib.signLabels(
        {
          site: source,
          session,
          response_digest: digest32(),
          fields: {
            payee: { class: 'public', value_digest: hashCanonical(r.payee) },
            amount: { class: 'public', value_digest: hashCanonical(r.amount) },
          },
          issued_at: now,
          kid: 'records-1',
        },
        recordKey.secretKey,
      ),
    );
  }
  const provenance: pcaLib.ProvenancePolicy = {
    params: { 'action.params.payee': 'material', 'action.params.amount': 'material' },
    // the only refs the verifier vouches for by name: the injected mail is web content
    registry: { [INJECTED_SOURCE]: 'web' },
    // the only pinned receipt signer: the system of record
    label_keys: [{ site: source, kid: 'records-1', pk: pb64u(recordKey.publicKey) }],
    // provenance alone never asks a question here; the grant's predicates decide which levels are acceptable
    material_tainted: 'allow',
  };
  return { grant, vouched: { root, schema, schemaKeys, session, intentRef, map, goalSalt, receipts, provenance } };
}

function build(inner: Inner, p: Payment, signer: Uint8Array, counter: number): Req {
  const params = paramsOf(p);
  // An approved plan node for exactly this payment, if there is one; otherwise the agent commits its own plan.
  const approved = inner.plan?.find((n) => n.params_digest === paramsDigest(params));
  const plan = approved ? inner.plan! : [nodeFor('n0', p)];
  const v = inner.vouched;
  // Vouched mode: the agent cites the system of record's receipt for this payee when it has one (the most a steered
  // agent can do to make a value look vouched for), otherwise the message it read.
  const receipt = v?.receipts.get(p.payee);
  const ref = receipt ? pcaLib.labelsRef(receipt) : undefined;
  const pcactn = buildPCActn({
    grant: inner.grant,
    chain: inner.chain,
    plan,
    nodeId: approved ? approved.id : 'n0',
    params,
    counter,
    signerSecret: signer,
    aud: RS,
    riskClaim: { r: riskOf(p.amount, inner.kappa), inputs: {} },
    ...(v
      ? {
          intent: { ref: v.intentRef, map_digest: v.map, goal_salt: v.goalSalt, fidelity_ppm: 1_000_000, residual_risk_ppm: 0 },
          intentSession: {
            session: v.session,
            root: pcaLib.sessionRootDigest(v.root),
            seq: 0,
            schema: pcaLib.actionSchemaDigest(v.schema),
            prov: ref
              ? { 'action.params.payee': [`pca-labels:${ref}#payee`], 'action.params.amount': [`pca-labels:${ref}#amount`] }
              : { 'action.params.payee': [INJECTED_SOURCE], 'action.params.amount': [INJECTED_SOURCE] },
            ...(ref ? { labels: [ref] } : {}),
          },
        }
      : {}),
  });
  return { headers: {}, body: { ...p, pcactn: encodePCActn(pcactn), ...(receipt ? { labels: [receipt] } : {}) } };
}

/** The plan the server checks the action against, and whether the principal authorized it. */
function planContext(approvedPlan: PlanNode[] | undefined, p: PCActn): { plan: PlanNode[]; planAuthorized: boolean } {
  if (approvedPlan) return { plan: approvedPlan, planAuthorized: true }; // anything else fails plan_root_authorized
  // Grant-only mode: rebuild the agent's one-node plan from the SIGNED action and accept it.
  const plan = [{ id: p.plan.node_id, verb: p.action.verb, resource: p.action.resource, params_digest: p.action.params_digest, reversibility_class: p.action.reversibility_class }];
  return { plan, planAuthorized: merkleRoot(plan.map(planNodeLeaf)) === p.plan.root };
}

const riskInputs = (r: number) => ({ blastRadius: r, semanticDistance: 0, reversibility: 0.5, taint: 0, confidence: 1 });
const failedChecks = (checks: Record<string, string>): string =>
  Object.entries(checks)
    .filter(([, v]) => v === 'fail')
    .map(([k]) => k)
    .join(', ');

/** Vouched-mode server: `authorize` with the Intent Layer context, bound to the payment the handler executes. */
function vouchedServer(inner: Inner): Server {
  const { grant, plan: approvedPlan, kappa, vouched: v } = inner;
  const labelsOf = (body: unknown): unknown[] => (body as { labels?: unknown[] } | undefined)?.labels ?? [];
  const authorize = createAuthorizer({
    audience: RS,
    resolveGrant: async (ref) => (ref === grant.id ? grant : null),
    // replay counter + the dollar budget (seeded once from the grant's signed bMax)
    budgetStore: memoryPcaStore(),
    hooks: { revocation: () => ({ enforced: true, ok: true }) },
    context: async (_req, p) => planContext(approvedPlan, p),
    // server-side pricing from the payment being executed, never from the agent's claim
    risk: (op) => riskInputs(riskOf(Number(op?.params?.amount), kappa)),
    intentV2: (req) => ({
      schema: { docs: [v!.schema], keys: v!.schemaKeys },
      session: { root: v!.root, grants: [] },
      acc: { state: {}, monitors: {} },
      wb: { artifacts: { labels: labelsOf(req.body) as never }, policy: { provenance: v!.provenance } },
    }),
  });
  return {
    async handle(r) {
      const body = r.body as Payment & { pcactn?: string; labels?: unknown[] };
      // the operation this handler will execute: the payment in the request body
      const params = paramsOf(body);
      const res = await authorize({ request: { headers: r.headers, body: r.body }, operation: { verb: VERB, resource: 'payments', params } });
      if (res.allow) return { ok: true, reason: 'authorize: predicates (incl. provenance), plan, intent session, budget and counter all pass' };
      let p: PCActn | undefined;
      try {
        p = decodePCActn(String(body.pcactn));
      } catch {
        p = undefined;
      }
      // For the report only: the per-parameter provenance labels the library computes for this action (the same
      // rule-17 decision the verifier ran), so the reason shows WHY the provenance predicates failed.
      const prov = pcaLib.decideParamProvenance({
        aud: RS,
        session: v!.session,
        action: { params },
        prov: p?.intent_session?.prov,
        committed_labels: p?.intent_session?.labels,
        labels: labelsOf(body),
        policy: v!.provenance,
      });
      const labels = Object.entries(prov.labels)
        .map(([k, l]) => `${k.replace('action.params.', '')} ${l}`)
        .join(', ');
      return { ok: false, reason: `${res.verdict.reasons?.[0] ?? 'denied'} [failed: ${failedChecks(res.verdict.checks)}; provenance: ${labels}]` };
    },
  };
}

export function pcaApproach(): Approach {
  const principal = generateKeyPair();

  return {
    id: 'pca',
    label: 'PCA',
    async grant(a) {
      const holder = generateKeyPair();
      let grant: Capability;
      let vouched: Vouched | undefined;
      if (a.vouchedBy) {
        ({ grant, vouched } = vouchedGrant(a, principal, holder));
      } else {
        ({ grant } = mintGrant({
          principalSecret: principal.secretKey,
          principalPublic: pb64u(principal.publicKey),
          holder: pb64u(holder.publicKey),
          goal: 'pay this month\'s vendor invoices',
          envelope: { predicates: predicatesFor(a), caveats: [], agent_binding: {}, risk_policy: riskPolicyFor(a) },
        }));
      }
      const plan = a.exact?.map((p, i) => nodeFor(`n${i + 1}`, p));
      const inner: Inner = { grant, chain: [grant], holder, counter: { n: 0 }, ...(plan ? { plan } : {}), kappa: a.maxPerCall, ...(vouched ? { vouched } : {}) };
      return { inner, dropped: [] };
    },
    server(g): Server {
      const inner = g.inner as Inner;
      if (inner.vouched) return vouchedServer(inner);
      const { grant, plan: approvedPlan, kappa } = inner;
      const store = memoryPcaStore();
      const bMax = readEnvelope(grant)?.risk_policy.bMax ?? 0; // the starting trust budget the principal signed
      const guard = requirePCA({
        audience: RS,
        resolveGrant: async (ref) => (ref === grant.id ? grant : null),
        budgetStore: store,
        hooks: { revocation: () => ({ enforced: true, ok: true }) },
        // the operation this route executes, from the server's own routing and the parsed body, never from the proof
        operation: (req) => ({ verb: VERB, resource: 'payments', params: paramsOf(req.body as Payment) }),
        // the starting trust budget the principal signed; the store carries the debited budget from the first call on
        seedBudget: (_g, now) => ({ B: bMax, tau: now, asOf: now }),
        context: async (req, p: PCActn) => {
          const body = req.body as Payment;
          return {
            params: paramsOf(body),
            ...planContext(approvedPlan, p),
            risk: riskInputs(riskOf(Number(body.amount), kappa)),
          };
        },
      });
      return {
        async handle(r) {
          const res = await guard({ headers: r.headers, body: r.body });
          if (res.ok) return { ok: true, reason: 'PCActn verified; predicates, plan, budget and counter all pass' };
          return { ok: false, reason: `${res.verdict.reasons?.[0] ?? 'denied'} [failed: ${failedChecks(res.verdict.checks)}]` };
        },
      };
    },
    async request(g, p) {
      const inner = g.inner as Inner;
      return build(inner, p, inner.holder.secretKey, ++inner.counter.n);
    },
    async attenuate(g, narrower) {
      const inner = g.inner as Inner;
      const sub = generateKeyPair();
      const leaf = inner.chain[inner.chain.length - 1]!;
      const caveat = agentNative.predicatesCaveat(predicatesFor(narrower));
      const child = delegate(leaf, pb64u(sub.publicKey), [caveat], inner.holder.secretKey);
      const next: Inner = { ...inner, chain: [...inner.chain, child], holder: sub, counter: { n: 0 } };
      return { inner: next, dropped: narrower.maxTotal !== undefined ? ['a separate cumulative ceiling for the sub-agent (not modeled here)'] : [] };
    },
    steal(g): Stolen {
      // The grant and chain are public data. The thief also has a copy of a past request. No private key.
      const inner = g.inner as Inner;
      return { inner: { grant: inner.grant, chain: inner.chain, plan: inner.plan, kappa: inner.kappa, vouched: inner.vouched } };
    },
    async forge(s, p) {
      const st = s.inner as Omit<Inner, 'holder' | 'counter'>;
      const thief = generateKeyPair();
      return build({ ...st, holder: thief, counter: { n: 0 } }, p, thief.secretKey, 1_000);
    },
  };
}
