/**
 * Shared acceptance matrix for resource-server adapters (`@atlasauth/pca-express`, `-fastify`, `-hono`, `-next`,
 * `-fetch`, or your own): every adapter runs the SAME scenarios through its own request / response plumbing with the
 * `operation` option (the `authorize` pipeline), and must produce {@link ADAPTER_ACCEPTANCE_EXPECTED} exactly.
 *
 * The routes: `POST /payments` executes `payments.send`, `POST /refunds` executes `payments.refund`, both on resource
 * `payments` with the JSON body as params. The grant permits both verbs up to $100 per call; the operation mapping
 * reads the request's method and URL, so the adapter must pass them through.
 *
 * Scenarios (each on a fresh adapter unless noted):
 *  - `over_limit_predicate`: a validly signed $400 payment under a `where amount <= 100` grant;
 *  - `over_limit_max_spend`: the same under a `max_spend: 100` caveat;
 *  - `body_differs`: a proof signed for $50, the body (what the handler executes) says $400;
 *  - `other_operation`: a proof for `payments.send` presented to `POST /refunds`;
 *  - `escalate_unanswered`: a payment the grant's `tighten[]` escalates (decision `escalate`) with no principal answer: refused, never allowed;
 *  - `missing_revocation` / `missing_store`: no `hooks.revocation` / no `budgetStore`;
 *  - `valid_first` then `replay_second` (same adapter): a $50 payment runs once, the same request again is refused.
 * Every refusal must happen before the handler runs; an allowed call must carry the bound operation.
 */

import {
  encodeKey,
  generateKeyPair,
  isAuthorizedFor,
  memoryPcaStore,
  mintGrant,
  mintRoot,
  paramsDigest,
  buildPCActn,
  encodePCActn,
  pcaHeaders,
  type AuthorizedOperation,
  type Capability,
  type Caveat,
  type PcaOperation,
  type PcaRequestLike,
  type PlanNode,
  type RequireAuthorizedOptions,
} from '@atlasauth/pca';

/** One request as the adapter's framework would receive it. */
export interface AcceptanceRequest {
  method: 'POST';
  /** Path only (`/payments`); adapters that need an absolute URL prefix an origin. */
  path: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
}

/** What the harness observed for one request. */
export interface AcceptanceObservation {
  status: number;
  handlerRan: boolean;
  /** The operation the adapter attached for the handler (allowed calls only). */
  operation?: AuthorizedOperation;
}

/**
 * Adapter-specific plumbing: build the adapter (middleware / wrapper) ONCE from `options` with a handler spy, and
 * return a function that sends one request through it. `options` are `requireAuthorized`-shaped and must be passed to
 * the adapter unchanged (they include `operation`).
 */
export type AcceptanceHarness = (options: RequireAuthorizedOptions) => (req: AcceptanceRequest) => Promise<AcceptanceObservation>;

/** One row of the matrix: status, whether the handler ran, and whether an attached operation matches what ran. */
export interface AcceptanceOutcome {
  status: number;
  handlerRan: boolean;
  bound: boolean;
}

export const ADAPTER_ACCEPTANCE_AUDIENCE = 'payments-rs';

export const ADAPTER_ACCEPTANCE_EXPECTED: Readonly<Record<string, AcceptanceOutcome>> = Object.freeze({
  over_limit_predicate: { status: 403, handlerRan: false, bound: false },
  over_limit_max_spend: { status: 403, handlerRan: false, bound: false },
  body_differs: { status: 403, handlerRan: false, bound: false },
  other_operation: { status: 403, handlerRan: false, bound: false },
  escalate_unanswered: { status: 403, handlerRan: false, bound: false },
  missing_revocation: { status: 403, handlerRan: false, bound: false },
  missing_store: { status: 403, handlerRan: false, bound: false },
  valid_first: { status: 200, handlerRan: true, bound: true },
  replay_second: { status: 403, handlerRan: false, bound: false },
});

const ROUTES: Record<string, { verb: string; resource: string }> = {
  'POST /payments': { verb: 'payments.send', resource: 'payments' },
  'POST /refunds': { verb: 'payments.refund', resource: 'payments' },
};

/** The server's mapping from request to operation: route table on method + path, JSON body as params. */
export function acceptanceOperation(req: PcaRequestLike): PcaOperation | null {
  const path = typeof req.url === 'string' ? new URL(req.url, 'http://adapter.invalid').pathname : '';
  const route = ROUTES[`${String(req.method).toUpperCase()} ${path}`];
  const body = req.body;
  if (!route || body === null || typeof body !== 'object' || Array.isArray(body)) return null;
  return { ...route, params: body as Record<string, unknown> };
}

function fixture(limit: 'predicate' | 'max_spend' | 'escalate') {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const pPub = encodeKey(principal.publicKey);
  const hPub = encodeKey(holder.publicKey);
  const { grant: minted } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: pPub,
    holder: hPub,
    goal: 'pay invoices',
    envelope: {
      predicates: [{ verb: ['payments.send', 'payments.refund'], resource: 'payments', where: limit === 'predicate' || limit === 'escalate' ? [{ field: 'action.params.amount', op: 'lte', value: 100 }] : [] }],
      caveats: [],
      agent_binding: {},
      // `escalate`: a payment over 50 asks the principal (decision escalate), with no answer it is refused
      ...(limit === 'escalate' ? { tighten: [{ id: 'big_payment', when: { field: 'action.params.amount', op: 'gt', value: 50 }, signal: 'escalate' as const }] } : {}),
      // "spend = risk": each call is priced at amount / 100 and debits the amount from a far-away budget
      risk_policy: { weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 },
    },
  });
  // max_spend as a ROOT caveat (outside the envelope): enforced like a delegated one
  const grant: Capability = limit === 'max_spend' ? mintRoot({ principalSecret: principal.secretKey, principalPublic: pPub, holder: hPub, caveats: [...minted.caveats, { type: 'max_spend', usd: 100 } as Caveat] }) : minted;
  let counter = 0;
  const request = (signed: { verb: string; amount: number }, sent: { path: string; amount: number }): AcceptanceRequest => {
    const params = { payee: 'acme', amount: signed.amount };
    const node: PlanNode = { id: 'n1', verb: signed.verb, resource: 'payments', params_digest: paramsDigest(params), reversibility_class: 'irreversible' };
    const p = buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params, counter: ++counter, signerSecret: holder.secretKey, aud: ADAPTER_ACCEPTANCE_AUDIENCE });
    return { method: 'POST', path: sent.path, headers: { ...pcaHeaders(encodePCActn(p)), 'content-type': 'application/json' }, body: { payee: 'acme', amount: sent.amount } };
  };
  const options = (over: Partial<RequireAuthorizedOptions> = {}): RequireAuthorizedOptions => ({
    audience: ADAPTER_ACCEPTANCE_AUDIENCE,
    resolveGrant: async (ref) => (ref === grant.id ? grant : null),
    budgetStore: memoryPcaStore(),
    hooks: { revocation: () => ({ enforced: true, ok: true }) },
    plan: 'single-step',
    operation: acceptanceOperation,
    risk: (o) => ({ blastRadius: Math.min(1, Number(o?.params?.amount) / 100), semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }),
    ...over,
  });
  return { request, options };
}

/** Run the matrix through `harness`; compare the result with {@link ADAPTER_ACCEPTANCE_EXPECTED} using deep equality. */
export async function runAdapterAcceptance(harness: AcceptanceHarness): Promise<Record<string, AcceptanceOutcome>> {
  const out: Record<string, AcceptanceOutcome> = {};
  const settle = (req: AcceptanceRequest, o: AcceptanceObservation): AcceptanceOutcome => {
    const ran = acceptanceOperation({ headers: {}, body: req.body, method: req.method, url: req.path });
    const bound = !!o.operation && !!ran && isAuthorizedFor({ ok: true, verdict: undefined as never, pcactn: undefined as never, operation: o.operation }, ran);
    return { status: o.status, handlerRan: o.handlerRan, bound };
  };
  const once = async (name: string, f: ReturnType<typeof fixture>, req: AcceptanceRequest, over: Partial<RequireAuthorizedOptions> = {}) => {
    out[name] = settle(req, await harness(f.options(over))(req));
  };

  const pred = fixture('predicate');
  await once('over_limit_predicate', pred, pred.request({ verb: 'payments.send', amount: 400 }, { path: '/payments', amount: 400 }));
  const spend = fixture('max_spend');
  await once('over_limit_max_spend', spend, spend.request({ verb: 'payments.send', amount: 400 }, { path: '/payments', amount: 400 }));
  await once('body_differs', pred, pred.request({ verb: 'payments.send', amount: 50 }, { path: '/payments', amount: 400 }));
  await once('other_operation', pred, pred.request({ verb: 'payments.send', amount: 50 }, { path: '/refunds', amount: 50 }));
  const esc = fixture('escalate');
  await once('escalate_unanswered', esc, esc.request({ verb: 'payments.send', amount: 70 }, { path: '/payments', amount: 70 }));
  await once('missing_revocation', pred, pred.request({ verb: 'payments.send', amount: 50 }, { path: '/payments', amount: 50 }), { hooks: {} });
  await once('missing_store', pred, pred.request({ verb: 'payments.send', amount: 50 }, { path: '/payments', amount: 50 }), { budgetStore: undefined as never });

  const send = harness(pred.options());
  const valid = pred.request({ verb: 'payments.send', amount: 50 }, { path: '/payments', amount: 50 });
  out.valid_first = settle(valid, await send(valid));
  out.replay_second = settle(valid, await send(valid));
  return out;
}
