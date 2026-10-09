/**
 * The facade (spec Part 2.1 "make the engine invisible").
 *
 *   const a = agent({
 *     principal,                       // the human's key — mints + roots the grant (longest-lived)
 *     goal: 'reconcile refunds for October',
 *     permissions: { stripe: ['refund'], gmail: ['send'] },
 *     limits: { refund: '$500/day' },
 *   });
 *   const { encoded } = a.act('stripe.refund', 'charge:ch_123', { amount: 42, currency: 'usd' }, { counter: 1 });
 *   // POST `encoded` to the resource server; its requirePCA()/adjudicator is authoritative.
 *
 * `agent()` compiles the human-level inputs into the REAL primitives — a policy envelope (predicates +
 * caveats), a risk policy / trust budget, and a signed Root Intent Grant (`mintGrant`) — then returns a
 * handle that builds a well-formed PCActn per tool call (`buildPCActn`) and offers a NON-authoritative
 * local `dryRun`. Nothing here authorizes anything on its own: the facade only produces proof-carrying
 * actions; the resource server's verifier (`requirePCA` / the adjudicator) decides. Every field it emits
 * is covered by a signature, so the facade cannot be a trusted bypass — a tampered grant or action
 * simply fails verification downstream.
 *
 * This is the general case of the payments mandate (`@atlasauth/pca-payments`): same compile-down, across
 * the connector catalog instead of a single `charge` verb.
 */

import { type Capability, type CapabilityChain, type Caveat, delegate } from './capability';
import { type Catalog, DEFAULT_CATALOG, type ActionSpec } from './catalog';
import { mintGrant, type AgentBinding } from './envelope';
import { type KeyPair, generateKeyPair } from './keys';
import { b64u } from './hash';
import { buildPCActn, encodePCActn, type PCActn } from './pcactn';
import { type PlanNode, paramsDigest } from './merkle';
import {
  type ActionContext,
  type Predicate,
  REVERSIBILITY_ORDER,
  evaluateCaveats,
  evaluatePredicates,
} from './predicates';
import {
  DEFAULT_RISK_POLICY,
  type RiskPolicy,
  type TrustBudget,
  admit,
  safetyBound,
  validateRiskPolicy,
} from './risk';

// ---- inputs ---------------------------------------------------------------------------------------

/** `{ stripe: ['refund', 'charge'], gmail: ['send'] }` — connector → allowed actions. */
export interface PermissionMap {
  [connector: string]: string[];
}

/** Human limit strings keyed by action name (`refund`) or fully-qualified verb (`stripe.refund`). */
export interface Limits {
  [verbOrAction: string]: string;
}

export interface AgentOptions {
  /** The human/principal key: signs + roots the grant. The longest-lived key in the system. */
  principal: KeyPair;
  /** Plaintext goal; only its salted commitment goes in the grant. */
  goal: string;
  /** What the agent may do. */
  permissions: PermissionMap;
  /** Optional per-action limits, e.g. `{ refund: '$500/day' }`. */
  limits?: Limits;
  /** The agent (holder) keypair that signs PCActns. Generated (and returned) when omitted. */
  holder?: KeyPair;
  /** Optional agent-identity binding (model/weights/operator/system-prompt pins). */
  agentBinding?: AgentBinding;
  /** Override/tweak the derived risk policy. */
  riskPolicy?: Partial<RiskPolicy>;
  /**
   * Budget denomination. `dollars` makes "spend = risk" exact (γ=1, κ=cap) when limits are monetary;
   * `risk` uses the default risk weights. `auto` (default) picks `dollars` iff any `$` limit is present.
   */
  budgetModel?: 'auto' | 'dollars' | 'risk';
  /** Connector catalog (defaults to the built-ins). */
  catalog?: Catalog;
  /** Default audience (resource-server / instance id) for `act`; overridable per call. */
  aud?: string;
  /** Clock (ms) for grant minting + period windows. Default `Date.now()`. */
  now?: number;
}

// ---- limit parsing --------------------------------------------------------------------------------

export interface ParsedLimit {
  amount: number;
  unit: 'usd' | 'count';
  /** Period window in ms, if the limit named one (`/day`). */
  periodMs?: number;
}

const PERIODS: Record<string, number> = {
  s: 1000, sec: 1000, second: 1000, seconds: 1000,
  m: 60_000, min: 60_000, minute: 60_000, minutes: 60_000,
  h: 3_600_000, hr: 3_600_000, hour: 3_600_000, hours: 3_600_000,
  d: 86_400_000, day: 86_400_000, days: 86_400_000,
  w: 604_800_000, week: 604_800_000, weeks: 604_800_000,
  mo: 2_592_000_000, month: 2_592_000_000, months: 2_592_000_000,
};

/** Longest limit string accepted (the grammar needs ~20 characters). Bounds the work AND the error text. */
export const MAX_LIMIT_LENGTH = 64;

/**
 * Parse `"$500/day"`, `"$500"`, `"10/hour"`, `"10"`. Throws on anything malformed, and on anything longer than
 * {@link MAX_LIMIT_LENGTH} characters (the previous `^\s*(\$)?\s*...` pattern backtracked quadratically on long
 * whitespace runs). The pattern now runs on the trimmed string with a single `\s*` per gap, so it is linear.
 */
export function parseLimit(s: string): ParsedLimit {
  if (typeof s !== 'string' || s.trim().length === 0) throw new Error(`parseLimit: empty limit`);
  if (s.length > MAX_LIMIT_LENGTH) throw new Error(`parseLimit: limit is longer than ${MAX_LIMIT_LENGTH} characters`);
  const m = /^(\$)?\s*([0-9]+(?:\.[0-9]+)?)\s*(?:\/\s*([a-zA-Z]+))?$/.exec(s.trim());
  if (!m) throw new Error(`parseLimit: cannot parse limit '${s}'`);
  const unit: 'usd' | 'count' = m[1] === '$' ? 'usd' : 'count';
  const amount = Number(m[2]);
  if (!Number.isFinite(amount) || amount < 0) throw new Error(`parseLimit: bad amount in '${s}'`);
  let periodMs: number | undefined;
  if (m[3] !== undefined) {
    const p = PERIODS[m[3].toLowerCase()];
    if (p === undefined) throw new Error(`parseLimit: unknown period '${m[3]}' in '${s}'`);
    periodMs = p;
  }
  return { amount, unit, ...(periodMs !== undefined ? { periodMs } : {}) };
}

// ---- compiled policy ------------------------------------------------------------------------------

export interface CompiledPolicy {
  predicates: Predicate[];
  caveats: Caveat[];
  riskPolicy: RiskPolicy;
  /** The resolved action specs (one per granted permission). */
  actions: ActionSpec[];
  budgetModel: 'dollars' | 'risk';
  /** Per-action parsed limits that matched a granted action, keyed by verb. */
  limits: Record<string, ParsedLimit>;
  /** The RAW limit input as given (keys may be bare action names or FQ verbs); lets the linter flag unmatched keys. */
  inputLimits: Limits;
}

/** Conservative fallback for a verb not in the catalog: treat as irreversible, high blast radius. */
function specFor(catalog: Catalog, verb: string): ActionSpec {
  const s = catalog.get(verb);
  if (s) return s;
  const [connector, ...rest] = verb.split('.');
  return {
    connector: connector ?? verb,
    action: rest.join('.') || verb,
    verb,
    reversibility: 'irreversible',
    blastRadius: 0.8,
    description: `(uncatalogued) ${verb}`,
  };
}

const sev = (cls: string): number => REVERSIBILITY_ORDER.indexOf(cls as (typeof REVERSIBILITY_ORDER)[number]);

/** Compile permissions + limits into the real policy primitives. Pure — no keys, no signing. */
export function compilePolicy(opts: {
  permissions: PermissionMap;
  limits?: Limits;
  catalog?: Catalog;
  budgetModel?: 'auto' | 'dollars' | 'risk';
  riskPolicy?: Partial<RiskPolicy>;
  now?: number;
}): CompiledPolicy {
  const catalog = opts.catalog ?? DEFAULT_CATALOG;
  const now = opts.now ?? Date.now();
  const rawLimits = opts.limits ?? {};

  // Resolve every granted (connector, action) to an ActionSpec.
  const actions: ActionSpec[] = [];
  for (const [connector, acts] of Object.entries(opts.permissions)) {
    if (!Array.isArray(acts)) throw new Error(`compilePolicy: permissions.${connector} must be an array`);
    for (const action of acts) actions.push(specFor(catalog, `${connector}.${action}`));
  }
  if (actions.length === 0) throw new Error('compilePolicy: no permissions granted');

  // Resolve a limit for an action: fully-qualified verb wins over the bare action name.
  // Read OWN keys only: `rawLimits` can originate from untrusted JSON, and an action named like an
  // Object.prototype member (`toString`, `constructor`, `__proto__`, `valueOf`, …) would otherwise read
  // the inherited value — a function or the prototype object — and feed it to parseLimit, throwing on a
  // policy that never configured that limit at all. Own-key lookup makes an absent limit truly absent.
  const ownLimit = (key: string): string | undefined =>
    Object.prototype.hasOwnProperty.call(rawLimits, key) ? rawLimits[key] : undefined;
  const limits: Record<string, ParsedLimit> = {};
  const limitFor = (s: ActionSpec): ParsedLimit | undefined => {
    const raw = ownLimit(s.verb) ?? ownLimit(s.action);
    if (raw === undefined) return undefined;
    const parsed = parseLimit(raw);
    limits[s.verb] = parsed;
    return parsed;
  };

  // Predicates: one per granted action. A monetary limit becomes a hard per-call ceiling.
  const predicates: Predicate[] = actions.map((s) => {
    const where: NonNullable<Predicate['where']> = [];
    const lim = limitFor(s);
    if (lim && lim.unit === 'usd' && s.amountField) {
      where.push({ field: `action.params.${s.amountField}`, op: 'lte', value: lim.amount });
      where.push({ field: `action.params.${s.amountField}`, op: 'gte', value: 0 });
    }
    return { verb: s.verb, resource: s.resource ?? '*', ...(where.length ? { where } : {}) };
  });

  // Caveats:
  //  - reversibility_max at the STRICTEST granted class (a child can never exceed it).
  //  - a period `expires` window = the smallest period any limit named (grant lifetime).
  //  - a grant-wide `rate` for a single count-limit (the closest offline primitive; see note).
  const caveats: Caveat[] = [];
  const strictest = actions.reduce((acc, s) => (sev(s.reversibility) > sev(acc) ? s.reversibility : acc), 'reversible' as string);
  caveats.push({ type: 'reversibility_max', class: strictest });

  const periods = Object.values(limits).map((l) => l.periodMs).filter((p): p is number => typeof p === 'number');
  if (periods.length) caveats.push({ type: 'expires', at: now + Math.min(...periods) });

  const countLimits = Object.values(limits).filter((l) => l.unit === 'count' && l.periodMs);
  if (countLimits.length === 1) {
    const cl = countLimits[0]!;
    caveats.push({ type: 'rate', max: cl.amount, per_secs: Math.max(1, Math.round(cl.periodMs! / 1000)) });
  }

  // Budget model.
  const dollarLimits = Object.values(limits).filter((l) => l.unit === 'usd');
  const model: 'dollars' | 'risk' =
    opts.budgetModel === 'dollars' ? 'dollars'
    : opts.budgetModel === 'risk' ? 'risk'
    : dollarLimits.length > 0 ? 'dollars' : 'risk';

  let riskPolicy: RiskPolicy;
  if (model === 'dollars' && dollarLimits.length > 0) {
    // "spend = risk" exact (mirrors mandateRiskPolicy): γ=1, κ = largest per-call cap, bMax = Σ caps.
    const kappa = Math.max(...dollarLimits.map((l) => l.amount));
    const bMax = dollarLimits.reduce((a, l) => a + l.amount, 0);
    riskPolicy = {
      weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 },
      theta1: 1, // within-cap actions auto-approve (over-cap is denied by the ceiling predicate)
      theta2: 1,
      kappa: kappa > 0 ? kappa : 1,
      lambda: 0,
      rho: DEFAULT_RISK_POLICY.rho,
      bMax: bMax > 0 ? bMax : 1,
    };
  } else {
    riskPolicy = { ...DEFAULT_RISK_POLICY, weights: { ...DEFAULT_RISK_POLICY.weights } };
  }
  if (opts.riskPolicy) {
    riskPolicy = { ...riskPolicy, ...opts.riskPolicy, weights: { ...riskPolicy.weights, ...(opts.riskPolicy.weights ?? {}) } };
  }
  const bad = validateRiskPolicy(riskPolicy);
  if (bad) throw new Error(`compilePolicy: derived risk policy invalid: ${bad}`);

  return { predicates, caveats, riskPolicy, actions, budgetModel: model, limits, inputLimits: { ...rawLimits } };
}

// ---- the agent handle -----------------------------------------------------------------------------

export interface ActOptions {
  /** Monotonic per-holder counter. Auto-incremented when omitted. */
  counter?: number;
  /** Audience (resource-server / instance id). Falls back to the agent's default; required if neither set. */
  aud?: string;
  now?: number;
  ttlMs?: number;
  nonce?: string;
  /** Agent uncertainty in [0,1] (can only RAISE server-side risk). */
  caution?: number;
  /** Override the risk value claimed for this action (else derived from the action spec / amount). */
  risk?: number;
}

/** A non-authoritative, offline pre-check of the grant's OWN predicates + caveats for an action. */
export interface DryRun {
  /** True iff the grant's predicates admit this action AND its caveats hold locally. */
  allowed: boolean;
  reason?: string;
  /** The risk tier admit() would assign under the compiled policy (1 auto / 2 / 3 human co-sign). */
  t?: number;
}

export interface ActResult {
  pcactn: PCActn;
  /** Wire-encoded PCActn — POST this to the resource server. */
  encoded: string;
  /** The local, non-authoritative dry-run for this action. */
  dryRun: DryRun;
}

export interface Agent {
  /** The signed Root Intent Grant. */
  grant: Capability;
  /** The full capability chain (root grant first; one extra hop per sub-agent). */
  chain: CapabilityChain;
  /** b64u salt that opens the grant's goal commitment (keep alongside the goal). */
  goalSalt: string;
  /** The compiled policy (predicates/caveats/risk). */
  policy: CompiledPolicy;
  /** The agent (holder) keypair — its secret signs PCActns and never leaves the client. */
  holder: KeyPair;
  /** b64u principal public key. */
  principalPublic: string;
  /** The starting trust budget (B = bMax). Threaded + metered server-side; exposed for planning. */
  budget: TrustBudget;
  /** The §2.4 autonomous bound: the most this agent can do between human co-signs (bMax/κ · κ). */
  autonomyBound: number;
  /** Build a proof-carrying action. Does NOT authorize — the resource server's verifier does. */
  act(verb: string, resource: string, params?: Record<string, unknown>, opts?: ActOptions): ActResult;
  /** Offline, non-authoritative pre-check of this grant's predicates + caveats for an action. */
  dryRun(verb: string, resource: string, params?: Record<string, unknown>, opts?: { now?: number }): DryRun;
  /** Rebind to a sub-agent: a new Agent whose chain has one more (attenuated) hop. */
  subAgent(opts?: { holder?: KeyPair; addedCaveats?: Caveat[] }): Agent;
  /** Wire-encode the grant (for transport / inspection). */
  encodeGrant(): string;
}

function riskFor(policy: CompiledPolicy, spec: ActionSpec, params: Record<string, unknown> | undefined, override?: number): number {
  if (typeof override === 'number') return Math.max(0, Math.min(1, override));
  if (policy.budgetModel === 'dollars' && spec.amountField) {
    const amt = Number((params ?? {})[spec.amountField]);
    if (Number.isFinite(amt) && policy.riskPolicy.kappa > 0) return Math.max(0, Math.min(1, amt / policy.riskPolicy.kappa));
  }
  return Math.max(0, Math.min(1, spec.blastRadius));
}

/** Internal: assemble an Agent handle over a given chain + holder + compiled policy. */
function makeAgent(args: {
  grant: Capability;
  chain: CapabilityChain;
  goalSalt: string;
  policy: CompiledPolicy;
  holder: KeyPair;
  principalPublic: string;
  catalog: Catalog;
  defaultAud?: string;
  startNow: number;
}): Agent {
  const { policy, catalog } = args;
  let counter = 0;
  const budget: TrustBudget = { B: policy.riskPolicy.bMax, tau: args.startNow, asOf: args.startNow };

  const dryRun = (verb: string, resource: string, params?: Record<string, unknown>, o?: { now?: number }): DryRun => {
    const spec = specFor(catalog, verb);
    const now = o?.now ?? Date.now();
    const ctx: ActionContext = {
      action: { verb, resource, params: params ?? {}, reversibility_class: spec.reversibility },
    };
    const pred = evaluatePredicates(policy.predicates, ctx);
    if (!pred.allowed) return { allowed: false, reason: pred.reason ?? 'no predicate matched' };
    const cav = evaluateCaveats(policy.caveats, {
      now,
      blastRadius: spec.blastRadius,
      reversibilityClass: spec.reversibility,
      delegationDepth: args.chain.length - 1,
    });
    if (!cav.ok) return { allowed: false, reason: `caveat(s) failed: ${cav.failed.join(', ')}` };
    const r = riskFor(policy, spec, params);
    const adm = admit(r, budget, policy.riskPolicy);
    return { allowed: true, t: adm.t };
  };

  return {
    grant: args.grant,
    chain: args.chain,
    goalSalt: args.goalSalt,
    policy,
    holder: args.holder,
    principalPublic: args.principalPublic,
    budget,
    autonomyBound: safetyBound(policy.riskPolicy) * policy.riskPolicy.kappa,
    dryRun,
    act(verb, resource, params, opts) {
      const aud = opts?.aud ?? args.defaultAud;
      if (!aud) throw new Error('act: aud (resource-server / instance id) is required (pass opts.aud or AgentOptions.aud)');
      const spec = specFor(catalog, verb);
      // The node must commit the SAME params digest the action carries, else plan-inclusion fails.
      const node: PlanNode = { id: 'n0', verb, resource, reversibility_class: spec.reversibility, params_digest: paramsDigest(params) };
      const r = riskFor(policy, spec, params, opts?.risk);
      const useCounter = opts?.counter ?? ++counter;
      if (opts?.counter !== undefined) counter = Math.max(counter, opts.counter);
      const pcactn = buildPCActn({
        grant: args.grant,
        chain: args.chain,
        plan: [node],
        nodeId: 'n0',
        params,
        counter: useCounter,
        signerSecret: args.holder.secretKey,
        aud,
        riskClaim: { r, inputs: { blastRadius: r } },
        ...(opts?.now !== undefined ? { now: opts.now } : {}),
        ...(opts?.ttlMs !== undefined ? { ttlMs: opts.ttlMs } : {}),
        ...(opts?.nonce !== undefined ? { nonce: opts.nonce } : {}),
        ...(opts?.caution !== undefined ? { caution: opts.caution } : {}),
      });
      return { pcactn, encoded: encodePCActn(pcactn), dryRun: dryRun(verb, resource, params, { now: opts?.now }) };
    },
    subAgent(o) {
      const sub = o?.holder ?? generateKeyPair();
      const leaf = args.chain[args.chain.length - 1]!;
      const child = delegate(leaf, b64u(sub.publicKey), o?.addedCaveats ?? [], args.holder.secretKey);
      return makeAgent({
        grant: args.grant,
        chain: [...args.chain, child],
        goalSalt: args.goalSalt,
        policy,
        holder: sub,
        principalPublic: args.principalPublic,
        catalog,
        defaultAud: args.defaultAud,
        startNow: args.startNow,
      });
    },
    encodeGrant() {
      return JSON.stringify(args.grant);
    },
  };
}

/**
 * Build an agent: compile the human inputs into a signed grant + a handle that emits PCActns.
 * The returned agent's `holder.secretKey` signs actions and must stay client-side.
 */
export function agent(opts: AgentOptions): Agent {
  const catalog = opts.catalog ?? DEFAULT_CATALOG;
  const now = opts.now ?? Date.now();
  const holder = opts.holder ?? generateKeyPair();
  const policy = compilePolicy({
    permissions: opts.permissions,
    limits: opts.limits,
    catalog,
    budgetModel: opts.budgetModel,
    riskPolicy: opts.riskPolicy,
    now,
  });
  const principalPublic = b64u(opts.principal.publicKey);
  const { grant, goalSalt } = mintGrant({
    principalSecret: opts.principal.secretKey,
    principalPublic,
    holder: b64u(holder.publicKey),
    goal: opts.goal,
    envelope: {
      predicates: policy.predicates,
      caveats: policy.caveats,
      agent_binding: opts.agentBinding ?? {},
      risk_policy: policy.riskPolicy,
    },
  });
  return makeAgent({
    grant,
    chain: [grant],
    goalSalt,
    policy,
    holder,
    principalPublic,
    catalog,
    defaultAud: opts.aud,
    startNow: now,
  });
}
