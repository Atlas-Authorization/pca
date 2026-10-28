import {
  defaultExtract,
  pcactnDigest,
  missingAuthorizeComponents,
  requireAuthorized,
  requirePCA,
  type AuthorizeOptions,
  type AuthorizedOperation,
  type PCActn,
  type PcaOperation,
  type PcaRequestLike,
  type PcaVerdict,
  type RequirePcaOptions,
  type SignerSuiteOpts,
} from '@atlasauth/pca';
import {
  PROBLEM_BASE,
  intentActionDigest,
  intentProblem,
  signIntentRequired,
  type Friction,
  type IntentProblemKind,
  type IntentRequiredBody,
  type SignedIntentRequired,
} from '@atlasauth/pca/ext/intent';
import { frictionRank } from '@atlasauth/pca-wallet';
import { PCA_PROOF_COMPONENT, decodeProofHeader, verifySignedRequest, type KeyDirectory, type KeyResolver, type ReplayCache, type VerifyResult } from '@atlasauth/pca-webbotauth';
import { parseSitePolicy, type SitePolicy } from './policy';
import { NO_FACTS, classifyPresentedTier, type AccessTier, type PresentedFacts, type RateRule, type TierRule } from './tiers';

/**
 * THE SITE GUARD (docs/specs/pca-intent-layer-v2.md §3.15 drop-in adoption, §5 verification order). One
 * framework-neutral function that a site puts in front of every route; the adapters in `./adapters/*` wrap it for
 * Express, Fastify, Hono, Next.js and Web Fetch runtimes.
 *
 * Order, each step fail-closed, run only as far as the route's required tier needs:
 *   1. route → verb → per-verb rule (the §5 `tiers` member);
 *   2. Tier 1 `web_bot_auth`: RFC 9421 signature in the web-bot-auth profile (`@atlasauth/pca-webbotauth`). When a
 *      signature is present it must verify, whatever the tier; when it covers `PCA-Action`, the covered proof is the one
 *      the PCA step verifies (no swapping the proof under a valid signature);
 *   3. Tier 2 `requirePCA` (chain, aud, counter, revocation, default-deny), and the PCActn's verb must be the route's.
 *      With the `operation` option it is `authorize` instead: every component required and the proof bound to the
 *      route's operation (verb, resource, params);
 *   4. Tier 3 the INTENT PORT: schema, session, layers, accumulators, facts, provenance (the V3/V5–V9 verifier
 *      modules implement it). It may admit, deny with a sibling problem type, or ask: `intent_required` is signed with
 *      the site key and answered as an RFC 9457 problem (403); it is delivered to the wallet when the port's
 *      `deliver` hook succeeds (`delivered_to: "wallet"`), otherwise the agent relays it (`delivered_to: "agent"`);
 *      then JIT consent for the action at the rule's friction tier (`jit` port);
 *   5. Tier 4: a posted bond of at least `bond_min_cents` (`bond` port) and a stored evidence record (`evidence` port).
 *
 * A request that does not even present the proof its tier needs gets 401 with `WWW-Authenticate: PCA
 * error="insufficient_tier", tier="N"` and an `insufficient-tier` problem document. Unknown option or policy members
 * throw at construction (§5: a configuration error fails closed).
 */

export interface SiteRequest {
  method: string;
  /** The absolute request URL as the client addressed it (needed for RFC 9421 `@authority` / `@path`). */
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

export type CheckState = 'pass' | 'fail' | 'skipped';

export interface SiteDecision {
  allow: boolean;
  /** The tier the route requires. */
  tier: AccessTier;
  /** The highest tier the request proved (as far as it was evaluated). */
  presentedTier: AccessTier;
  verb: string | null;
  checks: Record<string, CheckState>;
  status: number;
  headers: Record<string, string>;
  body?: unknown;
  reason?: string;
  /** Tier 1: the verified agent key id. */
  agentKeyId?: string;
  pcactn?: PCActn;
  verdict?: PcaVerdict;
  /** With the `operation` option: the operation the Tier 2+ decision is bound to (`id` is the operation id). */
  operation?: AuthorizedOperation;
  /** Tier 3: the signed question when the decision is `intent_required`. */
  intentRequired?: SignedIntentRequired;
}

export interface IntentContext {
  req: SiteRequest;
  verb: string;
  rule: TierRule;
  policy: SitePolicy;
  pcactn: PCActn;
  verdict: PcaVerdict;
  now: number;
}

export type IntentProblem = Exclude<IntentProblemKind, 'intent-required'>;

/**
 * The question the intent check wants asked. The guard fills in the fixed members, `delivered_to`, (by default)
 * `expires_at`, and the two digests it computes itself from the verified PCActn: `pcactn_digest` and the core
 * `intentActionDigest(pcactn.action)` (the PCActn's signed action), so a port cannot bind a question to another action.
 */
export type IntentQuestion = Omit<IntentRequiredBody, 'v' | 'kind' | 'reason' | 'delivered_to' | 'expires_at' | 'pcactn_digest' | 'action_digest'> & { expires_at?: number };

export type IntentPortResult =
  | { kind: 'admit' }
  | { kind: 'deny'; problem: IntentProblem; reason: string }
  | { kind: 'intent_required'; question: IntentQuestion; deliver?: (signed: SignedIntentRequired) => Promise<boolean> };

/** Tier 3 checks (V3: schema, intent_session, layers, accumulators; V5–V9: layers, facts, provenance, classes, frames). */
export type IntentPort = (ctx: IntentContext) => Promise<IntentPortResult>;

/** JIT consent (v1 L4 / v2 M6 `consent_for_action`): the friction tier the principal consented at, or null. */
export type JitPort = (ctx: IntentContext & { minTier: Friction }) => Promise<{ tier: Friction } | null>;

/** Tier 4: the bond posted for this action (bond-settlement.ts), or null. */
export type BondPort = (ctx: IntentContext) => Promise<{ posted_cents: number } | null>;

/** Tier 4: store the evidence record of an admitted action (the bundle of pca-evidence is built from these). */
export interface EvidenceStore {
  record(entry: { verb: string; tier: AccessTier; pcactn: PCActn; verdict: PcaVerdict; at: number }): Promise<void>;
}

/** Rate limiting per key (agent key or principal), a sliding window. Must be shared across a fleet. */
export interface RateLimiter {
  /** Count one event for `key` at `now` and say whether it is within `rule`. */
  hit(key: string, rule: RateRule, now: number): Promise<boolean>;
}

/** In-process sliding-window limiter (one node). */
export function memoryRateLimiter(): RateLimiter {
  const events = new Map<string, number[]>();
  return {
    async hit(key, rule, now) {
      const from = now - rule.per_secs * 1000;
      const list = (events.get(key) ?? []).filter((t) => t > from);
      if (list.length >= rule.max) {
        events.set(key, list);
        return false;
      }
      list.push(now);
      events.set(key, list);
      return true;
    },
  };
}

export interface WebBotAuthOptions {
  jwks?: KeyDirectory;
  resolveKey?: KeyResolver;
  replayCache?: ReplayCache;
  clockSkewSec?: number;
}

export interface SiteGuardOptions {
  /** This site's audience id (signed into every PCActn). */
  audience: string;
  /** The §5 policy (validated; `tiers` and `web_bot_auth` are enforced here). */
  policy?: unknown;
  /** Map a request to its verb (from the route, the MCP tool, the OpenAPI operation). null = an unmapped route: denied. */
  verbOf: (req: SiteRequest) => string | null;
  webBotAuth?: WebBotAuthOptions;
  /** requirePCA options (the audience is taken from `audience`). With `operation`, `plan: 'single-step'` is also accepted. */
  pca?: Omit<RequirePcaOptions, 'audience' | 'extract' | 'operation'> & { plan?: 'single-step' };
  /**
   * The operation a Tier 2+ route executes, from the site's own routing (the route's verb and resource, the parsed body
   * as params), never from the PCActn. REQUIRED with `pca` since 0.5, unless `pca.insecureAllowUnboundOperation` is set
   * (migration only). The PCA step runs `authorize`: `pca` must then name a `budgetStore`, `hooks.revocation` and
   * `resolveGrant` (construction throws otherwise), the proof must be for exactly this operation, and its params are what
   * the grant's limits evaluate. null denies.
   */
  operation?: (req: SiteRequest, verb: string) => PcaOperation | null | undefined | Promise<PcaOperation | null | undefined>;
  intent?: IntentPort;
  jit?: JitPort;
  bond?: BondPort;
  evidence?: EvidenceStore;
  rateLimiter?: RateLimiter;
  /** The site key that signs `intent_required` (its public half is a discovery `intent.schema_keys` entry; `suite` for PQ). */
  siteKey?: { kid: string; secret: Uint8Array; suite?: SignerSuiteOpts };
  now?: () => number;
}

const OPTION_KEYS = ['audience', 'policy', 'verbOf', 'webBotAuth', 'pca', 'intent', 'jit', 'bond', 'evidence', 'rateLimiter', 'siteKey', 'now', 'operation'];

function problem(status: number, type: string, title: string, detail: string, extra: Record<string, string> = {}): Pick<SiteDecision, 'status' | 'headers' | 'body'> {
  return { status, headers: { 'Content-Type': 'application/problem+json', ...extra }, body: { type, title, status, detail } };
}

function lowerHeaders(h: SiteRequest['headers']): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(h)) if (v !== undefined) out[k.toLowerCase()] = v;
  return out;
}

/** The PCA step's request: the covered proof (if any) and, for the `operation` mapping, the site request and its verb. */
type SitePcaRequest = PcaRequestLike & { __proof?: PCActn; __site?: SiteRequest; __verb?: string };

export const PROBLEM_INSUFFICIENT_TIER = `${PROBLEM_BASE}insufficient-tier`;

/** Build the site guard. Throws on unknown options or an invalid policy. */
export function siteGuard(options: SiteGuardOptions): (req: SiteRequest) => Promise<SiteDecision> {
  for (const k of Object.keys(options)) if (!OPTION_KEYS.includes(k)) throw new TypeError(`siteGuard: unknown option "${k}"`);
  if (typeof options.audience !== 'string' || options.audience.length === 0) throw new TypeError('siteGuard: audience is required');
  if (typeof options.verbOf !== 'function') throw new TypeError('siteGuard: verbOf is required');
  const policy = parseSitePolicy(options.policy ?? {});
  const wbaOn = policy.web_bot_auth.accept;
  if (wbaOn && !options.webBotAuth?.jwks && !options.webBotAuth?.resolveKey) throw new TypeError('siteGuard: web_bot_auth.accept needs webBotAuth.jwks or webBotAuth.resolveKey');
  if (options.intent && !options.siteKey) throw new TypeError('siteGuard: an intent port needs a siteKey to sign intent_required');
  for (const [verb, rule] of Object.entries(policy.tiers)) {
    if (rule.tier === 1 && !wbaOn) throw new TypeError(`siteGuard: ${verb} is Tier 1 but web_bot_auth.accept is false`);
    if (rule.tier >= 2 && !options.pca) throw new TypeError(`siteGuard: ${verb} is Tier ${rule.tier} but no pca (requirePCA) options are given`);
    if (rule.rate && !options.rateLimiter) throw new TypeError(`siteGuard: ${verb} has a rate rule but no rateLimiter`);
  }
  if (options.pca && options.operation === undefined && !options.pca.insecureAllowUnboundOperation) {
    throw new TypeError('siteGuard: `pca` needs `operation` (0.5): map each Tier 2+ request to the operation it will execute so the proof is bound to it');
  }
  if (options.operation !== undefined) {
    if (typeof options.operation !== 'function') throw new TypeError('siteGuard: operation must be a function');
    if (!options.pca) throw new TypeError('siteGuard: operation needs pca options (authorize)');
    const missing = missingAuthorizeComponents({ ...options.pca, audience: options.audience });
    if (missing.length) throw new TypeError(`siteGuard: operation (authorize) is missing ${missing.join(', ')}`);
  }
  const extract = (r: PcaRequestLike) => (r as SitePcaRequest).__proof ?? defaultExtract(r);
  const mapOperation = options.operation;
  const guard = !options.pca
    ? null
    : mapOperation
      ? requireAuthorized({
          ...(options.pca as Omit<AuthorizeOptions, 'audience'>),
          audience: options.audience,
          extract,
          operation: (r) => {
            const sr = r as SitePcaRequest;
            return sr.__site && sr.__verb !== undefined ? mapOperation(sr.__site, sr.__verb) : null;
          },
        })
      : requirePCA({ ...(options.pca as Omit<RequirePcaOptions, 'audience' | 'extract'>), audience: options.audience, extract });
  const clock = options.now ?? (() => Date.now());

  return async (req) => {
    const checks: Record<string, CheckState> = {};
    const facts: PresentedFacts = { ...NO_FACTS };
    const now = clock();
    let verb: string | null = null;
    let required: AccessTier = 4;
    const done = (allow: boolean, rest: Partial<SiteDecision> & Pick<SiteDecision, 'status' | 'headers'>): SiteDecision => ({
      allow,
      tier: required,
      presentedTier: classifyPresentedTier(facts),
      verb,
      checks,
      ...rest,
    });
    const deny = (status: number, type: string, title: string, reason: string, extra: Record<string, string> = {}, more: Partial<SiteDecision> = {}): SiteDecision =>
      done(false, { ...problem(status, type, title, reason, extra), reason, ...more });
    const intentDeny = (kind: IntentProblem, reason: string, more: Partial<SiteDecision>, extraHeaders: Record<string, string> = {}): SiteDecision => {
      const p = intentProblem(kind, { detail: reason });
      return done(false, { status: p.status, headers: { ...p.headers, ...extraHeaders }, body: p.body, reason, ...more });
    };
    const insufficient = (why: string) =>
      deny(401, PROBLEM_INSUFFICIENT_TIER, 'This action needs a higher access tier', why, { 'WWW-Authenticate': `PCA error="insufficient_tier", tier="${required}"` });

    try {
      // 1. route -> rule
      verb = options.verbOf(req);
      const rule = verb === null ? undefined : policy.tiers[verb];
      if (verb === null || rule === undefined) {
        checks.route = 'fail';
        return deny(403, `${PROBLEM_BASE}unmapped-route`, 'This route is not open to agents', verb === null ? 'unmapped route' : `verb ${verb} has no tier rule`);
      }
      checks.route = 'pass';
      required = rule.tier;
      const headers = lowerHeaders(req.headers);

      // 2. web bot auth (whenever a signature is presented, and always for Tier 1)
      let proof: PCActn | undefined;
      let agentKeyId: string | undefined;
      const hasSig = headers['signature-input'] !== undefined || headers['signature'] !== undefined;
      if (hasSig && wbaOn) {
        const r: VerifyResult = await verifySignedRequest({ method: req.method, url: req.url, headers }, {
          ...(options.webBotAuth?.jwks ? { jwks: options.webBotAuth.jwks } : {}),
          ...(options.webBotAuth?.resolveKey ? { resolveKey: options.webBotAuth.resolveKey } : {}),
          ...(options.webBotAuth?.replayCache ? { replayCache: options.webBotAuth.replayCache } : {}),
          ...(options.webBotAuth?.clockSkewSec !== undefined ? { clockSkewSec: options.webBotAuth.clockSkewSec } : {}),
          now: Math.floor(now / 1000),
        });
        if (!r.valid) {
          checks.web_bot_auth = 'fail';
          return deny(401, `${PROBLEM_BASE}invalid-signature`, 'The HTTP message signature does not verify', r.reason ?? 'invalid signature', { 'WWW-Authenticate': 'PCA error="invalid_signature"' });
        }
        checks.web_bot_auth = 'pass';
        facts.webBotAuth = true;
        agentKeyId = r.keyid;
        if (r.covered?.includes(PCA_PROOF_COMPONENT)) {
          const hv = headers[PCA_PROOF_COMPONENT];
          try {
            proof = decodeProofHeader(Array.isArray(hv) ? hv.join(', ') : String(hv));
          } catch (e) {
            checks.web_bot_auth = 'fail';
            facts.webBotAuth = false;
            return deny(401, `${PROBLEM_BASE}invalid-signature`, 'The signed PCA-Action header is not a PCActn', (e as Error).message);
          }
        }
      } else checks.web_bot_auth = 'skipped';

      if (required === 0) return done(true, { status: 200, headers: {}, ...(agentKeyId !== undefined ? { agentKeyId } : {}) });
      if (required === 1) {
        if (!facts.webBotAuth) return insufficient('Tier 1 needs an RFC 9421 web-bot-auth signature from a known agent key');
        if (rule.rate && !(await options.rateLimiter!.hit(`${verb}|agent|${agentKeyId!}`, rule.rate, now))) {
          checks.rate = 'fail';
          return deny(429, `${PROBLEM_BASE}rate-limited`, 'Rate limit exceeded for this agent key', 'rate limit', { 'retry-after': String(rule.rate.per_secs) });
        }
        if (rule.rate) checks.rate = 'pass';
        return done(true, { status: 200, headers: {}, ...(agentKeyId !== undefined ? { agentKeyId } : {}) });
      }

      // 3. Tier 2: requirePCA
      const pcaReq: SitePcaRequest = {
        headers: req.headers,
        body: req.body,
        ...(proof ? { __proof: proof } : {}),
        ...(mapOperation ? { method: req.method, url: req.url, __site: req, __verb: verb } : {}),
      };
      let presented: unknown = proof ?? null;
      if (!proof) {
        try {
          presented = defaultExtract(pcaReq);
        } catch {
          presented = 'unreadable';
        }
      }
      if (presented === null) return insufficient(`Tier ${required} needs a PCActn (PCA-Action header or JSON body {pcactn})`);
      const g = await guard!(pcaReq);
      if (!g.ok) {
        checks.pca = 'fail';
        return done(false, {
          status: g.status,
          headers: { 'Content-Type': 'application/json', ...(g.wwwAuthenticate ? { 'WWW-Authenticate': g.wwwAuthenticate } : {}) },
          body: { error: g.verdict.reasons[0] ?? 'forbidden', verdict: g.verdict },
          reason: g.verdict.reasons[0] ?? 'forbidden',
          verdict: g.verdict,
        });
      }
      if (g.pcactn.action.verb !== verb) {
        checks.pca = 'fail';
        return deny(403, `${PROBLEM_BASE}verb-mismatch`, 'The PCActn is for a different action', `PCActn verb ${g.pcactn.action.verb} is not this route's verb ${verb}`);
      }
      checks.pca = 'pass';
      facts.pca = true;
      const base = { pcactn: g.pcactn, verdict: g.verdict, ...(g.operation ? { operation: g.operation } : {}), ...(agentKeyId !== undefined ? { agentKeyId } : {}) };

      if (rule.rate) {
        const leaf = g.pcactn.cap_chain[g.pcactn.cap_chain.length - 1];
        const who = rule.rate.key === 'principal' ? g.pcactn.cap_chain[0]?.issuer : leaf?.holder;
        if (!who || !(await options.rateLimiter!.hit(`${verb}|${rule.rate.key}|${who}`, rule.rate, now))) {
          checks.rate = 'fail';
          return deny(429, `${PROBLEM_BASE}rate-limited`, `Rate limit exceeded for this ${rule.rate.key}`, 'rate limit', { 'retry-after': String(rule.rate.per_secs) }, base);
        }
        checks.rate = 'pass';
      }
      if (required === 2) return done(true, { status: 200, headers: {}, ...base });

      // 4. Tier 3: intent checks through the port, then JIT consent
      if (!options.intent) {
        checks.intent = 'fail';
        return intentDeny('intent-denied', 'Tier 3 needs an intent port (fail closed)', base);
      }
      const ctx: IntentContext = { req, verb, rule, policy, pcactn: g.pcactn, verdict: g.verdict, now };
      const ir = await options.intent(ctx);
      if (ir.kind === 'deny') {
        checks.intent = 'fail';
        return intentDeny(ir.problem, ir.reason, base);
      }
      if (ir.kind === 'intent_required') {
        checks.intent = 'fail';
        const key = options.siteKey!;
        const body: Omit<IntentRequiredBody, 'delivered_to'> = {
          ...ir.question,
          v: 1,
          kind: 'pca-intent-required',
          reason: 'uncertain',
          pcactn_digest: pcactnDigest(g.pcactn),
          action_digest: intentActionDigest(g.pcactn.action),
          expires_at: ir.question.expires_at ?? now + policy.lazy.question_ttl_s * 1000,
        };
        const sign = (to: IntentRequiredBody['delivered_to']) => signIntentRequired({ ...body, delivered_to: to }, key.kid, key.secret, key.suite);
        let signed = sign('wallet');
        let delivered = false;
        if (policy.lazy.deliver === 'wallet_direct' && ir.deliver) {
          try {
            delivered = await ir.deliver(signed);
          } catch {
            delivered = false;
          }
        }
        if (!delivered) signed = sign('agent');
        const p = intentProblem('intent-required', { body: signed });
        return done(false, { status: p.status, headers: p.headers, body: p.body, reason: 'intent_required', intentRequired: signed, ...base });
      }
      checks.intent = 'pass';
      facts.intent = true;

      const irreversible = g.pcactn.action.reversibility_class === 'irreversible';
      const need = (irreversible ? rule.jit?.irreversible : rule.jit?.reversible) ?? 'none';
      if (need !== 'none') {
        const consent = options.jit ? await options.jit({ ...ctx, minTier: need }) : null;
        if (!consent || frictionRank(consent.tier) < frictionRank(need)) {
          checks.jit = 'fail';
          return intentDeny('intent-denied', `just-in-time consent at ${need} tier or above is required`, base, { 'WWW-Authenticate': `PCA error="consent_required", tier="${need}"` });
        }
        checks.jit = 'pass';
      }
      if (required === 3) return done(true, { status: 200, headers: {}, ...base });

      // 5. Tier 4: bond + evidence
      const posted = options.bond ? await options.bond(ctx) : null;
      if (!posted || !(posted.posted_cents >= (rule.bond_min_cents ?? 0))) {
        checks.bond = 'fail';
        return deny(403, `${PROBLEM_BASE}bond-required`, 'A bond must be posted for this action', options.bond ? `bond below ${rule.bond_min_cents ?? 0} cents` : 'no bond port (fail closed)', {}, base);
      }
      checks.bond = 'pass';
      facts.bond = true;
      if (!options.evidence) {
        checks.evidence = 'fail';
        return deny(403, `${PROBLEM_BASE}evidence-required`, 'Dispute-grade actions need an evidence store', 'no evidence store (fail closed)', {}, base);
      }
      try {
        await options.evidence.record({ verb, tier: required, pcactn: g.pcactn, verdict: g.verdict, at: now });
      } catch (e) {
        checks.evidence = 'fail';
        return deny(503, `${PROBLEM_BASE}evidence-required`, 'The evidence record could not be stored', (e as Error).message, {}, base);
      }
      checks.evidence = 'pass';
      facts.evidence = true;
      return done(true, { status: 200, headers: {}, ...base });
    } catch (e) {
      checks.guard = 'fail';
      return deny(500, `${PROBLEM_BASE}verifier-error`, 'The verifier failed', `fail closed: ${(e as Error).message}`);
    }
  };
}
