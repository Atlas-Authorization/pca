import { createAttestationVerifier, type AttestationVerifierOpts } from '../attestation';
import { type LivenessBeacon } from '../beacons';
import { type Capability } from '../capability';
import { decodePCActn, type PCActn, type VerifyHooks } from '../pcactn';
import { type RevocationEpoch } from '../revocation';
import { type TrustBudget } from '../risk';
import {
  DEFAULT_REQUIRED_CHECKS,
  enforceRequired,
  verifyPCActn,
  type PcaContext,
  type PcaPrincipalInfo,
  type PcaVerdict,
} from './verify';

/** Framework-agnostic request shape: anything with headers and (optionally) a parsed/raw body. */
export interface PcaRequestLike {
  headers: Record<string, string | string[] | undefined> | { get(name: string): string | null };
  body?: unknown;
}

/** Per-holder replay + budget state. Implement over Redis/DB; the in-memory one is for tests/single node. */
export interface PcaHolderState {
  budget?: TrustBudget;
  lastCounter?: number;
  /** newest signed revocation epoch accepted for the grant (monotonic pin). */
  lastEpoch?: number;
  /** newest liveness-beacon seq accepted for the grant (monotonic pin). */
  lastBeaconSeq?: number;
}

export interface PcaStateStore {
  get(key: string): Promise<PcaHolderState | undefined>;
  put(key: string, state: PcaHolderState): Promise<void>;
}

export function memoryPcaStore(): PcaStateStore {
  const m = new Map<string, PcaHolderState>();
  return { get: async (k) => m.get(k), put: async (k, v) => void m.set(k, v) };
}

export interface RequirePcaOptions {
  /**
   * REQUIRED: this resource server's audience id. A PCActn whose signed `aud` differs is denied (audit P0-5:
   * no cross-server replay). Omit only with `insecureAllowUnenforced`.
   */
  audience?: string;
  /** Resolve the Root Intent Grant from the PCActn's `grant_ref`. null = unknown grant. */
  resolveGrant: (grantRef: string, pcactn: PCActn) => Promise<Capability | null>;
  hooks?: VerifyHooks;
  /**
   * Attestation enforcement for this resource server. Builds the `attestation` hook with the SAME binding the
   * Atlas server enforces: supply `expectedBinding(ctx)` (leaf holder + grant + epoch + the server-issued nonce
   * and its issue time, e.g. from `GET /v1/pca/attest-challenge`) and `resolveDocument`. A grant whose
   * `agent_binding` is non-empty DENIES without a bound attestation (require-when-bound), regardless of this
   * option being set. An explicit `hooks.attestation` wins.
   */
  attestation?: AttestationVerifierOpts;
  extract?: (req: PcaRequestLike) => PCActn | string | null;
  /** Anti-replay counter + budget persistence. Without it counters are not checked (surfaced in checks). */
  budgetStore?: PcaStateStore;
  /** Build verification context (params, plan, risk) per request. */
  context?: (req: PcaRequestLike, pcactn: PCActn) => PcaContext | Promise<PcaContext>;
  now?: () => number;
  /** WWW-Authenticate realm (default "pca"). */
  realm?: string;
  /**
   * Minimum enforcement rungs: every named check must be 'pass'; a required check that is 'not-enforced'
   * DENIES (default-deny). Default: `['counter', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound']`, i.e. you must supply
   * a `budgetStore` (replay counter), a `hooks.revocation` checker, and a `context()` that returns the
   * RS's own `plan` + `planAuthorized: true`.
   */
  require?: string[];
  /**
   * EXPLICIT, LOUDLY-NAMED opt-out of the default-deny profile: required-but-unenforced checks are allowed
   * (the pre-hardening behaviour). Only for local development / migration; never in production.
   */
  insecureAllowUnenforced?: boolean;
  /**
   * Supply the guardian-signed revocation epoch for a grant (e.g. fetched from `GET /v1/pca/revocations/epoch`)
   * plus the pinned guardian public key. When given, the `freshness` check is REQUIRED (default-deny): the
   * epoch must verify, be unexpired, not roll back past the last one accepted, and the PCActn's signed
   * `freshness.epoch` must be at least as new. Needs a `budgetStore` to pin the last accepted epoch.
   */
  revocationEpoch?: (
    grantRef: string,
    pcactn: PCActn,
  ) => Promise<{ epoch: RevocationEpoch; guardianPublic: string } | null | undefined>;
  /**
   * Supply the current liveness beacon for a grant (e.g. from `GET /v1/pca/beacons`) plus the pinned issuer key(s)
   * (the grant principal and/or operator) and your instance id. When given, the `beacon` check is REQUIRED
   * (default-deny): a stale / absent / replayed / unbound beacon DENIES, so a principal who stops issuing halts
   * the agent. The PCActn must commit it via `freshness.beacon_ref = beaconRef(beacon)`. Needs a `budgetStore`
   * to pin the last accepted seq.
   */
  beacon?: (
    grantRef: string,
    pcactn: PCActn,
  ) => Promise<{ beacon: LivenessBeacon; issuers: string[]; instance: string } | null | undefined>;
  /** Resolve the grant's issuer to an enrolled principal. Its result is returned on `verdict.principal`. */
  resolvePrincipal?: (principalPub: string, grant: Capability) => Promise<PcaPrincipalInfo | null | undefined>;
  /** Deny unless `resolvePrincipal` yields a `verified` principal (identity enforcement at the resource server). */
  requireVerifiedPrincipal?: boolean;
}

export type PcaGuardResult =
  | { ok: true; verdict: PcaVerdict; pcactn: PCActn }
  | { ok: false; status: 401 | 403; verdict: PcaVerdict; wwwAuthenticate?: string };

function header(req: PcaRequestLike, name: string): string | undefined {
  const h = req.headers as { get?: (n: string) => string | null } & Record<string, string | string[] | undefined>;
  if (typeof h.get === 'function') return h.get(name) ?? undefined;
  // Plain object: HTTP field names are case-insensitive (RFC 9110 §5.1). Match own keys only (never the prototype). If the
  // object carries several case-variants of the name with DIFFERENT values the credential is ambiguous -> treat as absent
  // (the caller then denies), never silently pick one.
  const want = name.toLowerCase();
  let found: string | undefined;
  for (const k of Object.keys(h)) {
    if (k.toLowerCase() !== want) continue;
    const raw = (h as Record<string, string | string[] | undefined>)[k];
    const v = Array.isArray(raw) ? raw[0] : raw;
    if (typeof v !== 'string') continue;
    if (found !== undefined && found !== v) return undefined;
    found = v;
  }
  return found;
}

function fromB64u(s: string): string {
  const b = s.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(b, 'base64').toString('utf8');
}

/** Default extraction: `PCA-Action: <base64url PCActn JSON>` header, else JSON body `{ pcactn }`. */
export function defaultExtract(req: PcaRequestLike): PCActn | string | null {
  const h = header(req, 'pca-action');
  if (h) return fromB64u(h.trim());
  let b = req.body;
  if (typeof b === 'string') {
    try {
      b = JSON.parse(b);
    } catch {
      return null;
    }
  }
  const x = (b as { pcactn?: unknown } | null | undefined)?.pcactn;
  if (typeof x === 'string' || (x !== null && typeof x === 'object')) return x as PCActn | string;
  return null;
}

const denyVerdict = (reason: string): PcaVerdict => ({
  allow: false,
  r: 1,
  requiredThreshold: { t: 3, proof: 'strong', optimisticAllowed: false },
  checks: { pcactn: 'fail' },
  reasons: [reason],
});

export function requirePCA(opts: RequirePcaOptions): (req: PcaRequestLike) => Promise<PcaGuardResult> {
  if (!opts.audience && !opts.insecureAllowUnenforced) {
    throw new TypeError('requirePCA: `audience` (this resource server\'s id) is required (or set insecureAllowUnenforced)');
  }
  const realm = opts.realm ?? 'pca';
  const challenge = (error?: string) =>
    `PCA realm="${realm}"${error ? `, error="${error}"` : ''}, hint="send PCA-Action: <base64url PCActn> or JSON body {pcactn}"`;
  const unauth = (reason: string, error = 'invalid_request'): PcaGuardResult => ({
    ok: false,
    status: 401,
    verdict: denyVerdict(reason),
    wwwAuthenticate: challenge(error),
  });

  return async (req) => {
    try {
      let raw: PCActn | string | null;
      try {
        raw = (opts.extract ?? defaultExtract)(req);
      } catch (e) {
        return unauth(`unreadable PCActn: ${(e as Error).message}`);
      }
      if (raw === null || raw === undefined) return unauth('no PCActn presented', 'missing_pcactn');
      let p: PCActn;
      try {
        p = typeof raw === 'string' ? decodePCActn(raw) : raw;
      } catch (e) {
        return unauth(`undecodable PCActn: ${(e as Error).message}`, 'invalid_pcactn');
      }
      if (p === null || typeof p !== 'object' || typeof p.grant_ref !== 'string') {
        return unauth('malformed PCActn', 'invalid_pcactn');
      }
      const grant = await opts.resolveGrant(p.grant_ref, p);
      if (!grant) return unauth('unknown grant_ref', 'unknown_grant');

      const now = opts.now?.() ?? Date.now();
      const leafHolder = p.cap_chain?.[p.cap_chain.length - 1]?.holder;
      const key = `${grant.id}:${leafHolder ?? ''}`;
      const state = opts.budgetStore && leafHolder ? await opts.budgetStore.get(key) : undefined;
      const ctx: PcaContext = { ...(await opts.context?.(req, p)) };
      if (state?.budget && ctx.budget === undefined) ctx.budget = state.budget;
      if (opts.revocationEpoch && ctx.revocationEpoch === undefined) {
        const re = await opts.revocationEpoch(p.grant_ref, p);
        // an unavailable epoch is NOT silently skipped: the required `freshness` check stays not-enforced -> denied.
        if (re) {
          const epochState = opts.budgetStore ? await opts.budgetStore.get(`${grant.id}:epoch`) : undefined;
          ctx.revocationEpoch = { ...re, lastAcceptedEpoch: epochState?.lastEpoch };
        }
      }

      if (opts.beacon && ctx.beacon === undefined) {
        const b = await opts.beacon(p.grant_ref, p);
        // an unavailable beacon is NOT skipped: the required `beacon` check stays not-enforced -> denied (dead-man).
        if (b) {
          const bs = opts.budgetStore ? await opts.budgetStore.get(`${grant.id}:beacon`) : undefined;
          ctx.beacon = { ...b, lastAcceptedSeq: bs?.lastBeaconSeq };
        }
      }

      const hooks: VerifyHooks | undefined =
        opts.attestation && !opts.hooks?.attestation
          ? { ...opts.hooks, attestation: createAttestationVerifier({ now: () => now, ...opts.attestation }) }
          : opts.hooks;
      const verdict = await verifyPCActn(p, { grant, hooks, now, context: ctx, audience: opts.audience });

      // Anti-replay (Appendix A step 5): strictly increasing per holder.
      if (opts.budgetStore) {
        if (state?.lastCounter !== undefined && !(p.counter > state.lastCounter)) {
          verdict.allow = false;
          verdict.checks.counter = 'fail';
          verdict.reasons.push(`counter: ${String(p.counter)} is not greater than last seen ${state.lastCounter} (replay)`);
        } else if (verdict.checks.counter === 'pass') {
          verdict.checks.counter = 'pass';
        }
      } else if (verdict.checks.counter === 'pass') {
        verdict.checks.counter = 'not-enforced';
      }

      if (!opts.insecureAllowUnenforced) {
        enforceRequired(verdict, opts.require ?? [
          ...DEFAULT_REQUIRED_CHECKS,
          ...(opts.revocationEpoch ? ['freshness'] : []),
          ...(opts.beacon ? ['beacon'] : []),
        ]);
      }

      if (opts.resolvePrincipal) {
        const resolved = await opts.resolvePrincipal(grant.issuer, grant);
        const principal: PcaPrincipalInfo = resolved ?? {
          pub: grant.issuer,
          subject_type: 'unverified',
          subject_id: null,
          verified: false,
        };
        verdict.principal = principal;
        if (opts.requireVerifiedPrincipal && !principal.verified) {
          verdict.allow = false;
          verdict.checks.principal = 'fail';
          verdict.reasons.push('principal: the grant issuer is not an enrolled, verified principal');
        } else verdict.checks.principal = principal.verified ? 'pass' : 'not-enforced';
      } else if (opts.requireVerifiedPrincipal) {
        verdict.allow = false;
        verdict.checks.principal = 'fail';
        verdict.reasons.push('principal: requireVerifiedPrincipal needs a resolvePrincipal resolver');
      }

      if (!verdict.allow) {
        // A bad signature / chain is an authentication failure; policy denial is authorization.
        const authnFailed = ['wire', 'version', 'audience', 'validity', 'cap_chain', 'grant_ref_bound', 'leaf_signature', 'malformed', 'grant_ref'].some(
          (c) => verdict.checks[c] === 'fail',
        );
        return authnFailed
          ? { ok: false, status: 401, verdict, wwwAuthenticate: challenge('invalid_pcactn') }
          : { ok: false, status: 403, verdict };
      }
      if (opts.budgetStore && ctx.revocationEpoch && verdict.checks.freshness === 'pass') {
        const k = `${grant.id}:epoch`;
        const prev = await opts.budgetStore.get(k);
        if ((prev?.lastEpoch ?? -1) < ctx.revocationEpoch.epoch.epoch) await opts.budgetStore.put(k, { lastEpoch: ctx.revocationEpoch.epoch.epoch });
      }
      if (opts.budgetStore && ctx.beacon && verdict.checks.beacon === 'pass') {
        const k = `${grant.id}:beacon`;
        const prev = await opts.budgetStore.get(k);
        if ((prev?.lastBeaconSeq ?? -1) < ctx.beacon.beacon.seq) await opts.budgetStore.put(k, { lastBeaconSeq: ctx.beacon.beacon.seq });
      }
      if (opts.budgetStore && leafHolder) {
        await opts.budgetStore.put(key, { budget: verdict.budget ?? state?.budget, lastCounter: p.counter });
      }
      return { ok: true, verdict, pcactn: p };
    } catch (e) {
      return { ok: false, status: 403, verdict: denyVerdict(`guard error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`) };
    }
  };
}
