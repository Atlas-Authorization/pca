/**
 * The relying-party client: `checkAgent` decides whether to trust an unknown agent from its passport and the transparency logs.
 *
 * It verifies the passport (signature, window, hardware attestation), proves the passport is listed in at least N independent
 * logs (signed head, witness cosignatures, inclusion proof), checks the heads are fresh and still consistent with the logs'
 * current state, and looks for a revocation or a newer passport. It FAILS CLOSED: `trusted` is returned only when every check
 * that was run passed and the quorum is met. The decision is tri-state:
 *
 *   trusted    every check passed in at least `minLogs` independent logs
 *   untrusted  there is positive evidence against the agent or the presenter (forged proof, revoked, split view, rollback)
 *   unknown    nothing is wrong that we can prove, but we cannot prove it is right (no proof, quorum short, stale head, log down)
 *
 * Callers deny on both `untrusted` and `unknown`; the difference is for logging, retry and for telling a mistake from an attack.
 * Offline verification uses a stapled bundle alone (no `client` on the logs); online checks add revocation and rollback detection.
 */
import { verifyInclusion } from '@atlasauth/pca';
import {
  verifyTreeHead,
  type SignedTreeHead,
  type WitnessPolicy,
} from '@atlasauth/pca/ext/ledger';
import { headExtends, resolveLogKey, retiredAtSize, type SignedKeyTransition } from './rotation';
import {
  trustScore,
  verifyPassport,
  type HardwareAttestationVerifier,
  type SignedPassport,
} from '@atlasauth/pca/ext/attestation';
import type { PqPinPolicy } from '@atlasauth/pca';
import {
  DIRECTORY_EXTENSION_URI,
  MAX_BUNDLE_BYTES,
  decodeBundle,
  parseBundle,
  type FreshnessToken,
  type LogProof,
  type StapledBundle,
} from './bundle';
import type { EntryView, LogClient, StatusView } from './client';
import { entryCommit, entryMatchesPassport, passportDigest, type EntryMode } from './entry';

export type Decision = 'trusted' | 'untrusted' | 'unknown';

export interface TrustedLog {
  /** The log's id as written into its leaves and the bundle's `log` field. */
  id: string;
  /** The log's pinned signing key (b64u Ed25519). */
  guardian: string;
  /** Key transitions you already hold for this log (the log's own, stapled and live ones are added). A head signed by a rotated key is accepted only through a witnessed chain from `guardian`. */
  transitions?: readonly SignedKeyTransition[];
  /** The STH scope the log signs under, when known (rejects a head minted for another log). */
  instanceId?: string;
  principal?: string;
  /** Present: the log is also queried live (fresh head, consistency from the stapled head, revocation lookup). */
  client?: LogClient;
}

export interface CheckPolicy {
  /** Passport issuer keys you trust. Empty trusts nobody. */
  trustedIssuers: readonly string[];
  /** Independent logs that must prove the passport (default 2). */
  minLogs?: number;
  /** Epoch ms (default now). */
  now?: number;
  /**
   * Oldest acceptable stapled head, by the log's signed timestamp (default `DEFAULT_MAX_STH_AGE_MS`, 1 hour). This is how long a
   * revocation can go unseen when you check offline: shorten it for riskier actions, or require a freshness token.
   */
  maxSthAgeMs?: number;
  /**
   * Freshness tokens (see `refreshBundle`): `maxAgeMs` is how recent a token's head must be (default `maxSthAgeMs`), e.g. 10 minutes. With
   * `require`, a log counts only when it has a valid, witnessed, recent token (or a live answer): the agent refreshes cheaply, you stay offline.
   */
  freshness?: { maxAgeMs: number; require?: boolean };
  /** Tolerance on head timestamps, ms (default 60 s, capped at 5 min). */
  clockSkewMs?: number;
  /** Entry modes you accept (default both). */
  modes?: readonly EntryMode[];
  /** `require`: a log counts only if it answered live; `prefer` (default): live when a client is given, the stapled proof when it is down; `off`: stapled proofs only. */
  online?: 'require' | 'prefer' | 'off';
  /** Treat a newer passport for the same subject and issuer as superseding this one (default true). */
  rejectSuperseded?: boolean;
  /** Permit `witnesses.threshold` of 0 (no witness demanded). Off by default: an unwitnessed head proves nothing about split views. */
  allowUnwitnessed?: boolean;
  attestationVerifier?: HardwareAttestationVerifier;
  /** Extra revocation source (your own deny list); a throw denies. */
  revocation?: (p: { id: string; iss: string; sub: string; digest: string }) => boolean | Promise<boolean>;
  /** Verifies an A2A agent card presented in place of a bare passport (its JWS, its pinned key). A false or a throw is `untrusted`. */
  cardVerifier?: (card: unknown) => boolean | Promise<boolean>;
  /** Operators you already know, for the `score` (a hint for ranking, never an input to `decision`). */
  knownOperators?: string[];
  pins?: PqPinPolicy;
}

export interface CheckOptions {
  logs: readonly TrustedLog[];
  /** Trusted witness keys and how many distinct ones must have cosigned each head. */
  witnesses: { keys: readonly string[]; threshold: number };
  policy: CheckPolicy;
  /** A bundle to use when the first argument is a bare passport. */
  bundle?: StapledBundle | string;
}

export type LogState =
  | 'proved'
  | 'no_proof'
  | 'invalid'
  | 'stale'
  | 'witness_shortfall'
  | 'unreachable'
  | 'revoked'
  | 'superseded'
  | 'equivocation'
  | 'rollback'
  | 'inconsistent';

export interface LogCheck {
  log: string;
  state: LogState;
  detail?: string;
}

export interface CheckResult {
  decision: Decision;
  /** Why, as stable codes (each prefixed by the log id when it is about one log). */
  reasons: string[];
  logs: LogCheck[];
  passport?: { id: string; operator: string; model_id: string; subject: string; issuer: string; hardware_verified: boolean; expires_at: number };
  /** `trustScore` of the passport: a ranking hint only. */
  score?: number;
}

/** Default age limit on a stapled head: how long an offline check can miss a revocation. */
export const DEFAULT_MAX_STH_AGE_MS = 3_600_000;
const WORST: LogState[] = ['revoked', 'superseded', 'equivocation', 'rollback', 'inconsistent', 'invalid'];

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);

function normalize(input: unknown, o: CheckOptions): { passport?: SignedPassport; bundle?: StapledBundle; error?: string } {
  try {
    if (typeof input === 'string') {
      const b = decodeBundle(input);
      return { passport: b.passport, bundle: b };
    }
    if (!isObj(input)) return { error: 'no_passport' };
    if (JSON.stringify(input).length > MAX_BUNDLE_BYTES) return { error: 'too_large' };
    const extra = o.bundle === undefined ? undefined : typeof o.bundle === 'string' ? decodeBundle(o.bundle) : parseBundle(o.bundle);
    if (input.typ === 'atlas-pca/directory-bundle') {
      const b = parseBundle(input);
      return { passport: b.passport, bundle: b };
    }
    if (input.typ === 'atlas-pca/passport') return { passport: input as unknown as SignedPassport, ...(extra ? { bundle: extra } : {}) };
    const exts = (input.capabilities as { extensions?: unknown } | undefined)?.extensions;
    if (Array.isArray(exts)) {
      const e = exts.find((x) => isObj(x) && x.uri === DIRECTORY_EXTENSION_URI) as { params?: { bundle?: unknown } } | undefined;
      if (e?.params?.bundle !== undefined) {
        const b = parseBundle(e.params.bundle);
        return { passport: b.passport, bundle: b };
      }
    }
    return { error: 'no_passport' };
  } catch (e) {
    return { error: `malformed:${e instanceof Error ? e.message : 'error'}` };
  }
}

interface Ctx {
  passport: SignedPassport;
  digest: string;
  now: number;
  skew: number;
  maxAge: number;
  /** How recent a freshness token's head must be. */
  freshAge: number;
  requireFresh: boolean;
  modes: readonly EntryMode[];
  online: 'require' | 'prefer' | 'off';
  rejectSuperseded: boolean;
  wp: WitnessPolicy;
  /** Transitions need a witness quorum of at least one, even when heads may be unwitnessed. */
  wpTransition: WitnessPolicy;
  bundleFresh: readonly FreshnessToken[];
  pins: PqPinPolicy | undefined;
}

const scopeOk = (l: TrustedLog, s: SignedTreeHead) => (l.instanceId === undefined || s.instance_id === l.instanceId) && (l.principal === undefined || s.principal === l.principal);

const sameTransition = (a: SignedKeyTransition, b: SignedKeyTransition) => a.seq === b.seq && a.from === b.from && a.to === b.to;
const mergeTransitions = (...lists: Array<readonly SignedKeyTransition[] | undefined>): SignedKeyTransition[] => {
  const out: SignedKeyTransition[] = [];
  for (const t of lists.flat()) if (t && !out.some((x) => sameTransition(x, t))) out.push(t);
  return out;
};

/**
 * Signature, scope and witnesses of one head. The signing key is the pinned key or the end of a witnessed chain of transitions from
 * it; a head from a key a transition retired, larger than the size it handed over, is refused. 'bad' = forged, mis-scoped, signed by
 * an unrelated key or by a retired one; 'witnesses' = valid but under-cosigned.
 */
function headState(l: TrustedLog, s: SignedTreeHead, c: Ctx, tr: readonly SignedKeyTransition[], maxAge: number = c.maxAge): 'ok' | 'bad' | 'witnesses' | 'stale' | 'future' {
  if (typeof s?.guardian !== 'string' || !scopeOk(l, s)) return 'bad';
  const k = resolveLogKey(l.guardian, s.guardian, tr, c.wpTransition, { instanceId: s.instance_id, principal: s.principal });
  if (!k.ok) return 'bad';
  const retired = retiredAtSize(s.guardian, tr, c.wpTransition, { instanceId: s.instance_id, principal: s.principal });
  if (retired !== undefined && s.size > retired) return 'bad';
  if (!verifyTreeHead(s, k.key, undefined, c.pins)) return 'bad';
  if (!verifyTreeHead(s, k.key, c.wp, c.pins)) return 'witnesses';
  if (s.timestamp - c.now > c.skew) return 'future';
  if (c.now - s.timestamp > maxAge) return 'stale';
  return 'ok';
}

/** Is the proved entry really this passport's, in this log, under a head we trust? */
function proofState(l: TrustedLog, ev: LogProof, c: Ctx): LogCheck | null {
  const bad = (detail: string): LogCheck => ({ log: l.id, state: 'invalid', detail });
  const e = ev.entry;
  if (e.log !== l.id) return bad('entry_for_another_log');
  if (!c.modes.includes(e.mode)) return bad('mode_not_accepted');
  if (!entryMatchesPassport(e, c.passport)) return bad('entry_does_not_match_passport');
  if (ev.proof?.index !== ev.index || ev.proof?.size !== ev.sth.size) return bad('proof_shape');
  if (!verifyInclusion(ev.sth.root, ev.proof, entryCommit(e))) return bad('forged_inclusion_proof');
  return null;
}

function viewProved(v: { entry: EntryView; proof: LogProof['proof'] }, sth: SignedTreeHead): EntryView | null {
  return v.proof?.size === sth.size && verifyInclusion(sth.root, v.proof, entryCommit(v.entry.entry)) && v.proof.index === v.entry.index ? v.entry : null;
}

type StatusVerdict = { state: 'revoked' | 'superseded' } | { state: 'listed' } | { state: 'absent' };

/** What a status view proves about this passport. Entries the log cannot prove against the view's head are ignored (they could only be made up). */
function readStatus(st: StatusView, ev: LogProof, c: Ctx): StatusVerdict {
  let listed = false;
  for (const item of st.entries ?? []) {
    const e = viewProved(item, st.sth);
    if (!e) continue;
    const x = e.entry;
    if (x.subject !== ev.entry.subject) continue;
    if (x.kind === 'revoke' && x.revokes === c.digest) return { state: 'revoked' };
    if (c.rejectSuperseded && x.kind === 'update' && x.issuer === ev.entry.issuer && e.index > ev.index && x.digest !== c.digest) return { state: 'superseded' };
    if (x.kind !== 'revoke' && x.digest === c.digest) listed = true;
  }
  return listed ? { state: 'listed' } : { state: 'absent' };
}

async function checkLog(l: TrustedLog, stapled: LogProof | undefined, c: Ctx): Promise<LogCheck> {
  const client = c.online === 'off' ? undefined : l.client;
  const token = c.bundleFresh.find((f) => f.log === l.id);
  let tr = mergeTransitions(l.transitions, stapled?.transitions, token?.transitions);
  let ev = stapled;
  let liveDown = false;
  let fresh: SignedTreeHead | undefined;
  if (client) {
    try {
      tr = mergeTransitions(tr, await client.transitions?.().catch(() => []));
      fresh = await client.sth();
      if (headState(l, fresh, c, tr) === 'bad') return { log: l.id, state: 'invalid', detail: 'live_head_not_signed_by_pinned_key' };
      if (!ev) {
        const p = await client.inclusion(c.digest);
        if (p) ev = { log: l.id, index: p.entry.index, entry: p.entry.entry, proof: p.proof, sth: p.sth };
      }
    } catch {
      liveDown = true;
    }
  }
  if (!ev) return liveDown ? { log: l.id, state: 'unreachable' } : { log: l.id, state: 'no_proof' };

  // The proof is checked against the head it came with.
  const hs = headState(l, ev.sth, c, tr);
  if (hs === 'bad') return { log: l.id, state: 'invalid', detail: 'head_not_signed_by_pinned_key' };
  const ps = proofState(l, ev, c);
  if (ps) return ps;

  // A freshness token: a recent head and the subject's entries proved against it. It can convict (revoked, superseded) and, when its
  // head is witnessed and recent, it stands in for a live check.
  let tokenOk = false;
  if (token) {
    const th = headState(l, token.status?.sth, c, tr, c.freshAge);
    if (th === 'bad') return { log: l.id, state: 'invalid', detail: 'freshness_head_not_signed_by_pinned_key' };
    const r = readStatus(token.status, ev, c);
    if (r.state === 'revoked' || r.state === 'superseded') return { log: l.id, state: r.state };
    tokenOk = th === 'ok' && r.state === 'listed';
  }

  if (client && fresh && !liveDown) {
    // Is the stapled head still part of the log's history? Rollback, split view and rewrites show up here.
    const pin = ev.sth;
    if (fresh.size < pin.size) return { log: l.id, state: 'rollback', detail: `live ${fresh.size} < stapled ${pin.size}` };
    if (fresh.size === pin.size && fresh.root !== pin.root) return { log: l.id, state: 'equivocation', detail: `two signed heads at size ${pin.size}` };
    if (fresh.size > pin.size) {
      try {
        const proof = await client.consistency(pin.size, fresh.size);
        if (!headExtends(pin, fresh, proof, c.pins)) return { log: l.id, state: 'inconsistent', detail: 'live head does not extend the stapled head' };
      } catch {
        liveDown = true;
      }
    }
    if (!liveDown) {
      try {
        const st = await client.status(ev.entry.subject);
        if (headState(l, st.sth, c, tr) === 'bad') return { log: l.id, state: 'invalid', detail: 'status_head_not_signed_by_pinned_key' };
        const r = readStatus(st, ev, c);
        if (r.state === 'revoked' || r.state === 'superseded') return { log: l.id, state: r.state };
      } catch {
        // a status endpoint that is down does not convict anyone; `online: require` is handled below
      }
    }
  }
  if (client && c.online === 'require' && (liveDown || !fresh)) return { log: l.id, state: 'unreachable', detail: 'live check required' };

  // Head quality last: a stale or under-cosigned head is "cannot prove", never a verdict on the agent. A live head that is witnessed,
  // fresh and consistent with the stapled one, or a witnessed recent freshness token, vouches for it whatever the stapled head's own
  // age or cosignatures say.
  const liveOk = client !== undefined && fresh !== undefined && !liveDown && headState(l, fresh, c, tr) === 'ok';
  if (hs === 'future') return { log: l.id, state: 'invalid', detail: 'head_from_the_future' };
  if (c.requireFresh && !liveOk && !tokenOk) return { log: l.id, state: 'stale', detail: 'no_fresh_token' };
  if (!liveOk && !tokenOk) {
    if (hs === 'witnesses') return { log: l.id, state: 'witness_shortfall' };
    if (hs === 'stale') return { log: l.id, state: 'stale', detail: `head is ${Math.round((c.now - ev.sth.timestamp) / 1000)}s old` };
  }
  return { log: l.id, state: 'proved' };
}

/** Decide whether to trust an agent. Never throws. */
export async function checkAgent(input: unknown, o: CheckOptions): Promise<CheckResult> {
  const done = (decision: Decision, reasons: string[], logs: LogCheck[] = [], extra: Partial<CheckResult> = {}): CheckResult => ({ decision, reasons, logs, ...extra });
  try {
    const p = o.policy;
    const minLogs = p.minLogs ?? 2;
    const threshold = o.witnesses?.threshold as number;
    if (!Number.isInteger(minLogs) || minLogs < 1) return done('unknown', ['bad_policy:min_logs']);
    if (!Number.isInteger(threshold) || threshold < 0 || (threshold === 0 && !p.allowUnwitnessed) || (threshold > 0 && (o.witnesses.keys?.length ?? 0) < threshold)) return done('unknown', ['bad_policy:witnesses']);
    if (!Array.isArray(o.logs) || o.logs.length < minLogs) return done('unknown', ['bad_policy:too_few_logs_configured']);

    const n = normalize(input, o);
    if (!n.passport) return done(n.error?.startsWith('malformed') ? 'untrusted' : 'unknown', [n.error ?? 'no_passport']);
    if (isObj(input) && input.typ !== 'atlas-pca/passport' && input.typ !== 'atlas-pca/directory-bundle' && p.cardVerifier) {
      let ok = false;
      try {
        ok = (await p.cardVerifier(input)) === true;
      } catch {
        ok = false;
      }
      if (!ok) return done('untrusted', ['card_verification_failed']);
    }

    const now = p.now ?? Date.now();
    const digest = passportDigest(n.passport);
    const pv = await verifyPassport(n.passport, {
      trustedIssuers: p.trustedIssuers,
      now,
      clockSkewMs: p.clockSkewMs ?? 60_000,
      revocation: async (x) => (p.revocation ? p.revocation({ ...x, digest }) : false),
      ...(p.attestationVerifier ? { attestationVerifier: p.attestationVerifier } : {}),
      ...(p.pins ?? {}),
    });
    if (!pv.ok) return done(pv.reason === 'revocation_unavailable' ? 'unknown' : 'untrusted', [`passport:${pv.reason}`]);
    const passport = { id: pv.passport.id, operator: pv.passport.operator, model_id: pv.passport.model_id, subject: pv.sub, issuer: pv.iss, hardware_verified: pv.hardware_verified, expires_at: pv.exp };
    const score = trustScore(pv.passport, { knownOperators: p.knownOperators ?? [] });

    const c: Ctx = {
      passport: n.passport,
      digest,
      now,
      skew: Math.min(Math.max(p.clockSkewMs ?? 60_000, 0), 300_000),
      maxAge: p.maxSthAgeMs ?? DEFAULT_MAX_STH_AGE_MS,
      freshAge: p.freshness?.maxAgeMs ?? p.maxSthAgeMs ?? DEFAULT_MAX_STH_AGE_MS,
      requireFresh: p.freshness?.require === true,
      modes: p.modes ?? ['public', 'hashed'],
      online: p.online ?? 'prefer',
      rejectSuperseded: p.rejectSuperseded ?? true,
      wp: { witnessKeys: [...o.witnesses.keys], threshold: threshold, ...(p.pins ?? {}) },
      wpTransition: { witnessKeys: [...o.witnesses.keys], threshold: Math.max(1, threshold), ...(p.pins ?? {}) },
      bundleFresh: n.bundle?.freshness ?? [],
      pins: p.pins,
    };

    // independent = distinct pinned keys; a log listed twice counts once
    const seen = new Set<string>();
    const logs = o.logs.filter((l) => (seen.has(l.guardian) ? false : (seen.add(l.guardian), true)));
    const checks = await Promise.all(
      logs.map((l) => checkLog(l, n.bundle?.proofs.find((x) => x.log === l.id), c).catch((): LogCheck => ({ log: l.id, state: 'unreachable', detail: 'error' }))),
    );

    const reasons = checks.filter((k) => k.state !== 'proved').map((k) => `${k.log}:${k.state}${k.detail ? `:${k.detail}` : ''}`);
    const proved = checks.filter((k) => k.state === 'proved').length;
    const hard = checks.some((k) => WORST.includes(k.state));
    if (hard) return done('untrusted', reasons, checks, { passport, score });
    if (proved >= minLogs) return done('trusted', reasons, checks, { passport, score });
    return done('unknown', [`quorum:${proved}/${minLogs}`, ...reasons], checks, { passport, score });
  } catch (e) {
    return done('unknown', [`error:${e instanceof Error ? e.message : 'error'}`]);
  }
}
