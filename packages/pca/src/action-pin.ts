import { b64u, canonicalBytesStrict, decodeB64uStrict, hashCanonical, utf8 } from './hash';
import { publicKeyOf } from './keys';
import { type SignerSuiteOpts, type SigAlg, resolveSigAlg, signSuiteArtifact, suiteKeysOf, suitePqPublicKey, verifyPinnedSuite } from './pq';
import { isPlainObject, ownGet, ownHas } from './intent-strict';
import { SCHEMA_V2_CAVEATS, type ActionSchemaKey } from './action-schema';

/**
 * ACTION PINS, EVOLUTION RECORDS AND RE-APPROVALS (action kit, docs/pca/specs/action-kit.md section 7.2).
 *
 * A grant envelope may carry `actions`: it authorizes the verbs it names AS DEFINED by the digests it pins. The verifier
 * compares the definition digest of the verb in the accepted signed schema (`verb.def`, schema v2) to the pin. A mismatch is
 * `def_changed`, unless the registry's signed {@link EvolutionRecord}s chain from the pinned digest to the presented one
 * through steps whose class is `equal` or `narrow` (the world only got stricter), or the grant's principal re-approved a
 * widening step (a signature over the record's diff digest, bound to the grant). `widen` and `incomparable` always need the
 * re-approval. Everything here is pure and total: malformed input is a refusal, never a throw.
 */

export const ACTION_PIN_ON_NEW = ['deny', 'escalate'] as const;
export const EVOLUTION_CLASSES = ['equal', 'narrow', 'widen', 'incomparable', 'added', 'removed'] as const;
export type EvolutionClass = (typeof EVOLUTION_CLASSES)[number];
export const EVOLUTION_RECORD_KIND = 'pca-evolution-record';
export const REAPPROVAL_KIND = 'pca-reapproval';
export const EVOLUTION_DOMAIN = 'atlas-pca/action-evolution/v1\0';
export const EVOLUTION_DIFF_DOMAIN = 'atlas-pca/action-evolution-diff/v1';
export const REAPPROVAL_DOMAIN = 'atlas-pca/action-reapproval/v1\0';
/** Longest chain of evolution steps the verifier follows from a pin. */
export const MAX_EVOLUTION_STEPS = 32;
/** Escalation tiers: 0 auto, 1 confirm, 2 cosign, 3 stepup. */
export const MAX_ESC_TIER = 3;

/** The grant's pin block (`envelope.actions`). */
export interface ActionPin {
  pack: { ns: string; root: string };
  /** verb -> pinned definition digest. Absent: the pack root alone is pinned. */
  defs?: Record<string, string>;
  /** What a verb the grant does not name does: a terminal deny or an escalation. */
  on_new_action: (typeof ACTION_PIN_ON_NEW)[number];
  /** Highest escalation tier the grant authorizes at all (default 3). A tier above it is a terminal deny (rule 22). */
  max_esc?: number;
  /** Highest tier the grant pre-authorizes without asking (default 0). A tier above it escalates (rule 22). */
  preauth_esc?: number;
  /**
   * Caveat KINDS the principal states this grant already imposes (amount_cap, count_cap, window, resource_scope, recipient_scope,
   * approval_ref, short_expiry, rate_cap), for rule 22: an action whose floors need a kind that is neither here nor in the envelope
   * caveats escalates. Envelope caveats whose `type` is one of these kinds count as well.
   */
  caveats?: string[];
}

export interface EvolutionSig {
  alg: SigAlg;
  kid: string;
  value: string;
  pq_value?: string;
}
export interface UnsignedEvolutionRecord {
  v: 1;
  kind: typeof EVOLUTION_RECORD_KIND;
  ns: string;
  verb: string;
  from: string | null;
  to: string | null;
  class: EvolutionClass;
  reasons: string[];
}
export interface EvolutionRecord extends UnsignedEvolutionRecord {
  sig: EvolutionSig;
}
/** The principal's signed approval of ONE evolution step for ONE grant. */
export interface Reapproval {
  v: 1;
  kind: typeof REAPPROVAL_KIND;
  /** `grant.id` (content address of the root capability carrying the envelope). */
  grant: string;
  verb: string;
  /** {@link evolutionDiffDigest} of the approved record. */
  diff: string;
  sig: { alg: 'ed25519'; value: string };
}

/** The keys the verifier pins for human review confirmations (mirrors `ReviewerPins` of pca-actions). */
export interface ReviewerPinsCtx {
  keys: { kid: string; pk: string; roles: string[]; not_before?: number; not_after?: number }[];
  /** Trait registry digests besides the document's own that a confirmation may name. */
  traits_digests?: string[];
}

/** What the verifier's rule 22 needs from the trait algebra (implemented by `@atlasauth/pca-actions`, injected into the context). */
export interface Rule22Engine {
  /**
   * Integrity half: null iff the v2 document's traits and materialized floors are consistent with its trait registry. A verb
   * without a valid signed confirmation (one by a key in `reviewers` with the reviewer role) must carry EVERY trait of the
   * registry: "unconfirmed means maximally dangerous". No `reviewers` means no verb is confirmed.
   */
  schemaError(doc: unknown, reviewers?: ReviewerPinsCtx): string | null;
  /** FloorDecision of the verb's materialized floors against the grant facts and the call context. */
  decide(i: { doc: unknown; verb: string; grant: { caveats: readonly string[]; max_esc: number; preauth_esc: number }; context: readonly string[] }): 'deny' | 'escalate' | 'allow';
}

const B64U_43 = /^[A-Za-z0-9_-]{43}$/;
const NS_RE = /^[a-z0-9_]+(?:\.[a-z0-9_]+){0,5}$/;
const VERB_RE = /^[a-z0-9_]+(?:\.[a-z0-9_]+){1,5}$/;
const tier = (x: unknown): x is number => typeof x === 'number' && Number.isInteger(x) && x >= 0 && x <= MAX_ESC_TIER;
const closed = (o: Record<string, unknown>, allowed: readonly string[]): string | null => {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) return `unknown member '${k}'`;
  return null;
};

/** Shape check of `envelope.actions`; null = well formed. */
export function actionPinError(x: unknown): string | null {
  if (!isPlainObject(x)) return 'actions must be an object';
  const u = closed(x, ['pack', 'defs', 'on_new_action', 'max_esc', 'preauth_esc', 'caveats']);
  if (u) return `actions: ${u}`;
  const p = x.pack;
  if (!isPlainObject(p) || closed(p, ['ns', 'root']) !== null) return 'actions.pack must be {ns, root}';
  if (typeof p.ns !== 'string' || !NS_RE.test(p.ns)) return 'actions.pack.ns is not a namespace';
  if (typeof p.root !== 'string' || !B64U_43.test(p.root)) return 'actions.pack.root must be a base64url digest';
  if (!(ACTION_PIN_ON_NEW as readonly unknown[]).includes(x.on_new_action)) return "actions.on_new_action must be 'deny' or 'escalate'";
  if (x.max_esc !== undefined && !tier(x.max_esc)) return 'actions.max_esc must be an integer tier 0..3';
  if (x.preauth_esc !== undefined && !tier(x.preauth_esc)) return 'actions.preauth_esc must be an integer tier 0..3';
  if (tier(x.max_esc) && tier(x.preauth_esc) && x.preauth_esc > x.max_esc) return 'actions.preauth_esc exceeds actions.max_esc';
  if (x.caveats !== undefined) {
    const c = x.caveats;
    if (!Array.isArray(c) || c.some((k) => typeof k !== 'string' || !SCHEMA_V2_CAVEATS.includes(k)) || new Set(c).size !== c.length) return 'actions.caveats must be distinct caveat kinds';
  }
  if (x.defs !== undefined) {
    if (!isPlainObject(x.defs)) return 'actions.defs must be an object';
    for (const [verb, d] of Object.entries(x.defs)) {
      if (!VERB_RE.test(verb)) return `actions.defs: '${verb}' is not a verb`;
      if (typeof d !== 'string' || !B64U_43.test(d)) return `actions.defs.${verb} must be a base64url digest`;
    }
  }
  return null;
}

// ---- signing helpers (domain-separated, suite pinned by the key entry, exactly like signed action schemas) ------------------------

function message(domain: string, body: unknown): Uint8Array {
  const dom = utf8(domain);
  const b = canonicalBytesStrict(body);
  const out = new Uint8Array(dom.length + b.length);
  out.set(dom);
  out.set(b, dom.length);
  return out;
}

/** The content a principal's re-approval signs: the diff of ONE record, `{ns, verb, from, to, class, reasons}`. */
export const evolutionDiffDigest = (r: UnsignedEvolutionRecord | EvolutionRecord): string =>
  hashCanonical({ d: EVOLUTION_DIFF_DOMAIN, ns: r.ns, verb: r.verb, from: r.from, to: r.to, class: r.class, reasons: r.reasons });

const sha = (x: unknown): x is string => typeof x === 'string' && B64U_43.test(x);

/** Shape of an unsigned evolution record; null = well formed. */
export function evolutionRecordError(x: unknown, opts: { signed?: boolean } = {}): string | null {
  if (!isPlainObject(x)) return 'evolution record must be an object';
  const signed = opts.signed !== false;
  const u = closed(x, signed ? ['v', 'kind', 'ns', 'verb', 'from', 'to', 'class', 'reasons', 'sig'] : ['v', 'kind', 'ns', 'verb', 'from', 'to', 'class', 'reasons']);
  if (u) return `evolution record: ${u}`;
  if (x.v !== 1 || x.kind !== EVOLUTION_RECORD_KIND) return 'evolution record: bad v/kind';
  if (typeof x.ns !== 'string' || !NS_RE.test(x.ns)) return 'evolution record: bad ns';
  if (typeof x.verb !== 'string' || !VERB_RE.test(x.verb)) return 'evolution record: bad verb';
  if (x.from !== null && !sha(x.from)) return 'evolution record: bad from';
  if (x.to !== null && !sha(x.to)) return 'evolution record: bad to';
  if (!(EVOLUTION_CLASSES as readonly unknown[]).includes(x.class)) return 'evolution record: bad class';
  const c = x.class as EvolutionClass;
  // the shape of the endpoints is fixed by the class: added has no `from`, removed no `to`, the rest have both
  if ((c === 'added') !== (x.from === null) || (c === 'removed') !== (x.to === null)) return 'evolution record: endpoints do not match the class';
  if (!Array.isArray(x.reasons) || x.reasons.length > 64 || x.reasons.some((r) => typeof r !== 'string' || r.length > 512)) return 'evolution record: bad reasons';
  if (signed) {
    const s = x.sig;
    if (!isPlainObject(s) || closed(s, ['alg', 'kid', 'value', 'pq_value']) !== null) return 'evolution record: bad sig';
    if (typeof s.kid !== 'string' || s.kid.length === 0 || s.kid.length > 128 || typeof s.value !== 'string' || typeof s.alg !== 'string') return 'evolution record: bad sig';
    if (s.pq_value !== undefined && typeof s.pq_value !== 'string') return 'evolution record: bad sig';
  }
  try {
    const { sig: _s, ...body } = x as Record<string, unknown>;
    void _s;
    canonicalBytesStrict(body);
  } catch (e) {
    return `evolution record: ${(e as Error).message}`;
  }
  return null;
}

/** Sign `body` under `domain` as a registry key (`kid` names the pinned key entry; the suite comes from `suite`, pinned by that entry). */
export function signRegistryDoc(domain: string, body: unknown, kid: string, registrySecret: Uint8Array, suite?: SignerSuiteOpts): EvolutionSig {
  const parts = signSuiteArtifact(suite?.alg, suiteKeysOf(registrySecret, suite), message(domain, body));
  const alg = resolveSigAlg(suite?.alg ?? 'ed25519')!.alg as SigAlg;
  return { alg, kid, value: parts.sig, ...(parts.pq_sig !== undefined ? { pq_value: parts.pq_sig } : {}) };
}

/** Sign an evolution record as the registry (`kid` names the pinned registry key entry). */
export function signEvolutionRecord(rec: UnsignedEvolutionRecord, kid: string, registrySecret: Uint8Array, suite?: SignerSuiteOpts): EvolutionRecord {
  const bad = evolutionRecordError(rec, { signed: false });
  if (bad) throw new Error(`signEvolutionRecord: ${bad}`);
  return { ...rec, sig: signRegistryDoc(EVOLUTION_DOMAIN, rec, kid, registrySecret, suite) };
}

/** The registry key entry for a signer (helper for registries and tests). */
export function registryKeyOf(kid: string, registrySecret: Uint8Array, suite?: SignerSuiteOpts): ActionSchemaKey {
  const alg = resolveSigAlg(suite?.alg ?? 'ed25519')!.alg as SigAlg;
  const pq = suitePqPublicKey(alg, suite);
  return { kid, alg, pk: b64u(publicKeyOf(registrySecret)), ...(pq !== undefined ? { pq_pk: pq } : {}) };
}

/** Verify a registry-signed document body under `domain` against the pinned registry keys (suite from the KEY entry). Never throws. */
export function verifyRegistrySig(domain: string, body: unknown, sig: { alg: unknown; kid: unknown; value: unknown; pq_value?: unknown }, keys: readonly ActionSchemaKey[]): { ok: true } | { ok: false; reason: string } {
  try {
    if (!Array.isArray(keys)) return { ok: false, reason: 'the registry keys must be an array' };
    const key = keys.find((k) => isPlainObject(k) && k.kid === sig.kid);
    if (!key) return { ok: false, reason: `no registry key with kid '${String(sig.kid)}'` };
    if (key.pq_pk !== undefined && typeof key.pq_pk !== 'string') return { ok: false, reason: 'the registry key pq_pk must be a string' };
    if (decodeB64uStrict(key.pk, 32) === null) return { ok: false, reason: 'registry key pk is not canonical base64url (32 bytes)' };
    const ka = resolveSigAlg(key.alg);
    if (ka === null || ka.alg !== resolveSigAlg(sig.alg)?.alg) return { ok: false, reason: 'sig.alg does not match the pinned key suite' };
    const pin = key.pq_pk !== undefined ? { pqPins: { [key.pk]: key.pq_pk } } : {};
    if (!verifyPinnedSuite(ka.alg, key.pk, key.pq_pk, message(domain, body), { sig: sig.value, pq_sig: sig.pq_value }, pin)) return { ok: false, reason: 'signature invalid' };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `verification error: ${(e as Error).message}` };
  }
}

/** Shape and signature of an evolution record against the pinned registry keys. */
export function verifyEvolutionRecord(rec: unknown, keys: readonly ActionSchemaKey[]): { ok: true } | { ok: false; reason: string } {
  const bad = evolutionRecordError(rec);
  if (bad) return { ok: false, reason: bad };
  const { sig, ...body } = rec as EvolutionRecord;
  return verifyRegistrySig(EVOLUTION_DOMAIN, body, sig, keys);
}

// ---- principal re-approval --------------------------------------------------------------------------------------------------------

/** The principal approves one evolution step for one grant. `grantId` is `grant.id`; `principalSecret` the key that minted it. */
export function signReapproval(args: { grantId: string; record: UnsignedEvolutionRecord | EvolutionRecord; principalSecret: Uint8Array }): Reapproval {
  const body = { v: 1 as const, kind: REAPPROVAL_KIND as typeof REAPPROVAL_KIND, grant: args.grantId, verb: args.record.verb, diff: evolutionDiffDigest(args.record) };
  const parts = signSuiteArtifact(undefined, suiteKeysOf(args.principalSecret, undefined), message(REAPPROVAL_DOMAIN, body));
  return { ...body, sig: { alg: 'ed25519', value: parts.sig } };
}

/** Is `r` the principal's (`issuer`, b64u Ed25519 key) valid approval of the step with diff digest `diff` for `grantId`? */
export function reapprovalValid(r: unknown, grantId: string, issuer: string, verb: string, diff: string): boolean {
  try {
    if (!isPlainObject(r) || closed(r, ['v', 'kind', 'grant', 'verb', 'diff', 'sig']) !== null) return false;
    if (r.v !== 1 || r.kind !== REAPPROVAL_KIND || r.grant !== grantId || r.verb !== verb || r.diff !== diff) return false;
    const s = r.sig;
    if (!isPlainObject(s) || closed(s, ['alg', 'value']) !== null || s.alg !== 'ed25519' || typeof s.value !== 'string') return false;
    const { sig: _s, ...body } = r;
    void _s;
    return verifyPinnedSuite('ed25519', issuer, undefined, message(REAPPROVAL_DOMAIN, body), { sig: s.value }, {});
  } catch {
    return false;
  }
}

// ---- the pin decision ---------------------------------------------------------------------------------------------------------------

export type PinCode = 'def_changed' | 'pack_mismatch' | 'new_action' | 'bad_pin' | 'unknown_verb';
export type PinDecision = { ok: true; via: 'exact' | 'pack' | 'chain' } | { ok: false; code: PinCode; escalate: boolean; reason: string; needs_reapproval?: string };

export interface PinInput {
  pin: unknown;
  /** The accepted, already verified schema document (only `pack` and `verbs[].def` are read). */
  doc: { pack?: { ns?: unknown; root?: unknown }; verbs?: ReadonlyArray<{ verb?: unknown; def?: unknown }> };
  verb: string;
  /** Candidate evolution records (from the registry / transparency log; untrusted until verified here). */
  records?: readonly unknown[];
  /** The pinned registry keys. */
  keys?: readonly ActionSchemaKey[];
  reapprovals?: readonly unknown[];
  grant: { id: string; issuer: string };
}

const deny = (code: PinCode, reason: string, extra: { escalate?: boolean; needs_reapproval?: string } = {}): PinDecision => ({
  ok: false,
  code,
  escalate: extra.escalate === true,
  reason,
  ...(extra.needs_reapproval !== undefined ? { needs_reapproval: extra.needs_reapproval } : {}),
});

/**
 * Decide the pin for one verb (section 7.2). Fails closed on anything malformed. A step of the chain is usable iff its record
 * verifies under a pinned registry key, names the pinned namespace and verb, and is `equal`/`narrow` or carries the principal's
 * re-approval. The chain is searched breadth first over verified steps (bounded by {@link MAX_EVOLUTION_STEPS}); a record that
 * merely exists does not move the pin.
 */
export function decidePin(i: PinInput): PinDecision {
  try {
    const pe = actionPinError(i.pin);
    if (pe) return deny('bad_pin', pe);
    const pin = i.pin as ActionPin;
    const doc = i.doc;
    const v = Array.isArray(doc?.verbs) ? doc.verbs.find((x) => x?.verb === i.verb) : undefined;
    if (!v) return deny('unknown_verb', `the accepted schema does not declare '${i.verb}'`);
    const pk = doc.pack;
    if (!isPlainObject(pk) || pk.ns !== pin.pack.ns) return deny('pack_mismatch', `the schema does not come from the pinned pack '${pin.pack.ns}'`);
    if (pin.defs === undefined) {
      return pk.root === pin.pack.root ? { ok: true, via: 'pack' } : deny('pack_mismatch', 'the pack root differs from the pinned root (the grant pins the pack as a whole)');
    }
    if (!ownHas(pin.defs, i.verb)) {
      return deny('new_action', `the grant does not name '${i.verb}' (on_new_action: ${pin.on_new_action})`, { escalate: pin.on_new_action === 'escalate' });
    }
    const pinned = ownGet(pin.defs, i.verb) as string;
    const presented = v.def;
    if (typeof presented !== 'string') return deny('def_changed', 'the schema verb carries no definition digest');
    if (presented === pinned) return { ok: true, via: 'exact' };
    // chain search over verified, permitted steps
    const edges = new Map<string, Array<{ to: string; blocked: string | null }>>();
    const keys = i.keys ?? [];
    for (const r of i.records ?? []) {
      if (!verifyEvolutionRecord(r, keys).ok) continue;
      const rec = r as EvolutionRecord;
      if (rec.ns !== pin.pack.ns || rec.verb !== i.verb || rec.from === null || rec.to === null) continue;
      const diff = evolutionDiffDigest(rec);
      const free = rec.class === 'equal' || rec.class === 'narrow';
      const approved = free || (i.reapprovals ?? []).some((a) => reapprovalValid(a, i.grant.id, i.grant.issuer, i.verb, diff));
      const list = edges.get(rec.from) ?? [];
      list.push({ to: rec.to, blocked: approved ? null : diff });
      edges.set(rec.from, list);
    }
    // BFS over verified steps: first only the usable ones; failing that over all of them, to tell the principal which step to approve
    const search = (usableOnly: boolean): Map<string, { from: string; blocked: string | null }> => {
      const parent = new Map<string, { from: string; blocked: string | null }>();
      const seen = new Set<string>([pinned]);
      let frontier = [pinned];
      for (let step = 0; step < MAX_EVOLUTION_STEPS && frontier.length > 0 && !parent.has(presented); step++) {
        const next: string[] = [];
        for (const f of frontier) {
          for (const e of edges.get(f) ?? []) {
            if (seen.has(e.to) || (usableOnly && e.blocked !== null)) continue;
            seen.add(e.to);
            parent.set(e.to, { from: f, blocked: e.blocked });
            next.push(e.to);
          }
        }
        frontier = next;
      }
      return parent;
    };
    if (search(true).has(presented)) return { ok: true, via: 'chain' };
    const all = search(false);
    if (all.has(presented)) {
      let firstBlocked: string | null = null;
      for (let cur = presented; cur !== pinned; ) {
        const p = all.get(cur)!;
        if (p.blocked !== null) firstBlocked = p.blocked;
        cur = p.from;
      }
      return deny('def_changed', 'the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve', { ...(firstBlocked !== null ? { needs_reapproval: firstBlocked } : {}) });
    }
    return deny('def_changed', 'the definition differs from the pinned digest and no signed evolution record chains to it');
  } catch (e) {
    return deny('bad_pin', `pin evaluation error (fail closed): ${(e as Error).message}`);
  }
}
