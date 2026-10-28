/**
 * Agent passport — portable attested identity (spec Part 2.5 "SPIFFE-for-agents").
 *
 * "Which agent" is more than a key: it is the model, its weights, its operator, its system prompt and
 * its tool manifest. A passport is the portable, content-addressed statement of that identity; a grant's
 * `AgentBinding` (envelope.ts) is the policy that says which passports it accepts. `matchesBinding`
 * decides, with the SAME allowlist semantics the attestation verifier uses — so you can check a
 * passport against a binding offline, before you ever mint or dispatch.
 *
 * HONEST: the unsigned `AgentPassport` is a CLAIM. Wrap it with `signPassport` and check it with `verifyPassport`
 * (issuer signature, validity window, subject key). `hardware_rooted` is accepted only when the passport carries
 * attestation evidence that a configured hardware verifier validates, bound to the subject key.
 * `matchesBinding` fails closed whenever a required-but-absent field or an unmet hardware demand would
 * otherwise pass silently.
 */

import type { AgentBinding } from './envelope';
import { hashCanonical } from './hash';

export interface AgentPassport {
  /** Content-addressed id = fingerprint of the identity fields. */
  id: string;
  model_id: string;
  /** Digest of the loaded model weights (fp16/quantized), if measured. */
  weights_digest?: string;
  /** Digest of the agent's system prompt / instructions. */
  system_prompt_digest?: string;
  /** Digest of the agent's available-tool manifest. */
  tool_manifest_digest?: string;
  /** Launch/runtime measurement — an opaque digest or an integer SVN as a string. */
  runtime_measurement?: string;
  operator: string;
  /** True iff the attestation this passport was issued from was validated by a HARDWARE verifier. */
  hardware_rooted: boolean;
  /** True iff `weights_digest` came from a hardware-MEASURED identity (not host/self-asserted). */
  weights_measured?: boolean;
  issued_at: number;
}

export type PassportIdentity = Omit<AgentPassport, 'id'>;

/** Content fingerprint over the identity fields (stable id; excludes `id` itself). */
export function passportFingerprint(p: PassportIdentity): string {
  return hashCanonical({
    d: 'atlas-pca/passport/v1',
    model_id: p.model_id,
    weights_digest: p.weights_digest ?? null,
    system_prompt_digest: p.system_prompt_digest ?? null,
    tool_manifest_digest: p.tool_manifest_digest ?? null,
    runtime_measurement: p.runtime_measurement ?? null,
    operator: p.operator,
    hardware_rooted: p.hardware_rooted,
  });
}

/** Issue a passport: fill `id` from the fingerprint of the identity. */
export function issuePassport(identity: PassportIdentity): AgentPassport {
  return { ...identity, id: passportFingerprint(identity) };
}

export interface BindingMatch {
  ok: boolean;
  reasons: string[];
}

/**
 * Does this passport satisfy a grant's AgentBinding? Mirrors attestation.matchAgentBinding:
 *  - each *_allowlist, when present, requires the matching digest to be present AND listed (fail-closed);
 *  - operator, when pinned, must equal;
 *  - require_hardware demands hardware_rooted;
 *  - require_measured_weights demands weights_measured (a self/host-asserted digest fails even if listed);
 *  - min_measurement: a string matches runtime_measurement for EQUALITY; `{ svn }` is a MONOTONE lower
 *    bound on the integer SVN parsed from runtime_measurement.
 */
export function matchesBinding(p: AgentPassport, b: AgentBinding): BindingMatch {
  const reasons: string[] = [];
  const need = (list: string[] | undefined, value: string | undefined, label: string) => {
    if (!list || list.length === 0) return;
    if (value === undefined) reasons.push(`${label} required by binding but absent from passport`);
    else if (!list.includes(value)) reasons.push(`${label} '${value}' not in allowlist`);
  };

  if (b.model_allowlist && b.model_allowlist.length > 0 && !b.model_allowlist.includes(p.model_id)) {
    reasons.push(`model_id '${p.model_id}' not in allowlist`);
  }
  need(b.weights_allowlist, p.weights_digest, 'weights_digest');
  need(b.system_prompt_allowlist, p.system_prompt_digest, 'system_prompt_digest');
  need(b.tool_manifest_allowlist, p.tool_manifest_digest, 'tool_manifest_digest');

  if (b.operator !== undefined && p.operator !== b.operator) reasons.push(`operator '${p.operator}' != required '${b.operator}'`);
  if (b.require_hardware && !p.hardware_rooted) reasons.push('binding requires a hardware-rooted attestation');
  if (b.require_measured_weights && !p.weights_measured) reasons.push('binding requires hardware-measured weights');

  if (b.min_measurement !== undefined) {
    if (typeof b.min_measurement === 'string') {
      if (p.runtime_measurement !== b.min_measurement) reasons.push('runtime_measurement does not equal the pinned measurement');
    } else {
      // Strict (0.4.2, same rule as matchAgentBinding): the bound is exactly {svn: n} with n a safe non-negative integer JSON number
      // (anything else fails closed), and the runtime SVN is the canonical decimal text of a safe integer ("0x10", "1e1", " 8 " are not).
      const mm = b.min_measurement as unknown;
      const bound = mm !== null && typeof mm === 'object' && !Array.isArray(mm) && Object.keys(mm).length === 1 ? (mm as { svn?: unknown }).svn : undefined;
      // Number.isSafeInteger is false for every non-number, so no separate typeof check
      if (!Number.isSafeInteger(bound) || (bound as number) < 0 || Object.is(bound, -0)) {
        reasons.push('min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)');
      } else {
        const rm = p.runtime_measurement as unknown;
        const svn = typeof rm === 'string' && /^(?:0|[1-9][0-9]*)$/.test(rm) ? Number(rm) : Number.NaN;
        if (!Number.isSafeInteger(svn) || svn < (bound as number)) reasons.push(`runtime SVN ${String(rm)} < required ${String(bound)}`);
      }
    }
  }

  return { ok: reasons.length === 0, reasons };
}

// ---- registry + reputation-free trust score -------------------------------------------------------

export interface PassportRegistry {
  get(id: string): AgentPassport | undefined;
  has(id: string): boolean;
  all(): AgentPassport[];
}

export function buildRegistry(passports: AgentPassport[]): PassportRegistry {
  const byId = new Map<string, AgentPassport>();
  for (const p of passports) byId.set(p.id, p);
  return { get: (id) => byId.get(id), has: (id) => byId.has(id), all: () => [...byId.values()] };
}

/**
 * A coarse identity-assurance score in [0,1] from the passport's own completeness (NOT behavioral
 * reputation — that is reputation.ts). Hardware root dominates; measured provenance + a known operator
 * add confidence.
 */
export function trustScore(p: AgentPassport, opts: { knownOperators?: string[] } = {}): number {
  let s = 0;
  if (p.hardware_rooted) s += 0.4;
  if (p.weights_digest) s += p.weights_measured ? 0.2 : 0.1;
  if (p.system_prompt_digest) s += 0.1;
  if (p.tool_manifest_digest) s += 0.1;
  if (opts.knownOperators?.includes(p.operator)) s += 0.2;
  return Math.max(0, Math.min(1, s));
}

// ---- signed passport: issuer signature, validity window, subject key binding, verifier -------------------------

import type { AttestationDocument, HardwareAttestationVerifier } from './attestation';
import type { ExpectedAttestationBinding } from './attestation';
import { assuranceLabelOf } from './assurance';
import { b64u, canonicalBytesStrict, utf8 } from './hash';
import { publicKeyOf } from './keys';
import type { VerifyContext } from './pcactn';
import { bindSuiteFields, isKnownSigAlg, resolveSigAlg, signSuiteArtifact, suiteKeysOf, suitePqPublicKey, verifyPinnedSuite, type PqPinPolicy, type SigAlg, type SignerSuiteOpts } from './pq';

/** Domain-separation tag prefixed to the canonical body before signing. */
export const PASSPORT_SIG_DOMAIN = 'atlas-pca/passport-sig/v1\0';
/** The only passport wire version this build understands. */
export const PASSPORT_VERSION = 1;
const MAX_SKEW_MS = 60_000;
/** Default ceiling on the age of a hardware quote a passport carries. */
export const DEFAULT_PASSPORT_EVIDENCE_AGE_MS = 24 * 3600_000;

/** Hardware evidence a passport carries when `hardware_rooted` is true. Verified by an existing `HardwareAttestationVerifier`. */
export interface PassportEvidence {
  /** The attestation document; its report_data/binding must equal `passportEvidenceBinding(passport.id, subject, document.nonce)`. */
  document: AttestationDocument;
  /** Epoch ms when the issuer obtained the quote (signed with the passport). `signPassport` defaults it to `iat`. */
  at?: number;
}

/**
 * A signed agent passport. `iss` is the issuer's Ed25519 public key (b64u), its key id. `sub` is the agent's Ed25519 key
 * (b64u), the leaf holder its PCActns are signed by. Everything except `sig`/`pq_sig` is signed (domain + canonical JSON),
 * including `alg`/`pq_pk` for a non-default suite.
 */
export interface SignedPassport {
  typ: 'atlas-pca/passport';
  ver: number;
  passport: AgentPassport;
  iss: string;
  sub: string;
  iat: number;
  nbf: number;
  exp: number;
  evidence?: PassportEvidence;
  alg?: SigAlg;
  pq_pk?: string;
  sig: string;
  pq_sig?: string;
}

/** The binding a hardware quote must carry for this passport: holder = subject key, grant = passport id, epoch 0, nonce = the evidence nonce. */
export function passportEvidenceBinding(passportId: string, subject: string, nonce: string): ExpectedAttestationBinding {
  return { holderPub: subject, grantRef: `passport:${passportId}`, epoch: 0, nonce };
}

const stripUndefined = <T extends object>(o: T): T => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as T;

function passportMessage(body: Omit<SignedPassport, 'sig' | 'pq_sig'>): Uint8Array {
  const p = utf8(PASSPORT_SIG_DOMAIN);
  const d = canonicalBytesStrict(body);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return m;
}

export interface SignPassportOptions {
  /** Issuer Ed25519 secret key. */
  issuerSecret: Uint8Array;
  /** The agent's Ed25519 public key (b64u) this passport is bound to. */
  subject: string;
  /** Validity, epoch ms. `iat` defaults to `passport.issued_at`, `nbf` to `iat`. */
  iat?: number;
  nbf?: number;
  exp: number;
  /** REQUIRED when `passport.hardware_rooted` is true. */
  evidence?: PassportEvidence;
  /** Signature suite (crypto agility, incl. ml-dsa and hybrids); default ed25519. */
  suite?: SignerSuiteOpts;
}

/** Sign a passport. Throws (a signer never emits a weaker or inconsistent artifact): hardware_rooted without evidence, bad window, unknown alg. */
export function signPassport(passport: AgentPassport, o: SignPassportOptions): SignedPassport {
  if (passport.id !== passportFingerprint(passport)) throw new Error('signPassport: passport.id is not the fingerprint of its identity (use issuePassport)');
  if (passport.hardware_rooted && !o.evidence) throw new Error('signPassport: hardware_rooted requires attestation evidence (fail closed)');
  if (o.evidence?.at !== undefined && !Number.isSafeInteger(o.evidence.at)) throw new RangeError('signPassport: evidence.at must be a safe integer');
  if (resolveSigAlg(o.suite?.alg) === null) throw new Error(`signPassport: unknown signature alg '${String(o.suite!.alg)}'`); // reachable only with a suite
  const iat = o.iat ?? passport.issued_at;
  const nbf = o.nbf ?? iat;
  const evidence = o.evidence ? { ...o.evidence, at: o.evidence.at ?? iat } : undefined;
  if (![iat, nbf, o.exp].every(Number.isSafeInteger) || o.exp <= nbf) throw new RangeError('signPassport: iat/nbf/exp must be safe integers with exp > nbf');
  const iss = b64u(publicKeyOf(o.issuerSecret));
  const body = bindSuiteFields(
    stripUndefined({ typ: 'atlas-pca/passport' as const, ver: PASSPORT_VERSION, passport: stripUndefined(passport), iss, sub: o.subject, iat, nbf, exp: o.exp, evidence }),
    o.suite?.alg,
    suitePqPublicKey(o.suite?.alg, o.suite),
  );
  return { ...body, ...signSuiteArtifact(o.suite?.alg, suiteKeysOf(o.issuerSecret, o.suite), passportMessage(body)) } as SignedPassport;
}

export type PassportReason =
  | 'malformed'
  | 'unsupported_version'
  | 'unsupported_suite'
  | 'unknown_issuer'
  | 'bad_signature'
  | 'id_mismatch'
  | 'not_yet_valid'
  | 'expired'
  | 'subject_mismatch'
  | 'revoked'
  | 'revocation_unavailable'
  | 'hardware_evidence_missing'
  | 'hardware_evidence_stale'
  | 'hardware_verifier_missing'
  | 'hardware_attestation_failed'
  | 'hardware_identity_mismatch';

export interface VerifyPassportOptions extends PqPinPolicy {
  /** Issuer keys (b64u Ed25519) you trust. Empty/absent trusts nobody (fail closed). */
  trustedIssuers: readonly string[];
  /** Epoch ms. */
  now: number;
  /** Tolerance on nbf/exp, ms (default 0, capped at 60000). */
  clockSkewMs?: number;
  /** The agent key the presenter signs with. When given the passport's `sub` must equal it. */
  subject?: string;
  /** Oldest acceptable hardware evidence, ms since the issuer obtained the quote (default 24 h, `DEFAULT_PASSPORT_EVIDENCE_AGE_MS`). Evidence dated in the future beyond the skew is stale too. */
  maxEvidenceAgeMs?: number;
  /** Verifies `evidence` for a `hardware_rooted` passport. Without it such a passport is REJECTED (never downgraded). */
  attestationVerifier?: HardwareAttestationVerifier;
  /** True iff this passport (by id / issuer / subject) is revoked. A throw denies. */
  revocation?: (p: { id: string; iss: string; sub: string }) => boolean | Promise<boolean>;
}

export type PassportVerdict =
  | { ok: true; passport: AgentPassport; iss: string; sub: string; exp: number; hardware_verified: boolean }
  | { ok: false; reason: PassportReason; detail?: string };

const bad = (reason: PassportReason, detail?: string): PassportVerdict => ({ ok: false, reason, ...(detail ? { detail } : {}) });
const isStr = (x: unknown): x is string => typeof x === 'string' && x.length > 0;

/**
 * Verify a signed passport. Fails closed with a distinct reason; never throws. `hardware_rooted: true` is accepted only when the
 * passport carries evidence that `attestationVerifier` validates, bound to the subject key and this passport's id, and whose
 * measured identity equals the claims.
 */
export async function verifyPassport(sp: unknown, o: VerifyPassportOptions): Promise<PassportVerdict> {
  try {
    const s = sp as Partial<SignedPassport> | null;
    // primitives and arrays have no `typ`; a non-object `passport` has no string `id`, so the field check below refuses it
    if (s?.typ !== 'atlas-pca/passport' || s.passport === null || s.passport === undefined) return bad('malformed');
    if (s.ver !== PASSPORT_VERSION) return bad('unsupported_version', String(s.ver));
    if (s.alg !== undefined && !isKnownSigAlg(s.alg)) return bad('unsupported_suite', String(s.alg));
    const p = s.passport as AgentPassport;
    if (!isStr(s.iss) || !isStr(s.sub) || !isStr(s.sig) || !isStr(p.id) || !isStr(p.model_id) || !isStr(p.operator) || typeof p.hardware_rooted !== 'boolean') return bad('malformed');
    if (![s.iat, s.nbf, s.exp, o.now].every(Number.isSafeInteger) || (s.exp as number) <= (s.nbf as number)) return bad('malformed', 'times');
    if (!Array.isArray(o.trustedIssuers) || !o.trustedIssuers.includes(s.iss)) return bad('unknown_issuer');
    const { sig, pq_sig, ...body } = s as SignedPassport;
    if (!verifyPinnedSuite(s.alg, s.iss, s.pq_pk, passportMessage(body), { sig, pq_sig }, o)) return bad('bad_signature');
    if (p.id !== passportFingerprint(p)) return bad('id_mismatch');
    const skew = Math.min(Math.max(o.clockSkewMs ?? 0, 0), MAX_SKEW_MS);
    if (o.now + skew < (s.nbf as number)) return bad('not_yet_valid');
    if (o.now - skew >= (s.exp as number)) return bad('expired');
    if (o.subject !== undefined && o.subject !== s.sub) return bad('subject_mismatch');
    if (typeof o.revocation !== 'function') return bad('revocation_unavailable', 'no revocation source');
    let revoked: boolean;
    try {
      revoked = (await o.revocation({ id: p.id, iss: s.iss, sub: s.sub })) === true;
    } catch {
      return bad('revocation_unavailable');
    }
    if (revoked) return bad('revoked');
    if (p.hardware_rooted) {
      const ev = (s.evidence ?? {}) as Partial<PassportEvidence>;
      const doc = ev.document as AttestationDocument; // a non-object has no string nonce, so the check below refuses it
      if (!isStr(doc?.nonce)) return bad('hardware_evidence_missing');
      const at = ev.at;
      if (!Number.isSafeInteger(at)) return bad('hardware_evidence_missing', 'evidence.at');
      const maxAge = o.maxEvidenceAgeMs ?? DEFAULT_PASSPORT_EVIDENCE_AGE_MS;
      if (!Number.isFinite(maxAge) || maxAge < 0 || o.now - (at as number) > maxAge || (at as number) - o.now > skew) return bad('hardware_evidence_stale');
      if (!o.attestationVerifier) return bad('hardware_verifier_missing');
      let r;
      try {
        // quote age is enforced above from the signed `evidence.at`; the vendor verifier's short nonce window cannot apply to an archived quote, so the nonce is "issued now"
        r = await o.attestationVerifier.verify({ document: doc, ctx: {} as VerifyContext, nowMs: o.now, expected: { ...passportEvidenceBinding(p.id, s.sub, doc.nonce), nonceIssuedAt: o.now } });
      } catch (e) {
        return bad('hardware_attestation_failed', e instanceof Error ? e.message : 'error');
      }
      if (!r || r.ok !== true || r.bound !== true) return bad('hardware_attestation_failed', r?.reason);
      const m = r.measured;
      if (!m || m.model_id !== p.model_id || m.operator !== p.operator || (p.weights_digest !== undefined && m.weights_digest !== p.weights_digest) || (p.runtime_measurement !== undefined && m.runtime_measurement !== p.runtime_measurement) || (p.system_prompt_digest !== undefined && m.system_prompt_digest !== p.system_prompt_digest) || (p.tool_manifest_digest !== undefined && m.tool_manifest_digest !== p.tool_manifest_digest) || (p.weights_measured === true && m.weights_measured !== true)) {
        return bad('hardware_identity_mismatch');
      }
    }
    return { ok: true, passport: p, iss: s.iss, sub: s.sub, exp: s.exp as number, hardware_verified: p.hardware_rooted };
  } catch (e) {
    return bad('malformed', e instanceof Error ? e.message : 'error');
  }
}

/** Assurance label (`level`, `vendor`) for a verified passport: hardware only when the evidence verified through `verifier`. */
export function passportAssurance(v: Extract<PassportVerdict, { ok: true }>, verifier?: HardwareAttestationVerifier): { level: string; vendor?: string } {
  if (!v.hardware_verified) return { level: 'software' };
  const l = assuranceLabelOf(verifier);
  return { level: l?.level ?? 'unknown', ...(l?.vendor ? { vendor: l.vendor } : {}) };
}
