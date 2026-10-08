import { canonicalizeStrict, decodeB64uStrict } from './hash';
import { validateSignatureWire } from './pq';

/**
 * PCActn wire format v2: the NORMATIVE structural + lexical rules a signed PCActn must satisfy BEFORE any
 * cryptographic check runs. Every verifier (TypeScript reference + the 8 language SDKs) enforces exactly
 * this; a failure is the single `wire` check (the verdict is a hard deny and no other check is evaluated).
 *
 * Lexical profile: see `strict-json.ts` (parsing signed bytes) and `canonicalizeStrict` (hash.ts).
 * Key order for hashing/signing: bytewise over UTF-8 (== code point order). Numbers: safe integers, or
 * plain-decimal (<= 15 significant digits) for the few fractional fields.
 */
export const PCACTN_WIRE_VERSION = 2;

/** Closed set of top-level fields of a ver-2 PCActn. */
export const PCACTN_REQUIRED_FIELDS = [
  'ver', 'action', 'grant_ref', 'cap_chain', 'plan', 'attestation', 'provenance', 'freshness',
  'counter', 'risk_claim', 'aud', 'iat', 'exp', 'sig',
] as const;
/**
 * Optional slots. Most are SIGNED (part of the signed hash when present). The UNSIGNED containers are
 * `threshold`, and the B4 post-quantum signature `pq_sig` (an ML-DSA signature cannot sign itself; it is
 * stripped from the signed body exactly like `sig`/`threshold`). `alg` and `pq_pk` ARE signed (so the
 * suite and the ML-DSA key cannot be downgraded/swapped — see pq.ts).
 */
export const PCACTN_OPTIONAL_FIELDS = [
  'nonce', 'caution', 'rationale_commitment', 'progress_step', 'prohibition_evidence', 'tool_binding',
  'threshold', 'zk_compliance', 'bond_ref',
  // B4 crypto-agility (additive): absent `alg` == "ed25519" and validates exactly as today.
  'alg', 'pq_pk', 'pq_sig',
] as const;

const KNOWN = new Set<string>([...PCACTN_REQUIRED_FIELDS, ...PCACTN_OPTIONAL_FIELDS]);

const isObj = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const isStr = (v: unknown): v is string => typeof v === 'string';
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0);
const isNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);

const B32 = 32;
const SIG = 64;

/** UTF-8 byte length (the NORMATIVE unit for all length bounds — portable across languages). */
const u8len = (s: string): number => new TextEncoder().encode(s).length;

/** Maximum lengths of the free-form freshness strings, in UTF-8 BYTES. */
export const MAX_AUD_LEN = 256;
export const MAX_NONCE_LEN = 128;

/**
 * Closed key set of a capability-chain hop (unknown keys are unsigned malleability). The B4
 * crypto-agility fields (`alg`, `pq_pk`, `pq_sig`) are additive and permitted on a hop exactly as on the
 * top-level PCActn: absent `alg` == `ed25519`, in which case `pq_pk`/`pq_sig` MUST be absent and the hop
 * is BYTE-IDENTICAL to the pre-B4 wire. Their per-suite shape is enforced by `validateSignatureWire`.
 */
const HOP_KEYS = new Set(['id', 'issuer', 'holder', 'body_digest', 'caveats', 'sig', 'parent', 'alg', 'pq_pk', 'pq_sig']);

/**
 * Validate the wire form. Returns `null` when well-formed, else a short reason. Never throws.
 * Does NOT judge semantic ranges (counter >= 0, proof index < size, chain depth <= 16, ver value): those are
 * their own checks. It judges: presence, JSON type, closed field sets, integer-ness, canonical base64url of
 * every fixed-length byte field, and that the whole body admits the strict canonical encoding.
 */
export function validateWireV2(p: unknown): string | null {
  try {
    if (!isObj(p)) return 'PCActn is not an object';
    for (const k of Object.keys(p)) if (!KNOWN.has(k)) return `unknown field '${k}'`;
    for (const k of PCACTN_REQUIRED_FIELDS) if (!(k in p)) return `missing field '${k}'`;
    // unsigned containers excluded from the signed body, but every signed byte must be canonical-encodable:
    const { sig, threshold, pq_sig, ...body } = p as Record<string, unknown>;
    void sig;
    void threshold;
    void pq_sig; // B4: the ML-DSA signature is unsigned (stripped like `sig`); absent in all pre-B4 objects.
    try {
      canonicalizeStrict(body);
    } catch (e) {
      return (e as Error).message;
    }

    if (!isInt(p.ver)) return "'ver' must be a safe integer";
    if (!isInt(p.counter)) return "'counter' must be a safe integer";
    if (!isInt(p.iat)) return "'iat' must be a safe integer";
    if (!isInt(p.exp)) return "'exp' must be a safe integer";
    if (!isStr(p.aud) || p.aud.length === 0 || u8len(p.aud) > MAX_AUD_LEN) return "'aud' must be a non-empty string (<= 256 UTF-8 bytes)";
    if (p.nonce !== undefined && (!isStr(p.nonce) || p.nonce.length === 0 || u8len(p.nonce) > MAX_NONCE_LEN)) {
      return "'nonce' must be a non-empty string (<= 128 UTF-8 bytes)";
    }
    // B4 crypto-agility: the signature fields (`alg`, `sig`, `pq_pk`, `pq_sig`) are validated per suite.
    // With no `alg` this asserts exactly `decodeB64uStrict(p.sig, 64)` and that `pq_pk`/`pq_sig` are absent —
    // i.e. BYTE-IDENTICAL wire behaviour to the pre-B4 reference. Unknown `alg` fails closed.
    const sigErr = validateSignatureWire(p as Record<string, unknown>, decodeB64uStrict);
    if (sigErr !== null) return sigErr;
    if (decodeB64uStrict(p.grant_ref, B32) === null) return "'grant_ref' is not canonical base64url (32 bytes)";

    const a = p.action;
    if (!isObj(a)) return "'action' must be an object";
    for (const k of Object.keys(a)) if (!['verb', 'resource', 'params_digest', 'reversibility_class'].includes(k)) return `unknown field 'action.${k}'`;
    if (!isStr(a.verb) || !isStr(a.resource) || !isStr(a.reversibility_class)) return 'action.verb/resource/reversibility_class must be strings';
    if (decodeB64uStrict(a.params_digest, B32) === null) return "'action.params_digest' is not canonical base64url (32 bytes)";

    const pl = p.plan;
    if (!isObj(pl)) return "'plan' must be an object";
    for (const k of Object.keys(pl)) if (!['root', 'inclusion_proof', 'node_id', 'conditions_digest'].includes(k)) return `unknown field 'plan.${k}'`;
    if (decodeB64uStrict(pl.root, B32) === null) return "'plan.root' is not canonical base64url (32 bytes)";
    if (!isStr(pl.node_id)) return "'plan.node_id' must be a string";
    if (pl.conditions_digest !== undefined && decodeB64uStrict(pl.conditions_digest, B32) === null) {
      return "'plan.conditions_digest' must be a canonical base64url string (32 bytes)";
    }
    const ip = pl.inclusion_proof;
    if (!isObj(ip)) return "'plan.inclusion_proof' must be an object";
    for (const k of Object.keys(ip)) if (!['index', 'size', 'path'].includes(k)) return `unknown field 'plan.inclusion_proof.${k}'`;
    if (!isInt(ip.index)) return "'plan.inclusion_proof.index' must be a safe integer";
    if (!isInt(ip.size)) return "'plan.inclusion_proof.size' must be a safe integer";
    if (!Array.isArray(ip.path)) return "'plan.inclusion_proof.path' must be an array";
    for (const [i, st] of ip.path.entries()) {
      if (!isObj(st)) return `proof step ${i} must be an object`;
      for (const k of Object.keys(st)) if (k !== 'side' && k !== 'hash') return `unknown field 'path[${i}].${k}'`;
      if (st.side !== 'L' && st.side !== 'R') return `proof step ${i}: side must be 'L' or 'R'`;
      if (decodeB64uStrict(st.hash, B32) === null) return `proof step ${i}: hash is not canonical base64url (32 bytes)`;
    }

    if (!Array.isArray(p.cap_chain)) return "'cap_chain' must be an array";
    for (const [i, c] of p.cap_chain.entries()) {
      if (!isObj(c)) return `cap_chain[${i}] must be an object`;
      for (const k of Object.keys(c)) if (!HOP_KEYS.has(k)) return `unknown field 'cap_chain[${i}].${k}'`;
      for (const k of ['id', 'issuer', 'holder', 'body_digest']) {
        if (decodeB64uStrict(c[k], B32) === null) return `cap_chain[${i}].${k} is not canonical base64url (32 bytes)`;
      }
      // B4 crypto-agility: validate the hop's `alg`/`sig`/`pq_pk`/`pq_sig` per suite, exactly as the leaf.
      // With no `alg` this asserts a 64-byte `sig` and that `pq_pk`/`pq_sig` are absent — BYTE-IDENTICAL to
      // the pre-B4 hop wire. A pure ml-dsa-65 hop carries a 3309-byte `sig`; a hybrid hop carries a 64-byte
      // `sig` plus a 3309-byte `pq_sig`, both alongside the issuer's 1952-byte `pq_pk`. Unknown `alg` fails.
      const hopSigErr = validateSignatureWire(c, decodeB64uStrict);
      if (hopSigErr !== null) return `cap_chain[${i}]: ${hopSigErr}`;
      if (c.parent !== undefined && decodeB64uStrict(c.parent, B32) === null) return `cap_chain[${i}].parent is not canonical base64url (32 bytes)`;
      if (!Array.isArray(c.caveats) || !c.caveats.every((cv) => isObj(cv) && isStr(cv.type))) return `cap_chain[${i}].caveats must be an array of {type,...} objects`;
    }

    const at = p.attestation;
    if (!isObj(at) || !isInt(at.epoch)) return "'attestation' must be an object with an integer 'epoch'";
    if (!isStr(at.quote_digest) || !isStr(at.model_id) || !isStr(at.measurement) || !isStr(at.operator)) return 'attestation string fields must be strings';
    const pv = p.provenance;
    if (!isObj(pv) || !isStr(pv.causal_hash) || !isNum(pv.taint_level) || !Array.isArray(pv.trusted_refs) || !pv.trusted_refs.every(isStr)) {
      return "'provenance' is malformed";
    }
    const fr = p.freshness;
    if (!isObj(fr) || !isInt(fr.epoch) || !isStr(fr.beacon_ref) || !isStr(fr.accumulator_witness)) return "'freshness' is malformed";
    const rc = p.risk_claim;
    if (!isObj(rc) || !isNum(rc.r) || !isObj(rc.inputs)) return "'risk_claim' is malformed";

    // optional signed slots
    if (p.caution !== undefined && !(isNum(p.caution) && p.caution >= 0 && p.caution <= 1)) return "'caution' must be a number in [0,1]";
    if (p.rationale_commitment !== undefined && decodeB64uStrict(p.rationale_commitment, B32) === null) {
      return "'rationale_commitment' is not canonical base64url (32 bytes)";
    }
    if (p.tool_binding !== undefined && decodeB64uStrict(p.tool_binding, B32) === null) return "'tool_binding' is not canonical base64url (32 bytes)";
    if (p.progress_step !== undefined && !isObj(p.progress_step)) return "'progress_step' must be an object";
    if (p.prohibition_evidence !== undefined && !isObj(p.prohibition_evidence) && !Array.isArray(p.prohibition_evidence)) {
      return "'prohibition_evidence' must be an object or array";
    }
    if (p.threshold !== undefined) {
      const th = p.threshold;
      if (!isObj(th) || !Array.isArray(th.shares)) return "'threshold' must be {shares:[...]}";
      for (const [i, s] of th.shares.entries()) {
        if (!isObj(s) || !isStr(s.role)) return `threshold.shares[${i}] is malformed`;
        if (decodeB64uStrict(s.publicKey, B32) === null) return `threshold.shares[${i}].publicKey is not canonical base64url (32 bytes)`;
        if (decodeB64uStrict(s.sig, SIG) === null) return `threshold.shares[${i}].sig is not canonical base64url (64 bytes)`;
      }
    }
    return null;
  } catch (e) {
    return `malformed: ${(e as Error).message}`;
  }
}
