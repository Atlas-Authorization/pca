/**
 * READ-SIDE AUTHORIZATION (K5, C-310..C-319): what an agent may SEE, proven, and where it may go next.
 *
 * A principal signs a READ GRANT: per (verb, resource prefix, purpose) a mask MODE per data class (the classes an action's
 * `returns.classes` already tags: pii, secret, financial ...), per-class enumeration caps, and per-sink label rules ("data labelled
 * X may reach `external_communication`"). {@link redactRead} applies the grant to one response (field -> class schema, flat record):
 * every field is shown, masked (last4 | bucket | hash | token) or dropped. The resource server signs a READ RECEIPT listing, per
 * field, what happened with a SALTED value digest, so the principal audits "the agent saw SSN last4 only" without the value. The
 * labels of everything not dropped then flow into later decisions: {@link checkSink} denies / escalates a write whose sink the
 * grant does not allow those labels to reach.
 *
 * TIGHTEN-ONLY: a caller (or untrusted text the model read) may ask for a STRICTER mode than the grant gives; a weaker request is
 * ignored. Pure and total: anything malformed, unsigned, unknown or out of scope DENIES. Integers only.
 */
import { b64u, hashCanonical } from './hash';
import { publicKeyOf } from './keys';
import { own, ID_RE, LABEL_RE, NAME_RE, type Scalar, isB32, isObj, isScalarMap, isStr, isUint, onlyKeys, signBody, sortedUnique, verifyBody, type K5Decision } from './workflow';

export const READ_GRANT_DOMAIN = 'atlas-pca/read-grant/v1\0';
export const READ_RECEIPT_DOMAIN = 'atlas-pca/read-receipt/v1\0';
const RG_REF = 'atlas-pca/read-grant-ref/v1';
const RR_REF = 'atlas-pca/read-receipt-ref/v1';
const RH = 'atlas-pca/read-hash/v1';
const RT = 'atlas-pca/read-token/v1';
const RV = 'atlas-pca/read-value/v1';

export interface ReadEntry {
  verb: string;
  resource_prefix: string;
  purposes: string[];
  modes: Record<string, string>;
  default_mode: string;
}
export interface ReadGrantBody {
  v: 1;
  id: string;
  principal: string;
  issued_at: number;
  expires_at: number;
  reads: ReadEntry[];
  caps: Record<string, number>;
  sinks: Record<string, { allow: string[]; escalate: string[] }>;
}
export interface SignedReadGrant {
  body: ReadGrantBody;
  sig: string;
}
export interface ReadField {
  class: string;
  action: 'shown' | 'masked' | 'dropped';
  kind: string | null;
  vd: string;
}
export interface ReadReceipt {
  v: 1;
  grant: string;
  verb: string;
  resource: string;
  purpose: string;
  seq: number;
  prev: string | null;
  fields: Record<string, ReadField>;
  labels: string[];
  issued_at: number;
  signer: string;
  sig: string;
}

const RANK: Record<string, number> = { show: 0, last4: 1, bucket: 2, token: 3, hash: 4, drop: 5 };
const MODE_RE = /^(show|last4|hash|token|drop|bucket:[1-9][0-9]{0,8})$/;
const isMode = (x: unknown): x is string => typeof x === 'string' && MODE_RE.test(x);
const rank = (m: string): number => RANK[m.startsWith('bucket:') ? 'bucket' : m] as number;
const SALT_MIN = 16;

function validEntry(e: unknown): e is ReadEntry {
  return (
    isObj(e) && onlyKeys(e, ['verb', 'resource_prefix', 'purposes', 'modes', 'default_mode']) && isStr(e.verb, 128) && isStr(e.resource_prefix, 512) && sortedUnique(e.purposes, ID_RE, 16) && (e.purposes as string[]).length > 0 &&
    isObj(e.modes) && Object.keys(e.modes).length <= 32 && Object.entries(e.modes).every(([k, v]) => LABEL_RE.test(k) && isMode(v)) && isMode(e.default_mode)
  );
}
/** Shape of a read grant body (no signature). */
export function validReadGrantBody(b: unknown): b is ReadGrantBody {
  if (!isObj(b) || !onlyKeys(b, ['v', 'id', 'principal', 'issued_at', 'expires_at', 'reads', 'caps', 'sinks']) || b.v !== 1) return false;
  if (typeof b.id !== 'string' || !ID_RE.test(b.id) || !isB32(b.principal) || !isUint(b.issued_at) || !isUint(b.expires_at)) return false;
  if (!Array.isArray(b.reads) || b.reads.length === 0 || b.reads.length > 32 || !b.reads.every(validEntry)) return false;
  if (!isObj(b.caps) || Object.keys(b.caps).length > 32 || !Object.entries(b.caps).every(([k, v]) => LABEL_RE.test(k) && isUint(v))) return false;
  const s = b.sinks;
  if (!isObj(s) || Object.keys(s).length > 16) return false;
  return Object.entries(s).every(([k, v]) => ID_RE.test(k) && isObj(v) && onlyKeys(v, ['allow', 'escalate']) && sortedUnique(v.allow, LABEL_RE, 16) && sortedUnique(v.escalate, LABEL_RE, 16) && !(v.allow as string[]).some((l) => (v.escalate as string[]).includes(l)));
}

export const readGrantDigest = (b: ReadGrantBody): string => hashCanonical({ d: RG_REF, g: b });
export const readReceiptRef = (r: ReadReceipt): string => hashCanonical({ d: RR_REF, r });
export function signReadGrant(secret: Uint8Array, body: ReadGrantBody): SignedReadGrant {
  if (!validReadGrantBody(body) || body.principal !== b64u(publicKeyOf(secret))) throw new RangeError('signReadGrant: malformed grant');
  return { body, sig: signBody(secret, READ_GRANT_DOMAIN, body) };
}
const recBody = (r: Omit<ReadReceipt, 'sig'>): Omit<ReadReceipt, 'sig'> => ({ v: r.v, grant: r.grant, verb: r.verb, resource: r.resource, purpose: r.purpose, seq: r.seq, prev: r.prev, fields: r.fields, labels: r.labels, issued_at: r.issued_at, signer: r.signer });
export function signReadReceipt(secret: Uint8Array, o: { grant: ReadGrantBody; verb: string; resource: string; purpose: string; fields: Record<string, ReadField>; labels: string[]; issuedAt: number; prev?: ReadReceipt }): ReadReceipt {
  const base = { v: 1 as const, grant: readGrantDigest(o.grant), verb: o.verb, resource: o.resource, purpose: o.purpose, seq: o.prev ? o.prev.seq + 1 : 0, prev: o.prev ? readReceiptRef(o.prev) : null, fields: o.fields, labels: o.labels, issued_at: o.issuedAt, signer: b64u(publicKeyOf(secret)) };
  return { ...base, sig: signBody(secret, READ_RECEIPT_DOMAIN, recBody(base)) };
}

export interface ReadResult {
  decision: K5Decision;
  code: string | null;
  view: Record<string, Scalar>;
  fields: Record<string, ReadField>;
  labels: string[];
  counts: Record<string, number>;
}
export interface ReadInput {
  grant: unknown;
  principal: string;
  now: number;
  verb: string;
  resource: string;
  purpose: string;
  /** field path -> data class (an action's `returns.classes`); `required` paths that end up dropped or absent escalate */
  schema: { fields: Record<string, string>; required: string[] };
  record: Record<string, Scalar>;
  /** class -> a STRICTER mode asked for by the caller; a weaker one is ignored (tighten-only) */
  tighten: Record<string, string>;
  /** a per-read secret of at least 16 characters: salts value digests, hashes and tokens */
  salt: string;
  /** reads already charged per class in the current window (the caller owns the window) */
  counts: Record<string, number>;
}
const out = (decision: K5Decision, code: string | null, counts: Record<string, number> = {}): ReadResult => ({ decision, code, view: {}, fields: {}, labels: [], counts });
const sorted = (xs: Iterable<string>): string[] => [...xs].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
const BMP = (s: string): boolean => [...s].every((c) => (c.codePointAt(0) as number) < 0x10000);

function gradeGrant(g: unknown, principal: string, now: number): { body: ReadGrantBody } | { code: string } {
  const sg = g as SignedReadGrant;
  if (!isB32(principal) || !isUint(now)) return { code: 'bad_request' };
  if (!isObj(sg) || !onlyKeys(sg, ['body', 'sig']) || !validReadGrantBody(sg.body)) return { code: 'bad_grant' };
  if (sg.body.principal !== principal || !verifyBody(READ_GRANT_DOMAIN, sg.body, principal, sg.sig)) return { code: 'bad_signature' };
  if (now < sg.body.issued_at) return { code: 'not_yet' };
  if (now >= sg.body.expires_at) return { code: 'expired' };
  return { body: sg.body };
}

/** Apply a read grant to one response. See the module header. */
export function redactRead(inp: ReadInput): ReadResult {
  try {
    const g = gradeGrant(inp.grant, inp.principal, inp.now);
    if ('code' in g) return out('deny', g.code);
    const sc = inp.schema;
    if (!isB32(inp.principal) || !isUint(inp.now) || !isStr(inp.verb, 128) || !isStr(inp.resource, 512) || typeof inp.purpose !== 'string' || !ID_RE.test(inp.purpose) || typeof inp.salt !== 'string' || inp.salt.length < SALT_MIN) return out('deny', 'bad_request');
    if (!isObj(sc) || !isObj(sc.fields) || !Object.entries(sc.fields).every(([k, v]) => NAME_RE.test(k) && typeof v === 'string' && LABEL_RE.test(v)) || !Array.isArray(sc.required) || !sc.required.every((p) => typeof p === 'string' && own(sc.fields, p) !== undefined)) return out('deny', 'bad_request');
    if (!isScalarMap(inp.record) || !isObj(inp.tighten) || !Object.entries(inp.tighten).every(([k, v]) => LABEL_RE.test(k) && isMode(v))) return out('deny', 'bad_request');
    if (!isObj(inp.counts) || !Object.entries(inp.counts).every(([k, v]) => LABEL_RE.test(k) && isUint(v))) return out('deny', 'bad_request');
    const entry = g.body.reads.find((e) => e.verb === inp.verb && inp.resource.startsWith(e.resource_prefix) && e.purposes.includes(inp.purpose));
    if (entry === undefined) return out('deny', 'no_read_scope', inp.counts);
    const fields: Record<string, ReadField> = {};
    const view: Record<string, Scalar> = {};
    const used: Record<string, number> = {};
    for (const path of sorted(Object.keys(inp.record))) {
      const v = own(inp.record, path) as Scalar;
      const cls = own(sc.fields, path);
      // a field the schema does not classify is never shown
      const vd = hashCanonical({ d: RV, salt: inp.salt, p: path, v });
      if (cls === undefined) {
        fields[path] = { class: 'unclassified', action: 'dropped', kind: null, vd };
        continue;
      }
      let mode = own(entry.modes, cls) ?? entry.default_mode;
      const t = own(inp.tighten, cls);
      if (t !== undefined && rank(t) > rank(mode)) mode = t;
      let shown: Scalar | undefined;
      let action: ReadField['action'] = 'masked';
      let kind: string | null = mode.startsWith('bucket:') ? 'bucket' : mode;
      if (mode === 'show') {
        shown = v;
        action = 'shown';
        kind = null;
      } else if (mode === 'last4') {
        if (typeof v === 'string' && BMP(v) && [...v].length > 4) shown = `****${[...v].slice(-4).join('')}`;
      } else if (mode.startsWith('bucket:')) {
        const n = Number(mode.slice(7));
        if (typeof v === 'number' && v >= 0) shown = v - (v % n);
      } else if (mode === 'hash') {
        shown = hashCanonical({ d: RH, salt: inp.salt, c: cls, v });
      } else if (mode === 'token') {
        shown = `tok_${hashCanonical({ d: RT, salt: inp.salt, c: cls, v }).slice(0, 22)}`;
      }
      if (shown === undefined) {
        fields[path] = { class: cls, action: 'dropped', kind: null, vd };
        continue;
      }
      fields[path] = { class: cls, action, kind, vd };
      view[path] = shown;
      used[cls] = (own(used, cls) ?? 0) + 1;
    }
    const counts: Record<string, number> = { ...inp.counts };
    for (const [c, n] of Object.entries(used)) {
      counts[c] = (own(counts, c) ?? 0) + n;
      const cap = own(g.body.caps, c);
      if (cap !== undefined && (counts[c] as number) > cap) return out('deny', 'read_cap', inp.counts);
    }
    if (sc.required.some((p) => own(view, p) === undefined)) return out('escalate', 'required_dropped', inp.counts);
    const labels = sorted(new Set(Object.values(fields).filter((f) => f.action !== 'dropped').map((f) => f.class)));
    return { decision: 'allow', code: null, view, fields, labels, counts };
  } catch {
    return out('deny', 'bad_request');
  }
}

function validReadReceipt(r: unknown): r is ReadReceipt {
  if (!isObj(r) || !onlyKeys(r, ['v', 'grant', 'verb', 'resource', 'purpose', 'seq', 'prev', 'fields', 'labels', 'issued_at', 'signer', 'sig']) || r.v !== 1) return false;
  if (!isB32(r.grant) || !isStr(r.verb, 128) || !isStr(r.resource, 512) || typeof r.purpose !== 'string' || !ID_RE.test(r.purpose) || !isUint(r.seq) || !(r.prev === null || isB32(r.prev)) || (r.seq === 0) !== (r.prev === null)) return false;
  if (!isUint(r.issued_at) || !isB32(r.signer) || typeof r.sig !== 'string' || !sortedUnique(r.labels, LABEL_RE, 32) || !isObj(r.fields) || Object.keys(r.fields).length > 64) return false;
  return Object.entries(r.fields).every(([k, f]) => NAME_RE.test(k) && isObj(f) && onlyKeys(f, ['class', 'action', 'kind', 'vd']) && typeof f.class === 'string' && (f.class === 'unclassified' || LABEL_RE.test(f.class)) && (f.action === 'shown' || f.action === 'masked' || f.action === 'dropped') && (f.kind === null || typeof f.kind === 'string') && isB32(f.vd));
}
/** The labels carried by a verified, unbroken chain of read receipts, or an error code. */
export function readChainLabels(receipts: unknown, rsSigner: string, grantDigest: string, now: number): { labels: string[] } | { code: string; at: number } {
  if (!Array.isArray(receipts)) return { code: 'bad_receipt', at: 0 };
  const all = new Set<string>();
  let prev: ReadReceipt | null = null;
  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];
    if (!validReadReceipt(r) || r.signer !== rsSigner || r.grant !== grantDigest || r.seq !== i || r.issued_at > now) return { code: 'bad_receipt', at: i };
    if ((prev === null ? r.prev !== null : r.prev !== readReceiptRef(prev)) || !verifyBody(READ_RECEIPT_DOMAIN, recBody(r), rsSigner, r.sig)) return { code: 'bad_receipt', at: i };
    // the receipt's labels must be exactly the classes of its non-dropped fields: an understated label list would launder data
    const want = sorted(new Set(Object.values(r.fields).filter((f) => f.action !== 'dropped').map((f) => f.class)));
    if (want.length !== r.labels.length || want.some((l, j) => l !== r.labels[j])) return { code: 'bad_receipt', at: i };
    for (const l of r.labels) all.add(l);
    prev = r;
  }
  return { labels: sorted(all) };
}
export interface SinkInput {
  grant: unknown;
  principal: string;
  rsSigner: string;
  now: number;
  sink: string;
  /** every read receipt whose data the write may carry */
  receipts: unknown[];
}
/** May data read under these receipts reach `sink`? Deny on any label the grant does not allow; escalate on an "ask" label. */
export function checkSink(inp: SinkInput): { decision: K5Decision; code: string | null; labels: string[] } {
  const no = (code: string) => ({ decision: 'deny' as K5Decision, code, labels: [] as string[] });
  try {
    const g = gradeGrant(inp.grant, inp.principal, inp.now);
    if ('code' in g) return no(g.code);
    if (!isB32(inp.rsSigner) || typeof inp.sink !== 'string') return no('bad_request');
    const rule = own(g.body.sinks, inp.sink);
    if (rule === undefined) return no('unknown_sink');
    const c = readChainLabels(inp.receipts, inp.rsSigner, readGrantDigest(g.body), inp.now);
    if ('code' in c) return no(c.code);
    if (c.labels.some((l) => !rule.allow.includes(l) && !rule.escalate.includes(l))) return { decision: 'deny', code: 'label_flow', labels: c.labels };
    if (c.labels.some((l) => rule.escalate.includes(l))) return { decision: 'escalate', code: 'label_escalate', labels: c.labels };
    return { decision: 'allow', code: null, labels: c.labels };
  } catch {
    return no('bad_request');
  }
}
