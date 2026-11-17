/**
 * Trace ingestion: the proxy/guard receipt log, OpenTelemetry spans from `@atlasauth/pca-otel`, and a simple JSONL format all
 * become one normalized, bounded, deterministic {@link TraceSet}. Input is hostile by assumption (an attacker may act during
 * observation, or flood the log), so every record is validated, anything unusable is REJECTED with a reason (never repaired),
 * and sensitive actions are flagged here so no later stage can include them silently.
 */
import { hashCanonicalLenient, verifyReceiptChain, type Receipt } from '@atlasauth/pca';
import { DEFAULT_CATALOG } from '@atlasauth/pca/ext/research';
import { cleanText } from '@atlasauth/pca-explain';
import { DEFAULT_DANGEROUS_VERBS } from '@atlasauth/pca-policy-ci';
import type { IngestOptions, Rejected, Trace, TraceSet, TraceSource } from './types';

export const DEFAULT_MAX_TRACES = 100_000;
const VERB = /^[A-Za-z0-9_.:-]{1,128}$/;
const NAME = /^[A-Za-z0-9_.:-]{1,128}$/;
const PARAM_KEY = /^[A-Za-z0-9_]{1,64}$/;
const FORBIDDEN_KEY = new Set(['__proto__', 'constructor', 'prototype']);
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;
/** Resources that name credentials, key material, identity or money plumbing: a reviewer must opt each one in. */
const SECRET_LIKE = /(secret|credential|passw(or)?d|private[_-]?key|api[_-]?key|\.env\b|\btoken|\/iam\b|\/admin\b|\bbilling\b|\bpayout)/i;

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);

/** `null` when the resource is a usable literal; else why not. A literal `*` or `re:` would be read as a pattern by the verifier. */
function resourceError(r: unknown): string | null {
  if (typeof r !== 'string' || r.length === 0 || r.length > 512) return 'resource must be a string of 1-512 characters';
  if (CONTROL.test(r)) return 'resource contains control characters';
  if (r.includes('*') || r.startsWith('re:')) return 'resource contains a wildcard or regex marker (it would be read as a pattern)';
  if (r.split('/').some((s) => s === '..' || s === '.')) return "resource contains a '.' or '..' path segment";
  return null;
}

/** Normalize one record. Returns the trace (sensitivity not yet decided) or a rejection reason. */
function normalize(raw: unknown, source: TraceSource): Omit<Trace, 'id' | 'sensitive'> | string {
  if (!isObj(raw)) return 'record is not an object';
  const { at, verb, resource, outcome } = raw;
  if (typeof at !== 'number' || !Number.isFinite(at) || at < 0 || at > 8.64e15) return 'at must be a finite epoch-millisecond number';
  if (typeof verb !== 'string' || !VERB.test(verb)) return 'verb is missing or malformed';
  const re = resourceError(resource);
  if (re) return re;
  const o = outcome === undefined ? 'allow' : outcome;
  if (o !== 'allow' && o !== 'deny') return "outcome must be 'allow' or 'deny'";
  const params: Record<string, string | number | boolean> = {};
  if (raw.params !== undefined) {
    if (!isObj(raw.params)) return 'params must be an object';
    for (const k of Object.keys(raw.params)) {
      const v = raw.params[k];
      if (FORBIDDEN_KEY.has(k) || !PARAM_KEY.test(k)) return `param name '${cleanText(k).slice(0, 40)}' is not allowed`;
      if (typeof v === 'number') {
        if (!Number.isFinite(v)) return `param '${k}' is not a finite number`;
        params[k] = v;
      } else if (typeof v === 'string') {
        if (v.length > 256 || CONTROL.test(v)) return `param '${k}' is too long or has control characters`;
        params[k] = v;
      } else if (typeof v === 'boolean') params[k] = v;
      // nested values and nulls are not analyzable here: dropped, never guessed
    }
  }
  const out: Omit<Trace, 'id' | 'sensitive'> = { at: Math.trunc(at), verb, resource: resource as string, params, outcome: o as 'allow' | 'deny', source };
  if (raw.tenant !== undefined) {
    if (typeof raw.tenant !== 'string' || !NAME.test(raw.tenant)) return 'tenant is malformed';
    out.tenant = raw.tenant;
  }
  if (raw.actor !== undefined) {
    if (typeof raw.actor !== 'string' || !NAME.test(raw.actor)) return 'actor is malformed';
    out.actor = raw.actor;
  }
  return out;
}

const median = (xs: number[]): number => {
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2;
};

/** Build the set: id, sensitivity flags, deterministic order, digest. */
function finish(rows: Omit<Trace, 'id' | 'sensitive'>[], rejected: Rejected[], truncated: number, o: IngestOptions): TraceSet {
  const dangerous = (o.dangerousVerbs ?? DEFAULT_DANGEROUS_VERBS).map((s) => s.toLowerCase());
  const extra = (o.sensitiveResources ?? []).flatMap((s) => {
    try { return [new RegExp(s, 'i')]; } catch { return []; }
  });
  // amount outliers: a value more than 10x the median of its (verb, param) group, with at least 5 samples
  const groups = new Map<string, number[]>();
  for (const r of rows) for (const [k, v] of Object.entries(r.params)) if (typeof v === 'number') (groups.get(`${r.verb}\0${k}`) ?? groups.set(`${r.verb}\0${k}`, []).get(`${r.verb}\0${k}`)!).push(v);
  const med = new Map<string, number>();
  for (const [k, xs] of groups) if (xs.length >= 5) med.set(k, median(xs.map(Math.abs)));

  const traces: Trace[] = rows.map((r) => {
    const sensitive: string[] = [];
    const v = r.verb.toLowerCase();
    if (dangerous.some((d) => v.includes(d))) sensitive.push('dangerous-verb');
    if (DEFAULT_CATALOG.get(r.verb)?.reversibility === 'irreversible') sensitive.push('irreversible-action');
    if (SECRET_LIKE.test(r.resource) || extra.some((x) => x.test(r.resource))) sensitive.push('sensitive-resource');
    if (o.trustedActors !== undefined && (r.actor === undefined || !o.trustedActors.includes(r.actor))) sensitive.push('untrusted-actor');
    for (const [k, val] of Object.entries(r.params)) {
      const m = med.get(`${r.verb}\0${k}`);
      if (typeof val === 'number' && m !== undefined && Math.abs(val) > 10 * Math.max(m, 1e-9) && Math.abs(val) > 0) sensitive.push(`amount-outlier:${k}`);
    }
    return { ...r, id: hashCanonicalLenient({ t: r.tenant ?? null, v: r.verb, r: r.resource, o: r.outcome }).slice(0, 16), sensitive: [...new Set(sensitive)].sort() };
  });
  traces.sort((a, b) => a.at - b.at || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0) || JSON.stringify(a.params).localeCompare(JSON.stringify(b.params)));
  return { v: 1, traces, rejected, truncated, digest: hashCanonicalLenient(traces) };
}

function collect(items: unknown[], source: TraceSource, o: IngestOptions, map: (x: unknown) => unknown = (x) => x): TraceSet {
  const cap = o.maxTraces ?? DEFAULT_MAX_TRACES;
  const rows: Omit<Trace, 'id' | 'sensitive'>[] = [];
  const rejected: Rejected[] = [];
  let truncated = 0;
  items.forEach((raw, index) => {
    if (rows.length >= cap) { truncated++; return; }
    let n: ReturnType<typeof normalize>;
    try { n = normalize(map(raw), source); } catch { n = 'record could not be read'; }
    if (typeof n === 'string') { if (rejected.length < 1000) rejected.push({ index, reason: n }); } else rows.push(n);
  });
  return finish(rows, rejected, truncated, o);
}

/** Simple format: one JSON object per line `{at, verb, resource, params?, outcome?, tenant?, actor?}`. A bad line is rejected, not fatal. */
export function fromJsonl(text: string, o: IngestOptions = {}): TraceSet {
  const lines = text.split('\n').filter((l) => l.trim() !== '');
  return collect(lines, 'jsonl', o, (l) => JSON.parse(l as string));
}

/**
 * One line of the proxy's optional observed-parameters log (see the README): the numeric and enumerable-string parameters of
 * one decision, linked to its audit receipt and hash-chained to the previous line. Receipts themselves carry only a digest of
 * the arguments, so this is what lets amount caps be learned from an audit log.
 */
export interface ObservedRecord {
  v: 1;
  /** The receipt's `seq` and `hash` this line belongs to. */
  seq: number;
  receipt: string;
  verb: string;
  resource: string;
  params: Record<string, string | number | boolean>;
  /** Names (never values) of parameters the writer chose not to record. */
  omitted?: string[];
  prev: string;
  hash: string;
}

const MAX_OBSERVED_PARAMS = 32;
const MAX_OBSERVED_STRING = 64;

/**
 * The digest of a line's content that the proxy also writes into the receipt (facts `obs1` + `obs2`, the digest split at 22
 * characters so a fact is not redacted as a secret). It is the proxy's `observedContentDigest`, duplicated here byte for byte
 * (pca-proxy depends on this package, so it cannot be imported); `observed.test.ts` pins both to one literal vector.
 */
export function observedContentDigest(c: { seq: number; verb: string; resource: string; params: Record<string, unknown>; omitted?: readonly string[] }): string {
  return hashCanonicalLenient({ d: 'pca-proxy/observed-content/v1', seq: c.seq, verb: c.verb, resource: c.resource, params: c.params, omitted: c.omitted ?? [] });
}

/** The hash a line must carry: everything but `hash`, canonical. Writers and this reader must agree on it exactly. */
export function observedHash(r: Omit<ObservedRecord, 'hash'>): string {
  return hashCanonicalLenient({ v: r.v, seq: r.seq, receipt: r.receipt, verb: r.verb, resource: r.resource, params: r.params, omitted: r.omitted ?? [], prev: r.prev });
}

export function parseObservedParams(text: string): ObservedRecord[] {
  return text.split('\n').filter((l) => l.trim() !== '').map((l) => JSON.parse(l) as ObservedRecord);
}

/** A chain that is intact, sequential and made of well-formed lines; anything else is a refusal with the reason. */
export function checkObservedChain(recs: readonly ObservedRecord[]): { ok: true } | { ok: false; reason: string } {
  let prev = '';
  let lastSeq = -1;
  for (const r of recs) {
    if (!isObj(r) || r.v !== 1 || !Number.isSafeInteger(r.seq) || r.seq <= lastSeq || typeof r.receipt !== 'string' || typeof r.verb !== 'string' || typeof r.resource !== 'string' || !isObj(r.params) || typeof r.prev !== 'string' || typeof r.hash !== 'string') return { ok: false, reason: `malformed or out-of-order line near seq ${String((r as { seq?: unknown })?.seq)}` };
    if (r.prev !== prev) return { ok: false, reason: `prev link mismatch at seq ${r.seq}` };
    const { hash, ...body } = r;
    if (observedHash(body) !== hash) return { ok: false, reason: `hash mismatch at seq ${r.seq} (edited line)` };
    if (Object.keys(r.params).length > MAX_OBSERVED_PARAMS) return { ok: false, reason: `too many parameters at seq ${r.seq}` };
    prev = hash;
    lastSeq = r.seq;
  }
  return { ok: true };
}

/** Keep only what the contract allows: finite numbers, booleans, and short plain strings. */
function observedParams(p: ObservedRecord['params']): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(p)) {
    const v = p[k];
    if (typeof v === 'string' && v.length > MAX_OBSERVED_STRING) continue;
    out[k] = v;
  }
  return out;
}

/**
 * The proxy/guard audit log: a hash-chained receipt log. A receipt records the verb, resource, outcome and time, not the
 * parameters (only a digest of them), so numeric caps cannot be learned from it alone: pass the proxy's observed-parameters
 * log as `observed` to get them. A broken receipt chain, a broken observed chain, or a line that does not belong to the
 * receipt it names is refused outright: an edited log is not evidence. An observe-mode receipt whose `allowed` fact is
 * "false" is a call the policy would have refused, so it is read as a denial, not as the forward it also was.
 */
export function fromReceipts(log: readonly Receipt[], o: IngestOptions = {}, observed?: readonly ObservedRecord[]): TraceSet {
  if (o.requireIntactChain !== false) {
    const c = verifyReceiptChain([...log]);
    if (!c.ok) throw new Error(`receipt log is not an intact chain (${c.reason ?? 'broken'}); refusing to learn from it`);
  }
  const bySeq = new Map<number, ObservedRecord>();
  if (observed !== undefined) {
    const c = checkObservedChain(observed);
    if (!c.ok) throw new Error(`observed-parameters log is not an intact chain (${c.reason}); refusing to learn from it`);
    const rs = new Map(log.map((r) => [r.seq, r]));
    for (const rec of observed) {
      const r = rs.get(rec.seq);
      if (r === undefined || r.hash !== rec.receipt || r.verb !== rec.verb || r.resource !== rec.resource) throw new Error(`observed-parameters line ${rec.seq} does not belong to the receipt it names; refusing to learn from it`);
      // the receipt carries the digest of its line's content, so the two files cannot be rewritten independently
      const f = r.checks ?? {};
      if (typeof f.obs1 !== 'string' || typeof f.obs2 !== 'string') throw new Error(`observed-parameters line ${rec.seq} has no digest on its receipt (the line was added, or the receipt facts were stripped); refusing to learn from it`);
      if (`${f.obs1}${f.obs2}` !== observedContentDigest(rec)) throw new Error(`observed-parameters line ${rec.seq} does not match the digest its receipt carries (the line or the receipt was rewritten); refusing to learn from it`);
      bySeq.set(rec.seq, rec);
    }
    // a receipt that carries a digest must have its line; only the very last such receipt may be missing it (a crash loses the tail)
    const carriers = log.filter((r) => r.checks?.obs1 !== undefined || r.checks?.obs2 !== undefined).map((r) => r.seq);
    const lastCarrier = carriers.reduce((a, b) => (b > a ? b : a), -1);
    const missing = carriers.filter((q) => !bySeq.has(q));
    if (missing.some((q) => q !== lastCarrier)) throw new Error(`receipt ${String(missing.find((q) => q !== lastCarrier))} carries a parameters digest but its line is missing; refusing to learn from it`);
  }
  return collect([...log], 'receipt', o, (r) => {
    if (!isObj(r)) return r;
    const rec = bySeq.get(r.seq as number);
    const facts = isObj(r.checks) ? r.checks : {};
    return { at: r.at, verb: r.verb, resource: r.resource, outcome: facts.allowed === 'false' ? 'deny' : r.outcome, ...(rec !== undefined ? { params: observedParams(rec.params) } : {}) };
  });
}

export function parseReceiptJsonl(text: string): Receipt[] {
  return text.split('\n').filter((l) => l.trim() !== '').map((l) => JSON.parse(l) as Receipt);
}

type AttrBag = Record<string, unknown> | { key: string; value: unknown }[];
function attrs(bag: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = Object.create(null);
  if (Array.isArray(bag)) {
    for (const kv of bag as { key?: unknown; value?: unknown }[]) {
      if (!isObj(kv) || typeof kv.key !== 'string') continue;
      const v = kv.value;
      out[kv.key] = isObj(v) ? (v.stringValue ?? v.intValue ?? v.doubleValue ?? v.boolValue) : v; // OTLP-JSON value wrappers
    }
  } else if (isObj(bag)) for (const k of Object.keys(bag)) out[k] = bag[k];
  return out;
}

/**
 * Spans exported by `instrumentGuard` (`pca.decision`, `pca.verb`, `pca.resource`); `pca.param.<name>`, `pca.tenant` and
 * `pca.actor` attributes are read when the application adds them. Time comes from `startTimeUnixNano`, `startTime` (ms) or `at`.
 */
export function fromOtelSpans(spans: readonly unknown[], o: IngestOptions = {}): TraceSet {
  return collect([...spans], 'otel', o, (s) => {
    if (!isObj(s)) return s;
    const a = attrs(s.attributes as AttrBag);
    const params: Record<string, unknown> = {};
    for (const k of Object.keys(a)) if (k.startsWith('pca.param.')) params[k.slice(10)] = a[k];
    const nano = s.startTimeUnixNano;
    const at = nano !== undefined ? Number(String(nano)) / 1e6 : s.startTime !== undefined ? s.startTime : s.at;
    return { at, verb: a['pca.verb'], resource: a['pca.resource'], outcome: a['pca.decision'] ?? 'missing', params, tenant: a['pca.tenant'], actor: a['pca.actor'] };
  });
}

/** Detect the format of a text log and ingest it: receipts, a JSON array of spans, or JSONL. */
export function ingestText(text: string, format: 'auto' | 'receipts' | 'otel' | 'jsonl' = 'auto', o: IngestOptions = {}, observedText?: string): TraceSet {
  const t = text.trim();
  if (format === 'otel' || (format === 'auto' && t.startsWith('['))) {
    const j = JSON.parse(t) as unknown;
    return fromOtelSpans(Array.isArray(j) ? j : [j], o);
  }
  const first = t.split('\n')[0] ?? '';
  let looksReceipt = false;
  try { const f = JSON.parse(first) as Record<string, unknown>; looksReceipt = isObj(f) && 'prev' in f && 'hash' in f && 'actionDigest' in f; } catch { /* not json: the jsonl reader reports the line */ }
  if (format === 'receipts' || (format === 'auto' && looksReceipt)) return fromReceipts(parseReceiptJsonl(text), o, observedText === undefined ? undefined : parseObservedParams(observedText));
  return fromJsonl(text, o);
}
