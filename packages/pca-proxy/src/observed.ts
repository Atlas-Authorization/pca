/**
 * The optional observed-parameters log: what an observe-mode run saw of the numeric and enumerable arguments, so
 * `pca autopilot` can learn amount caps from an audit log (a receipt alone carries only a digest of the arguments).
 *
 * Off by default, and only ever written in observe mode (the proxy refuses to start with it on in enforce mode). A parameter is
 * recorded only when its value cannot carry content: a safe integer, a boolean, or a short string from a declared closed enum.
 * Everything else is left out and only its NAME is listed. A parameter that is not `free` (money amounts are `material` by
 * default) is recorded only when the operator names it in `include`; a `critical` one never is, and neither is any parameter whose
 * role or tags say credential, personal data, a path, a query, code, a url or text, whatever `include` says.
 *
 * Each line names the receipt it belongs to and is hash-chained to the line before it. The binding also runs the other way: the
 * receipt carries the digest of its line's content in two facts, `obs1` and `obs2` (the 43-character digest split in two so a
 * fact is not mistaken for a secret and redacted), so the two files cannot be rewritten independently.
 */

import { existsSync, mkdirSync, appendFileSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { hashCanonicalLenient, type Receipt } from '@atlasauth/pca';
import { effectiveParamSensitivity, type ActionDef, type ParamDef } from '@atlasauth/pca-actions';

export interface ObservedLine {
  v: 1;
  seq: number;
  receipt: string;
  verb: string;
  resource: string;
  params: Record<string, string | number | boolean>;
  omitted: string[];
  prev: string;
  hash: string;
}

/** The digest the receipt carries: the line's content that does not depend on the receipt's own hash or the line before it. */
export function observedContentDigest(c: { seq: number; verb: string; resource: string; params: Record<string, unknown>; omitted: readonly string[] }): string {
  return hashCanonicalLenient({ d: 'pca-proxy/observed-content/v1', seq: c.seq, verb: c.verb, resource: c.resource, params: c.params, omitted: c.omitted });
}

/** The two receipt facts that bind a receipt to its line. */
export function bindingFacts(digest: string): { obs1: string; obs2: string } {
  return { obs1: digest.slice(0, 22), obs2: digest.slice(22) };
}

/** The hash of a line: the same object shape `observedHash` of `@atlasauth/pca-autopilot` computes. */
export function observedLineHash(r: Omit<ObservedLine, 'hash'>): string {
  return hashCanonicalLenient({ v: r.v, seq: r.seq, receipt: r.receipt, verb: r.verb, resource: r.resource, params: r.params, omitted: r.omitted, prev: r.prev });
}

const NEVER_ROLE = /^(credential|person|contact|party|path|query|code|url|text)\./;
const NEVER_TAG = new Set(['pii', 'phi', 'pci', 'secret', 'credential', 'free_text_outbound', 'code', 'path', 'sql']);
const MAX_PARAMS = 32;
const MAX_ENUM = 64;
const MAX_NAME = 64;

function valueAt(args: Record<string, unknown>, dotted: string): unknown {
  let cur: unknown = args;
  for (const seg of dotted.split('.')) {
    if (cur === null || typeof cur !== 'object' || Array.isArray(cur) || !Object.prototype.hasOwnProperty.call(cur, seg)) return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

/** Decide which of an action's validated arguments may be recorded. Pure. */
export function selectParams(def: ActionDef, args: unknown, include: readonly string[]): { params: Record<string, string | number | boolean>; omitted: string[] } {
  const params: Record<string, string | number | boolean> = {};
  const omitted: string[] = [];
  if (args === null || typeof args !== 'object' || Array.isArray(args)) return { params, omitted };
  const a = args as Record<string, unknown>;
  for (const [name, d] of Object.entries(def.params) as Array<[string, ParamDef]>) {
    const v = valueAt(a, name);
    if (v === undefined) continue;
    const skip = (): void => {
      if (omitted.length < 32 && name.length <= MAX_NAME) omitted.push(name);
    };
    if (d.role !== undefined && NEVER_ROLE.test(d.role)) {
      skip();
      continue;
    }
    if ((d.tags ?? []).some((t) => NEVER_TAG.has(t))) {
      skip();
      continue;
    }
    const sens = effectiveParamSensitivity(d);
    if (sens === 'critical' || (sens === 'material' && !include.includes(name))) {
      skip();
      continue;
    }
    if (d.type === 'integer' && typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0)) {
      if (Object.keys(params).length < MAX_PARAMS) params[name] = v;
      else skip();
    } else if (d.type === 'boolean' && typeof v === 'boolean') {
      if (Object.keys(params).length < MAX_PARAMS) params[name] = v;
      else skip();
    } else if (d.type === 'string' && d.values !== undefined && typeof v === 'string' && v.length <= MAX_ENUM && d.values.includes(v)) {
      if (Object.keys(params).length < MAX_PARAMS) params[name] = v;
      else skip();
    } else skip();
  }
  return { params, omitted };
}

/** Walk a line file: every line parses, links to the one before, and carries the hash of its own content. */
export function checkLines(lines: readonly ObservedLine[]): { ok: true } | { ok: false; reason: string } {
  let prev = '';
  let last = -1;
  for (const l of lines) {
    if (l === null || typeof l !== 'object' || l.v !== 1 || !Number.isSafeInteger(l.seq) || l.seq <= last || typeof l.hash !== 'string' || !Array.isArray(l.omitted)) return { ok: false, reason: `malformed or out-of-order line near seq ${String((l as { seq?: unknown })?.seq)}` };
    if (l.prev !== prev) return { ok: false, reason: `prev link mismatch at seq ${l.seq}` };
    const { hash, ...body } = l;
    if (observedLineHash(body) !== hash) return { ok: false, reason: `hash mismatch at seq ${l.seq} (edited line)` };
    prev = hash;
    last = l.seq;
  }
  return { ok: true };
}

export function readLines(path: string): ObservedLine[] {
  return readFileSync(path, 'utf8').split('\n').filter((l) => l.trim() !== '').map((l) => JSON.parse(l) as ObservedLine);
}

/**
 * Check a parameters file against the receipt log it belongs to, in both directions: the line chain is intact; each line names
 * the receipt at its seq (hash, verb, resource); the digest of the line's content equals the digest the receipt carries; and every
 * receipt that carries a digest has its line (a deleted line is found unless it is the very last one, which a crash can lose).
 */
export function verifyObserved(receipts: readonly Receipt[], lines: readonly ObservedLine[]): { ok: true; lines: number } | { ok: false; reason: string } {
  const c = checkLines(lines);
  if (!c.ok) return c;
  const bySeq = new Map(receipts.map((r) => [r.seq, r]));
  const have = new Set<number>();
  for (const l of lines) {
    const r = bySeq.get(l.seq);
    if (r === undefined || r.hash !== l.receipt || r.verb !== l.verb || r.resource !== l.resource) return { ok: false, reason: `line ${l.seq} does not belong to the receipt it names` };
    const f = r.checks ?? {};
    if (f.obs1 === undefined || f.obs2 === undefined || `${f.obs1}${f.obs2}` !== observedContentDigest(l)) return { ok: false, reason: `line ${l.seq} does not match the digest its receipt carries (the line was rewritten, or the receipt was)` };
    have.add(l.seq);
  }
  const lastLine = lines[lines.length - 1]?.seq ?? -1;
  for (const r of receipts) {
    if ((r.checks?.obs1 !== undefined || r.checks?.obs2 !== undefined) && !have.has(r.seq) && r.seq < lastLine) return { ok: false, reason: `receipt ${r.seq} carries a parameters digest but its line is missing` };
  }
  return { ok: true, lines: lines.length };
}

export class ObservedParamsLog {
  private prev = '';
  private last = -1;
  readonly include: readonly string[];

  constructor(private readonly path: string, include: readonly string[] = []) {
    this.include = include;
    if (existsSync(path)) {
      const lines = readLines(path);
      const c = checkLines(lines);
      if (!c.ok) throw new Error(`observed-parameters log ${path} is not an intact chain (${c.reason}); refusing to append to it`);
      const l = lines[lines.length - 1];
      if (l !== undefined) {
        this.prev = l.hash;
        this.last = l.seq;
      }
    } else mkdirSync(dirname(path), { recursive: true });
  }

  /** What would be written for this call, and the digest the receipt must carry. Undefined when there is nothing to record or omit. */
  prepare(def: ActionDef | undefined, args: unknown, seq: number, verb: string, resource: string): { params: Record<string, string | number | boolean>; omitted: string[]; digest: string } | undefined {
    if (def === undefined) return undefined;
    const { params, omitted } = selectParams(def, args, this.include);
    if (Object.keys(params).length === 0 && omitted.length === 0) return undefined;
    return { params, omitted, digest: observedContentDigest({ seq, verb, resource, params, omitted }) };
  }

  /** Append the line for a receipt that was just written. Throws when it cannot be written; the caller warns and carries on. */
  write(p: { params: Record<string, string | number | boolean>; omitted: string[] }, r: Receipt): void {
    if (r.seq <= this.last) throw new Error('the receipt is not newer than the last line');
    const body: Omit<ObservedLine, 'hash'> = { v: 1, seq: r.seq, receipt: r.hash, verb: r.verb, resource: r.resource, params: p.params, omitted: p.omitted, prev: this.prev };
    const line: ObservedLine = { ...body, hash: observedLineHash(body) };
    appendFileSync(this.path, `${JSON.stringify(line)}\n`, { mode: 0o600 });
    this.prev = line.hash;
    this.last = line.seq;
  }
}
