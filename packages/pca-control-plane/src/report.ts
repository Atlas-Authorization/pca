/**
 * Report a pca-proxy audit log to the control plane. Each receipt becomes one event; batches are signed with the source key
 * and posted to `POST /v1/pca/control/events`. A small offset file next to the log remembers how many lines were sent, so
 * a restart never reports an event twice (the control plane de-duplicates only inside one batch).
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { signIngest } from './ingest';
import type { ControlEvent, Outcome } from './types';

export const REPORT_BATCH = 200;
/** Risk assigned to a call that the policy allowed, and to one it refused (or would refuse in observe mode). The receipt carries no risk score. */
export const RISK_ALLOWED = 0.1;
export const RISK_REFUSED = 0.6;

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);

/** One audit receipt as an event, or null when the line is not a receipt (it is skipped, never guessed). */
export function eventOfReceipt(line: unknown, o: { agent: string; session?: string }, observed?: ControlEvent['observed']): ControlEvent | null {
  if (!isObj(line)) return null;
  const { at, verb, resource, outcome, hash } = line;
  if (typeof at !== 'number' || !Number.isFinite(at) || typeof verb !== 'string' || typeof resource !== 'string' || typeof hash !== 'string' || hash.length === 0 || hash.length > 128) return null;
  const facts = isObj(line.checks) ? line.checks : {};
  const refused = outcome === 'deny' || facts.allowed === 'false';
  const out: Outcome = refused ? 'deny' : typeof facts.approval === 'string' ? 'executed' : 'auto';
  return {
    id: hash,
    at,
    agent: o.agent,
    ...(o.session !== undefined ? { session: o.session } : {}),
    verb: verb.slice(0, 256),
    resource: resource.slice(0, 512),
    outcome: out,
    r: refused ? RISK_REFUSED : RISK_ALLOWED,
    ...(facts.mode === 'observe' || facts.mode === 'enforce' ? { mode: facts.mode } : {}),
    ...(observed !== undefined ? { observed } : {}),
  };
}

export interface ReportOptions {
  file: string;
  source: string;
  /** The source's Ed25519 secret key. */
  secret: Uint8Array;
  agent: string;
  session?: string;
  /** API origin, e.g. https://api.atlasauth.net */
  url: string;
  /** An `sk_` secret key with `pca:write`. */
  apiKey: string;
  fetch?: typeof fetch;
  now?: () => number;
  out?: (s: string) => void;
}

/** The observed-parameters line of each receipt (by seq) from `<log>.params.jsonl`, when the proxy wrote one. The server checks the binding. */
function observedBySeq(file: string): Map<number, { params: Record<string, string | number | boolean>; omitted: string[] }> {
  const out = new Map<number, { params: Record<string, string | number | boolean>; omitted: string[] }>();
  const path = `${file}.params.jsonl`;
  if (!existsSync(path)) return out;
  for (const l of readFileSync(path, 'utf8').split('\n')) {
    if (l.trim() === '') continue;
    try {
      const x = JSON.parse(l) as { seq?: unknown; params?: unknown; omitted?: unknown };
      if (typeof x.seq === 'number' && isObj(x.params) && Array.isArray(x.omitted)) out.set(x.seq, { params: x.params as never, omitted: x.omitted as string[] });
    } catch {
      /* a torn last line is picked up on the next pass */
    }
  }
  return out;
}

/** The `observed` field for a receipt: its line plus the digest the receipt itself carries for it. */
export function observedFor(receipt: unknown, line: { params: Record<string, string | number | boolean>; omitted: string[] } | undefined): ControlEvent['observed'] | undefined {
  if (line === undefined || !isObj(receipt) || typeof receipt.seq !== 'number' || !isObj(receipt.checks)) return undefined;
  const { obs1, obs2 } = receipt.checks;
  if (typeof obs1 !== 'string' || typeof obs2 !== 'string') return undefined;
  return { seq: receipt.seq, params: line.params, omitted: line.omitted, digest: `${obs1}${obs2}` };
}

const offsetFile = (file: string) => `${file}.report`;
const readOffset = (file: string): number => {
  try {
    const n = Number(readFileSync(offsetFile(file), 'utf8').trim());
    return Number.isSafeInteger(n) && n >= 0 ? n : 0;
  } catch {
    return 0;
  }
};

let lastSeq = 0;
/** Strictly increasing and restart-safe: the time in microseconds, bumped when two batches share one. */
const nextSeq = (now: number): number => (lastSeq = Math.max(lastSeq + 1, now * 1000));

/** Send what has not been sent yet. Returns how many events were reported. Throws on a refusal (4xx) so a bad key or source is not retried forever. */
export async function reportOnce(o: ReportOptions): Promise<number> {
  const f = o.fetch ?? fetch;
  const now = o.now ?? Date.now;
  const out = o.out ?? (() => undefined);
  if (!existsSync(o.file)) return 0;
  const lines = readFileSync(o.file, 'utf8').split('\n').filter((l) => l.trim() !== '');
  let sent = readOffset(o.file);
  const observed = observedBySeq(o.file);
  let reported = 0;
  // the parameters line is written just after its receipt: a last receipt that promises one which has not arrived yet waits for the next pass
  let end = lines.length;
  try {
    const last = JSON.parse(lines[end - 1] ?? 'null') as { seq?: number; checks?: Record<string, unknown> } | null;
    if (last && typeof last.seq === 'number' && last.checks?.obs1 !== undefined && !observed.has(last.seq)) end -= 1;
  } catch {
    end -= 1;
  }
  while (sent < end) {
    const slice = lines.slice(sent, Math.min(end, sent + REPORT_BATCH));
    const events: ControlEvent[] = [];
    for (const l of slice) {
      try {
        const r = JSON.parse(l) as { seq?: number };
        const e = eventOfReceipt(r, o, observedFor(r, typeof r.seq === 'number' ? observed.get(r.seq) : undefined));
        if (e) events.push(e);
      } catch {
        /* a torn last line is picked up on the next pass */
      }
    }
    if (events.length > 0) {
      const seq = nextSeq(now());
      const envelope = signIngest(o.secret, { source: o.source, seq, sent_at: now(), events });
      const res = await f(`${o.url.replace(/\/+$/, '')}/v1/pca/control/events`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${o.apiKey}`, 'idempotency-key': `${o.source}-${seq}` },
        body: JSON.stringify({ envelope }),
      });
      if (res.status >= 400 && res.status < 500) throw new Error(`the control plane refused the batch (${res.status}): ${(await res.text()).slice(0, 200)}`);
      if (!res.ok) throw new Error(`the control plane is unavailable (${res.status})`);
      reported += events.length;
    }
    sent += slice.length;
    writeFileSync(offsetFile(o.file), `${sent}\n`);
    out(`reported ${reported} event(s)`);
  }
  return reported;
}

/** Report, and with `follow` keep watching the log until stopped. A transient failure is retried; a refusal ends the run. */
export async function report(o: ReportOptions & { follow?: boolean; pollMs?: number; sleep?: (ms: number) => Promise<void>; stop?: () => boolean }): Promise<number> {
  const sleep = o.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  let total = 0;
  for (;;) {
    try {
      total += await reportOnce(o);
    } catch (e) {
      if (!o.follow || /refused the batch/.test((e as Error).message)) throw e;
      (o.out ?? (() => undefined))(`retrying: ${(e as Error).message}`);
    }
    if (!o.follow || o.stop?.()) return total;
    await sleep(o.pollMs ?? 2_000);
  }
}
