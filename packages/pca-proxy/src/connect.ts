/**
 * One-command connect. The dashboard's guided setup shows `pca-proxy mcp --observe --connect <token> -- <server>`. The token is a
 * single-use setup token (valid minutes, one instance, one setup run) whose only power is to register ONE source key. The proxy
 * makes that key itself, keeps it on this machine (mode 0600, next to the working directory), registers its PUBLIC half with the
 * token, gets back an ingest key (it can report events and nothing else), and from then on reports each decision as an event signed
 * with its source key and sent with the ingest key. The wire contract is `POST /v1/pca/control/connect` then `POST /v1/pca/control/events`. There is no key to paste and no second process.
 *
 * Reporting never blocks or changes a call: events are queued (bounded), sent in the background, retried on a network failure, and
 * dropped (with one warning) when the control plane refuses a batch.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { b64u, decodeKey, generateKeyPair, publicKeyOf, type Receipt } from '@atlasauth/pca';
import { eventOfReceipt, signIngest, type ControlEvent } from '@atlasauth/pca-control-plane';
import { ConfigError } from './config';

const PREFIX = 'pcs1.';
export const BATCH = 200;
export const QUEUE_MAX = 5000;
const FLUSH_MS = 1500;

export interface SetupToken {
  origin: string;
  instanceId: string;
  source: string;
}

/** What a token names (the secret part is not needed to read it). Throws ConfigError for anything that is not one. */
export function parseSetupToken(token: string): SetupToken {
  const bad = (why: string): never => {
    throw new ConfigError(`--connect: that is not a setup token (${why}). Make a new one in the dashboard.`);
  };
  if (!token.startsWith(PREFIX) || token.length > 600) return bad('wrong shape');
  let p: Record<string, unknown>;
  try {
    p = JSON.parse(Buffer.from(token.slice(PREFIX.length), 'base64url').toString('utf8')) as Record<string, unknown>;
  } catch {
    return bad('unreadable');
  }
  if (typeof p.o !== 'string' || typeof p.i !== 'string' || typeof p.s !== 'string' || typeof p.k !== 'string') return bad('incomplete');
  let u: URL;
  try {
    u = new URL(p.o);
  } catch {
    return bad('no API address');
  }
  const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]';
  if (u.protocol !== 'https:' && !(local && u.protocol === 'http:')) return bad('the API address is not https');
  return { origin: u.origin, instanceId: p.i, source: p.s };
}

interface Marker {
  v: 1;
  origin: string;
  instance_id: string;
  source: string;
  public_key: string;
  signer: string;
  ingest_key: string;
}

export interface Connection {
  origin: string;
  instanceId: string;
  source: string;
  secret: Uint8Array;
  publicKey: string;
  /** The `sk_` key (scope `pca:ingest`) the reports are sent with. */
  ingestKey: string;
  /** The guardian public key that signs issued grants (pin it as `agent.issuedGrant.signer`). */
  signer: string;
}

export interface ConnectDeps {
  fetch?: typeof fetch;
  log?: (s: string) => void;
}

const keyFile = (dir: string) => join(dir, 'source.key');
const markerFile = (dir: string) => join(dir, 'connection.json');

function readMarker(dir: string): Marker | undefined {
  try {
    const m = JSON.parse(readFileSync(markerFile(dir), 'utf8')) as Marker;
    return m.v === 1 && typeof m.public_key === 'string' && typeof m.source === 'string' && typeof m.ingest_key === 'string' ? m : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Register (first run: the token is needed) or resume (later runs: the saved connection is enough). The key is written BEFORE the
 * registration, so a crash between the two leaves the same key to retry with, and the server answers a retry of the same token
 * with the same key as it did the first time.
 */
export async function connect(o: { token?: string; dir: string } & ConnectDeps): Promise<Connection> {
  const f = o.fetch ?? fetch;
  const saved = readMarker(o.dir);
  if (saved !== undefined && existsSync(keyFile(o.dir))) {
    const tok = o.token !== undefined ? parseSetupToken(o.token) : undefined;
    // a new token for another source or instance means a new connection: do not silently report to the old one
    if (tok === undefined || (tok.instanceId === saved.instance_id && tok.source === saved.source)) {
      return { origin: saved.origin, instanceId: saved.instance_id, source: saved.source, secret: decodeKey(readFileSync(keyFile(o.dir), 'utf8').trim()), publicKey: saved.public_key, signer: saved.signer, ingestKey: saved.ingest_key };
    }
  }
  if (o.token === undefined) throw new ConfigError('--connect needs the setup token from the dashboard (once; later runs reuse the saved connection)');
  const tok = parseSetupToken(o.token);
  mkdirSync(o.dir, { recursive: true, mode: 0o700 });
  let secret: Uint8Array;
  if (existsSync(keyFile(o.dir)) && saved === undefined) secret = decodeKey(readFileSync(keyFile(o.dir), 'utf8').trim());
  else {
    secret = generateKeyPair().secretKey;
    writeFileSync(keyFile(o.dir), `${b64u(secret)}\n`, { mode: 0o600 });
  }
  const publicKey = b64u(publicKeyOf(secret));
  const res = await f(`${tok.origin}/v1/pca/control/connect`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: o.token, source: tok.source, public_key: publicKey, agent: tok.source }) });
  if (!res.ok) {
    const why = res.status === 401 ? 'the setup token was refused (it expires after ten minutes and works once): make a new one in the dashboard' : `the control plane answered ${res.status}`;
    throw new ConfigError(`--connect: ${why}`);
  }
  const body = (await res.json()) as { instance_id?: unknown; source?: unknown; signer?: unknown; ingest_key?: unknown };
  if (typeof body.source !== 'string' || typeof body.ingest_key !== 'string' || !body.ingest_key.startsWith('sk_') || (body.instance_id !== undefined && body.instance_id !== tok.instanceId)) throw new ConfigError('--connect: the control plane answered for a different setup');
  const signer = typeof body.signer === 'string' ? body.signer : '';
  const m: Marker = { v: 1, origin: tok.origin, instance_id: tok.instanceId, source: body.source, public_key: publicKey, signer, ingest_key: body.ingest_key };
  writeFileSync(markerFile(o.dir), `${JSON.stringify(m, null, 2)}\n`, { mode: 0o600 });
  (o.log ?? (() => undefined))(`connected as source ${body.source}; its key is in ${keyFile(o.dir)} (keep it private)`);
  return { origin: tok.origin, instanceId: tok.instanceId, source: body.source, secret, publicKey, signer, ingestKey: body.ingest_key };
}

type Observed = { params: Record<string, string | number | boolean>; omitted: string[]; digest: string };

/** Queue each receipt as an event and send them, signed with the registered key. */
export class Reporter {
  private queue: ControlEvent[] = [];
  private timer: ReturnType<typeof setTimeout> | undefined;
  private sending: Promise<void> = Promise.resolve();
  private lastSeq = 0;
  private warned = false;
  private closed = false;
  private readonly f: typeof fetch;
  private readonly log: (s: string) => void;
  private readonly now: () => number;

  constructor(private readonly c: Connection, o: ConnectDeps & { now?: () => number; agent?: string } = {}) {
    this.f = o.fetch ?? fetch;
    this.log = o.log ?? (() => undefined);
    this.now = o.now ?? Date.now;
    this.agent = o.agent ?? c.source;
  }
  private readonly agent: string;

  /** Hook this to `engine.onReceipt`. */
  push = (r: Receipt, obs?: Observed): void => {
    if (this.closed) return;
    const ev = eventOfReceipt(r, { agent: this.agent }, obs !== undefined ? { seq: r.seq, params: obs.params, omitted: obs.omitted, digest: obs.digest } : undefined);
    if (ev === null) return;
    if (this.queue.length >= QUEUE_MAX) {
      this.queue.shift();
      if (!this.warned) {
        this.warned = true;
        this.log('the control plane has been unreachable for a while: the oldest events are being dropped');
      }
    }
    this.queue.push(ev);
    if (this.timer === undefined) this.arm(FLUSH_MS);
  };

  private arm(ms: number): void {
    this.timer = setTimeout(() => void this.flush(), ms);
    this.timer.unref?.();
  }

  /** Send what is queued. Safe to call at any time; one send runs at a time. */
  flush(): Promise<void> {
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
    this.sending = this.sending.then(() => this.drain());
    return this.sending;
  }

  async close(): Promise<void> {
    await this.flush();
    this.closed = true;
  }

  private async drain(): Promise<void> {
    while (this.queue.length > 0) {
      const batch = this.queue.slice(0, BATCH);
      const seq = (this.lastSeq = Math.max(this.lastSeq + 1, this.now() * 1000));
      let status = 0;
      try {
        const envelope = signIngest(this.c.secret, { source: this.c.source, seq, sent_at: this.now(), events: batch });
        const res = await this.f(`${this.c.origin}/v1/pca/control/events`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${this.c.ingestKey}`, 'idempotency-key': `${this.c.source}-${seq}` }, body: JSON.stringify({ envelope }) });
        status = res.status;
        if (res.ok) {
          this.queue.splice(0, batch.length);
          this.warned = false;
          continue;
        }
      } catch {
        /* the network: retry below */
      }
      if (status >= 400 && status < 500 && status !== 429) {
        // refused (not for a reason that goes away): drop this batch, say so once, keep the proxy running
        this.queue.splice(0, batch.length);
        this.log(`the control plane refused a batch (${status}); those ${batch.length} event(s) were dropped`);
        continue;
      }
      // a failure that may pass: keep the queue, try again on the next tick
      if (this.timer === undefined && !this.closed) this.arm(5_000);
      return;
    }
  }
}
