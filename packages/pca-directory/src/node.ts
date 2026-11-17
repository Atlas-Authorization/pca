/**
 * Node-only parts: an HTTP server for a log or a witness, file-backed durable state, and the loop a witness runs to follow logs.
 * Import from `@atlasauth/pca-directory/node`. The main entry stays free of node built-ins so it runs in a browser.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { join } from 'node:path';
import { b64u, generateKeyPair, unb64u } from '@atlasauth/pca';
import type { SignedTreeHead, ConsistencyProof, WitnessCosignature } from '@atlasauth/pca/ext/ledger';
import { httpLogClient, postCosignature, type HttpLogClientOptions } from './client';
import type { SignedKeyTransition as Transition } from './rotation';
import { MemoryDirectoryStore, type DirectoryLog, type StoredEntry } from './log';
import { directoryRoutes, type RouteOptions } from './routes';
import type { SignedKeyTransition } from './rotation';
import type { Witness, WitnessLogState, WitnessState } from './witness';

const MAX_BODY = 128 * 1024;

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const c of req) {
    n += (c as Buffer).length;
    if (n > MAX_BODY) throw new Error('body too large');
    chunks.push(c as Buffer);
  }
  if (n === 0) return undefined;
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const s = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'access-control-allow-origin': '*', 'content-length': Buffer.byteLength(s) });
  res.end(s);
}

function adapt(handler: (r: { method: string; path: string; query: Record<string, string | undefined>; body?: unknown; submitter: string }) => Promise<{ status: number; body: unknown }>): Server {
  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://x');
      let body: unknown;
      if (req.method === 'POST') {
        try {
          body = await readBody(req);
        } catch {
          return send(res, 400, { error: 'bad body' });
        }
      }
      const out = await handler({ method: req.method ?? 'GET', path: url.pathname, query: Object.fromEntries(url.searchParams), body, submitter: req.socket.remoteAddress ?? 'unknown' });
      send(res, out.status, out.body);
    } catch {
      send(res, 500, { error: 'internal error' });
    }
  });
}

/** Serve a log over HTTP. Reads are public; put your own authentication in front of POST /entries if the log is not open. */
export function serveLog(log: DirectoryLog, o: RouteOptions & { port: number; host?: string }): Promise<Server> {
  const server = adapt(directoryRoutes(log, o));
  return new Promise((resolve) => server.listen(o.port, o.host ?? '127.0.0.1', () => resolve(server)));
}

/** A durable store for one process: entries and cosignatures are appended to JSON-lines files under `dir`. */
export class FileDirectoryStore extends MemoryDirectoryStore {
  private constructor(private readonly dir: string) {
    super();
  }
  static async open(dir: string): Promise<FileDirectoryStore> {
    mkdirSync(dir, { recursive: true });
    const s = new FileDirectoryStore(dir);
    const ef = join(dir, 'entries.jsonl');
    if (existsSync(ef)) for (const line of readFileSync(ef, 'utf8').split('\n')) if (line) await MemoryDirectoryStore.prototype.append.call(s, JSON.parse(line) as StoredEntry);
    const cf = join(dir, 'cosignatures.jsonl');
    if (existsSync(cf)) for (const line of readFileSync(cf, 'utf8').split('\n')) if (line) {
      const c = JSON.parse(line) as { size: number; root: string; cosig: WitnessCosignature };
      await MemoryDirectoryStore.prototype.addCosignature.call(s, c.size, c.root, c.cosig);
    }
    const tf = join(dir, 'transitions.jsonl');
    if (existsSync(tf)) for (const line of readFileSync(tf, 'utf8').split('\n')) if (line) await MemoryDirectoryStore.prototype.addTransition.call(s, JSON.parse(line) as SignedKeyTransition);
    return s;
  }
  override async addTransition(t: SignedKeyTransition): Promise<void> {
    const had = (await this.transitions()).some((x) => x.seq === t.seq);
    await super.addTransition(t);
    if (!had) appendFileSync(join(this.dir, 'transitions.jsonl'), `${JSON.stringify(t)}\n`);
  }
  override async append(row: StoredEntry): Promise<boolean> {
    if (!(await super.append(row))) return false;
    appendFileSync(join(this.dir, 'entries.jsonl'), `${JSON.stringify(row)}\n`);
    return true;
  }
  override async addCosignature(size: number, root: string, cosig: WitnessCosignature): Promise<void> {
    await super.addCosignature(size, root, cosig);
    appendFileSync(join(this.dir, 'cosignatures.jsonl'), `${JSON.stringify({ size, root, cosig })}\n`);
  }
}

/** Witness state in one JSON file, replaced atomically on every change. */
export class FileWitnessState implements WitnessState {
  private m: Record<string, WitnessLogState>;
  constructor(private readonly path: string) {
    this.m = existsSync(path) ? (JSON.parse(readFileSync(path, 'utf8')) as Record<string, WitnessLogState>) : {};
  }
  async get(g: string) {
    return this.m[g];
  }
  async set(g: string, s: WitnessLogState) {
    this.m = { ...this.m, [g]: s };
    writeFileSync(`${this.path}.tmp`, JSON.stringify(this.m), { mode: 0o600 });
    renameSync(`${this.path}.tmp`, this.path);
  }
}

/** Read a 32-byte secret key from a file holding its base64url form, or create one (mode 0600) and return it. */
export function loadOrCreateSecret(path: string): { secret: Uint8Array; created: boolean } {
  if (existsSync(path)) {
    const secret = unb64u(readFileSync(path, 'utf8').trim());
    if (secret.length !== 32) throw new Error(`${path}: not a 32-byte base64url secret key`);
    return { secret, created: false };
  }
  const { secretKey } = generateKeyPair();
  writeFileSync(path, b64u(secretKey), { mode: 0o600 });
  return { secret: secretKey, created: true };
}

/**
 * Serve a witness: `POST /add-checkpoint` with `{ sth, proof? }` answers `{ cosignature }` or 4xx with the reason and what the
 * witness knows (`known`), so a log that is behind can send the proof from there. `GET /info` names the key.
 */
export function serveWitness(w: Witness, o: { port: number; host?: string }): Promise<Server> {
  const server = adapt(async (r) => {
    if (r.method === 'GET' && r.path === '/info') return { status: 200, body: { object: 'pca_directory_witness', key: w.publicKey } };
    if (r.method === 'POST' && r.path === '/add-checkpoint') {
      const b = r.body as { sth?: SignedTreeHead; proof?: ConsistencyProof } | null;
      if (!b || typeof b !== 'object' || !b.sth) return { status: 400, body: { error: 'sth is required' } };
      const out = await w.cosign(b.sth, b.proof);
      if (out.ok) return { status: 200, body: { object: 'pca_directory_cosignature', cosignature: out.cosignature, size: out.size, root: out.root } };
      const status = out.reason === 'unknown_log' ? 404 : out.reason === 'proof_required' || out.reason === 'stale_state' ? 409 : out.reason === 'bad_head' || out.reason === 'bad_proof' ? 422 : 409;
      return { status, body: { error: out.reason, ...(out.known ? { known: out.known } : {}) } };
    }
    return { status: 404, body: { error: 'not found' } };
  });
  return new Promise((resolve) => server.listen(o.port, o.host ?? '127.0.0.1', () => resolve(server)));
}

export interface FollowedLog {
  /** Base URL of the log's directory routes. */
  url: string;
  guardian: string;
}

/**
 * One pass of the witness loop: for each log, fetch its head, build the consistency proof from what this witness last cosigned,
 * cosign, and post the cosignature back to the log. Returns one line per log for the operator's log output.
 */
export async function witnessOnce(w: Witness, state: WitnessState, logs: readonly FollowedLog[], o: HttpLogClientOptions = {}): Promise<string[]> {
  const out: string[] = [];
  for (const l of logs) {
    try {
      const client = httpLogClient(l.url, o);
      const sth = await client.sth();
      const prev = await state.get(l.guardian);
      const proof = prev && sth.size > prev.size && prev.size > 0 ? await client.consistency(prev.size, sth.size) : undefined;
      const r = await w.cosign(sth, proof);
      if (!r.ok) {
        out.push(`${l.url}: refused (${r.reason})`);
        continue;
      }
      const posted = await postCosignature(l.url, r.size, r.root, r.cosignature, o);
      out.push(`${l.url}: cosigned size ${r.size}${posted ? '' : ' (log did not accept it)'}`);
      out.push(...(await witnessRotation(w, l, o)));
    } catch (e) {
      out.push(`${l.url}: ${e instanceof Error ? e.message : 'error'}`);
    }
  }
  return out;
}

/** If the log has a key transition waiting, cosign it (the witness must already have cosigned the head it hands over) and post it back. */
async function witnessRotation(w: Witness, l: FollowedLog, o: HttpLogClientOptions): Promise<string[]> {
  const f = o.fetch ?? ((globalThis as { fetch?: NonNullable<HttpLogClientOptions['fetch']> }).fetch as NonNullable<HttpLogClientOptions['fetch']>);
  const base = l.url.replace(/\/+$/, '');
  const res = await f(`${base}/rotation`, { headers: { accept: 'application/json', ...(o.headers ?? {}) } });
  if (res.status === 404) return [];
  if (!res.ok) return [`${l.url}: rotation lookup failed (HTTP ${res.status})`];
  const t = ((await res.json()) as { transition?: Transition }).transition;
  if (!t) return [];
  const r = await w.cosignTransition(t);
  if (!r.ok) return [`${l.url}: key transition refused (${r.reason})`];
  const post = await f(`${base}/rotation/cosignatures`, { method: 'POST', headers: { 'content-type': 'application/json', ...(o.headers ?? {}) }, body: JSON.stringify({ cosignature: r.cosignature }) });
  return [`${l.url}: cosigned key transition ${t.seq}${post.ok ? '' : ' (log did not accept it)'}`];
}
