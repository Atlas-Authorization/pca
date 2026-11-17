/** The HTTP face of the witness: four routes, JSON only, bounded bodies, no secrets in any response or log line. */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { Witness } from './witness';

export const MAX_BODY_BYTES = 256 * 1024;

const send = (res: ServerResponse, status: number, body: unknown): void => {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text), 'cache-control': 'no-store' });
  res.end(text);
};

function readBody(req: IncomingMessage): Promise<{ ok: true; text: string } | { ok: false; status: 400 | 413 }> {
  return new Promise((resolve) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        resolve({ ok: false, status: 413 });
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve({ ok: true, text: Buffer.concat(chunks).toString('utf8') }));
    req.on('error', () => resolve({ ok: false, status: 400 }));
  });
}

export function createWitnessServer(witness: Witness, log: (line: string) => void = () => undefined): Server {
  return createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', 'http://witness');
      const path = url.pathname;
      if (req.method === 'GET' && path === '/healthz') return send(res, 200, { ok: true });
      if (req.method === 'GET' && path === '/v1/key') return send(res, 200, { witness: witness.publicKey, logs: witness.configuredLogs() });
      const m = /^\/v1\/state\/([^/]+)\/([^/]+)$/.exec(path);
      if (req.method === 'GET' && m) {
        try {
          const s = await witness.state(decodeURIComponent(m[1]!), decodeURIComponent(m[2]!));
          return s ? send(res, 200, s) : send(res, 404, { error: 'unknown_log_or_no_head' });
        } catch {
          return send(res, 500, { error: 'state_unavailable' });
        }
      }
      if (req.method === 'POST' && path === '/v1/cosign') {
        if (!/^application\/json\b/i.test(req.headers['content-type'] ?? '')) return send(res, 415, { error: 'malformed_request', detail: 'content-type must be application/json' });
        const body = await readBody(req);
        if (!body.ok) return send(res, body.status, { error: 'malformed_request', detail: body.status === 413 ? 'body too large' : 'unreadable body' });
        let json: unknown;
        try {
          json = JSON.parse(body.text);
        } catch {
          return send(res, 400, { error: 'malformed_request', detail: 'body is not JSON' });
        }
        const r = await witness.cosign(json);
        log(`cosign status=${r.status}${r.status === 200 ? ` size=${r.body.head.size}` : ` error=${r.body.error}`}`);
        return send(res, r.status, r.body);
      }
      return send(res, path.startsWith('/v1/') || path === '/healthz' ? 405 : 404, { error: 'not_found' });
    })().catch(() => {
      if (!res.headersSent) send(res, 500, { error: 'internal' });
    });
  });
}
