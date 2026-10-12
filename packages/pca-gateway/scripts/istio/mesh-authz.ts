/**
 * In-mesh PCA check service for the Istio CUSTOM-provider test. Bundled with esbuild and run as a plain
 * `node` pod (no image build, no Docker). One process, two listeners:
 *   :8000  Envoy HTTP ext_authz check endpoint (envoyExtAuthz) -- what Istio's envoyExtAuthzHttp calls
 *   :8001  TEST-ONLY admin: GET /mint?aud=&verb=&tamper=1 returns a PCA-Action header value for a fresh
 *          agent and registers its grant; GET /checks returns the requests Istio's Envoy actually sent.
 */
import { createServer } from 'node:http';
import { agent, generateKeyPair, pcaHeaders, PCA_HEADER, decodePCActn, decodePcaHeader, type Capability } from '@atlasauth/pca';
import { envoyExtAuthz, memoryReplayGuard } from '../../src/index';

const AUD = process.env.PCA_AUDIENCE ?? 'ins_acme';
const grants = new Map<string, Capability>();
const seen: Array<{ method: string; url: string; headers: Record<string, string | string[] | undefined> }> = [];

const check = envoyExtAuthz({
  audience: AUD,
  bindRequest: false, // conformance harness: unbound proofs
  routes: [
    { method: 'POST', path: '/refunds', capability: { verb: 'stripe.refund' } },
    { method: 'POST', path: '/payouts', capability: { verb: 'stripe.payout' } },
  ],
  resolveGrant: async (ref) => grants.get(ref) ?? null,
  replayGuard: memoryReplayGuard(),
});

createServer((req, res) => {
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers[k] = v;
  seen.push({ method: req.method ?? '', url: req.url ?? '', headers: req.headers });
  check({ method: req.method ?? '', path: req.url ?? '/', headers }).then(
    (out) => {
      res.writeHead(out.status, out.headers);
      res.end(out.body);
    },
    () => {
      res.writeHead(503);
      res.end('check failed');
    },
  );
}).listen(8000, '0.0.0.0');

createServer((req, res) => {
  const u = new URL(req.url ?? '/', 'http://x');
  if (u.pathname === '/mint') {
    const aud = u.searchParams.get('aud');
    const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
    const { encoded, pcactn } = a.act(u.searchParams.get('verb') ?? 'stripe.refund', 'charge:ch_1', { amount: 20, currency: 'usd' }, { counter: 1, ...(aud ? { aud } : {}) });
    grants.set(pcactn.grant_ref, a.grant as Capability);
    let value = pcaHeaders(encoded)[PCA_HEADER] as string;
    if (u.searchParams.get('tamper')) {
      const o = decodePCActn(decodePcaHeader(value)) as unknown as { action: { resource: string } };
      o.action.resource = 'charge:ch_EVIL';
      value = Buffer.from(JSON.stringify(o)).toString('base64url');
    }
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(value);
  } else if (u.pathname === '/checks') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(seen));
  } else {
    res.writeHead(404);
    res.end();
  }
}).listen(8001, '0.0.0.0');
