import { describe, expect, it } from 'vitest';
import { agent, decodePCActn, decodePcaHeader, generateKeyPair, hashCanonical, paramsDigest } from '@atlasauth/pca';
import { pcaFetch } from './index';

const mk = () => agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: 'mcp_test' });
const map = (tool: string, args: Record<string, unknown>) => (tool === 'refund' ? { verb: 'stripe.refund', resource: `charge:${String(args['chargeId'])}` } : null);

function recorder() {
  const seen: Array<{ url: unknown; headers: Headers }> = [];
  const f = (async (url: unknown, init?: { headers?: ConstructorParameters<typeof Headers>[0] }) => {
    seen.push({ url, headers: new Headers(init?.headers) });
    return new Response('{}');
  }) as unknown as typeof fetch;
  return { seen, f };
}

const rpc = (method: string, params?: unknown) => JSON.stringify({ jsonrpc: '2.0', id: 1, method, ...(params !== undefined ? { params } : {}) });

describe('pcaFetch', () => {
  it('adds a fresh PCA-Action for each tools/call, bound to the call', async () => {
    const a = mk();
    const { seen, f } = recorder();
    const wrapped = pcaFetch(a, map, { fetch: f });
    const args = { chargeId: 'ch_1', amount: 42 };
    await wrapped('http://x/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: rpc('tools/call', { name: 'refund', arguments: args }) });
    await wrapped('http://x/mcp', { method: 'POST', body: rpc('tools/call', { name: 'refund', arguments: args }) });
    const [h1, h2] = seen.map((s) => s.headers.get('PCA-Action'));
    expect(h1).toBeTruthy();
    expect(h2).toBeTruthy();
    expect(h1).not.toBe(h2);
    expect(seen[0]!.headers.get('content-type')).toBe('application/json');
    const p = decodePCActn(decodePcaHeader(h1!));
    expect(p.action.verb).toBe('stripe.refund');
    expect(p.action.resource).toBe('charge:ch_1');
    expect(p.action.params_digest).toBe(paramsDigest(args));
    expect(p.aud).toBe('mcp_test');
    expect(decodePCActn(decodePcaHeader(h2!)).counter).toBeGreaterThan(p.counter);
  });

  it('passes other requests, unmapped tools and non-JSON bodies through unchanged', async () => {
    const { seen, f } = recorder();
    const wrapped = pcaFetch(mk(), map, { fetch: f });
    await wrapped('http://x/mcp', { method: 'POST', body: rpc('initialize', {}) });
    await wrapped('http://x/mcp', { method: 'POST', body: rpc('tools/call', { name: 'other', arguments: {} }) });
    await wrapped('http://x/mcp', { method: 'POST', body: 'not json' });
    await wrapped('http://x/mcp', { method: 'GET' });
    await wrapped('http://x/mcp', { method: 'POST', body: JSON.stringify([{ method: 'tools/call', params: { name: 'refund' } }]) });
    expect(seen.map((s) => s.headers.get('PCA-Action'))).toEqual([null, null, null, null, null]);
  });

  it('provenance by default: the bundle rides with the proof and every tools/call response is recorded as untrusted', async () => {
    const a = mk();
    a.provenance!.principal('Refund 42 on ch_1');
    const { seen, f } = recorder();
    const wrapped = pcaFetch(a, map, { fetch: f });
    await wrapped('http://x/mcp', { method: 'POST', body: rpc('tools/call', { name: 'refund', arguments: { chargeId: 'ch_1', amount: 42 } }) });
    expect(seen[0]!.headers.get('PCA-Provenance')).toBeTruthy();
    expect(a.provenance!.receipts().map((r) => `${r.origin}:${r.source}`)).toEqual(['principal:user', 'action:stripe.refund', 'tool:refund']);
    expect(a.provenance!.receipts().at(-1)!.content_digest).toBe(hashCanonical('{}'));
  });

  it('honours an audience override', async () => {
    const { seen, f } = recorder();
    await pcaFetch(mk(), map, { fetch: f, aud: 'other_server' })('http://x', { method: 'POST', body: rpc('tools/call', { name: 'refund', arguments: { chargeId: 'c' } }) });
    expect(decodePCActn(decodePcaHeader(seen[0]!.headers.get('PCA-Action')!)).aud).toBe('other_server');
  });
});
