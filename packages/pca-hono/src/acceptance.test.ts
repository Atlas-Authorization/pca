import { describe, expect, it } from 'vitest';
import { ADAPTER_ACCEPTANCE_EXPECTED, runAdapterAcceptance, type AcceptanceHarness } from '@atlasauth/pca-testing';
import { pcaHono, type PcaAttachment } from './index';

/** Hono plumbing: a context with `req.header` / `req.json` / `req.method` / `req.url`; the route handler is `next`. */
const harness: AcceptanceHarness = (options) => {
  const mw = pcaHono(options);
  return async (r) => {
    const headers = new Headers(r.headers);
    const vars = new Map<string, unknown>();
    let handlerRan = false;
    const c = {
      req: { header: (n: string) => headers.get(n) ?? undefined, json: async () => r.body, method: r.method, url: `http://localhost${r.path}` },
      set: (k: string, v: unknown) => void vars.set(k, v),
      json: (b: unknown, status?: number) => new Response(JSON.stringify(b), { status: status ?? 200 }),
    };
    const res = await mw(c, async () => { handlerRan = true; });
    const pca = vars.get('pca') as PcaAttachment | undefined;
    return { status: res ? res.status : 200, handlerRan, ...(pca?.operation ? { operation: pca.operation } : {}) };
  };
};

describe('pcaHono: shared adapter acceptance matrix (operation option -> authorize)', () => {
  it('refuses over-limit, rebound, replayed and misconfigured requests before the handler; allows a valid one once', async () => {
    expect(await runAdapterAcceptance(harness)).toEqual(ADAPTER_ACCEPTANCE_EXPECTED);
  });
});
