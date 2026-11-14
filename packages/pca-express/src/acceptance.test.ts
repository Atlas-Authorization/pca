import { describe, expect, it } from 'vitest';
import { ADAPTER_ACCEPTANCE_EXPECTED, runAdapterAcceptance, type AcceptanceHarness } from '@atlasauth/pca-testing';
import { pcaExpress, type PcaAttachment } from './index';

/** Express plumbing: lowercased header keys, parsed JSON body, method + originalUrl; the route handler is `next`. */
const harness: AcceptanceHarness = (options) => {
  const mw = pcaExpress(options);
  return async (r) => {
    const req: Record<string, unknown> & { headers: Record<string, string> } = {
      headers: Object.fromEntries(Object.entries(r.headers).map(([k, v]) => [k.toLowerCase(), v])),
      body: r.body,
      method: r.method,
      originalUrl: r.path,
      url: r.path,
    };
    let status = 200;
    let handlerRan = false;
    const res = {
      status(c: number) { status = c; return res; },
      set() { return res; },
      json(b: unknown) { return b; },
    };
    await mw(req as never, res as never, () => { handlerRan = true; });
    const pca = req.pca as PcaAttachment | undefined;
    return { status, handlerRan, ...(pca?.operation ? { operation: pca.operation } : {}) };
  };
};

describe('pcaExpress: shared adapter acceptance matrix (operation option -> authorize)', () => {
  it('refuses over-limit, rebound, replayed and misconfigured requests before the handler; allows a valid one once', async () => {
    expect(await runAdapterAcceptance(harness)).toEqual(ADAPTER_ACCEPTANCE_EXPECTED);
  });
});
