import { describe, expect, it } from 'vitest';
import { ADAPTER_ACCEPTANCE_EXPECTED, runAdapterAcceptance, type AcceptanceHarness, type AcceptanceObservation } from '@atlasauth/pca-testing';
import { withPCA } from './index';

/** Web plumbing: a real `Request` (headers, JSON body, method, absolute URL) through the wrapped handler. */
const harness: AcceptanceHarness = (options) => {
  let seen: Pick<AcceptanceObservation, 'operation'> | undefined;
  const route = withPCA(options, async (_req, { pca }) => {
    seen = pca.operation ? { operation: pca.operation } : {};
    return new Response('{"ok":true}', { status: 200 });
  });
  return async (r) => {
    seen = undefined;
    const res = await route(new Request(`http://localhost${r.path}`, { method: r.method, headers: r.headers, body: JSON.stringify(r.body) }));
    return { status: res.status, handlerRan: seen !== undefined, ...(seen ?? {}) };
  };
};

describe('withPCA (fetch): shared adapter acceptance matrix (operation option -> authorize)', () => {
  it('refuses over-limit, rebound, replayed and misconfigured requests before the handler; allows a valid one once', async () => {
    expect(await runAdapterAcceptance(harness)).toEqual(ADAPTER_ACCEPTANCE_EXPECTED);
  });
});
