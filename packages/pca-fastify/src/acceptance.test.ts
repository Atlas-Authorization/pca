import { describe, expect, it } from 'vitest';
import { ADAPTER_ACCEPTANCE_EXPECTED, runAdapterAcceptance, type AcceptanceHarness } from '@atlasauth/pca-testing';
import { pcaFastify, type PcaAttachment } from './index';

/** Fastify plumbing: the preHandler either sends a reply (route skipped) or returns (route handler runs). */
const harness: AcceptanceHarness = (options) => {
  const pre = pcaFastify(options);
  return async (r) => {
    const req: Record<string, unknown> & { headers: Record<string, string> } = {
      headers: Object.fromEntries(Object.entries(r.headers).map(([k, v]) => [k.toLowerCase(), v])),
      body: r.body,
      method: r.method,
      url: r.path,
    };
    let status = 200;
    let sent = false;
    const reply = {
      code(c: number) { status = c; return reply; },
      header() { return reply; },
      send(b: unknown) { sent = true; return b; },
    };
    await pre(req as never, reply as never);
    const handlerRan = !sent;
    const pca = req.pca as PcaAttachment | undefined;
    return { status, handlerRan, ...(handlerRan && pca?.operation ? { operation: pca.operation } : {}) };
  };
};

describe('pcaFastify: shared adapter acceptance matrix (operation option -> authorize)', () => {
  it('refuses over-limit, rebound, replayed and misconfigured requests before the handler; allows a valid one once', async () => {
    expect(await runAdapterAcceptance(harness)).toEqual(ADAPTER_ACCEPTANCE_EXPECTED);
  });
});
