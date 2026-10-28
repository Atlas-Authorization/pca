import { describe, expect, it } from 'vitest';
import { agent, atomicMemoryPcaStore, executeAuthorized, generateKeyPair, hashCanonical, memoryOperationStore, pcaHeaders, type Capability, type VerifyContext } from '@atlasauth/pca';
import { pcaHono } from './index';

// The README "Binding to the operation" sample, run as written (its free names are defined here).
const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: 'ins_acme' });
const grants = new Map<string, Capability>([[a.grant.id, a.grant]]);
let revoked = false;
const isRevoked = async () => revoked;
const myRevocationChecker = async (_ctx: VerifyContext) => ({ enforced: true as const, ok: !(await isRevoked()) });
const created: { body: unknown; idempotencyKey: string }[] = [];
const refunds = { create: async (body: unknown, o: { idempotencyKey: string }) => (created.push({ body, idempotencyKey: o.idempotencyKey }), { id: `re_${created.length}` }) };
void myRevocationChecker;
void isRevoked;

const app = { routes: [] as unknown[], post(_p: string, ...h: unknown[]) { this.routes = h; } };

const operations = memoryOperationStore();      // operation records; production: durableOperationStore or your DB

app.post(
  '/refunds',
  pcaHono({
    audience: 'ins_acme',
    resolveGrant: async (ref) => grants.get(ref) ?? null,
    budgetStore: atomicMemoryPcaStore(),         // production: a shared store (atomic `claim` or `withKeyLock`)
    hooks: { revocation: async () => ({ enforced: true, ok: !(await isRevoked()) }) },
    // what this route executes, from YOUR routing and the JSON body (never from the PCActn)
    operation: (req) => {
      const body = req.body as Record<string, unknown>; // the parsed JSON body
      return { verb: 'stripe.refund', resource: `charge:${String(body.chargeId)}`, params: body };
    },
    plan: 'single-step',                         // a one-step action: the grant alone limits it
    risk: () => ({ semanticDistance: 0, reversibility: 1, blastRadius: 0.05, taint: 0, confidence: 1 }), // the server prices the risk; any input left out counts as the worst case
  }),
  async (c) => {
    const body = await c.req.json();
    const out = await executeAuthorized(c.get('pca'), ({ idempotencyKey }) => refunds.create(body, { idempotencyKey }), {
      store: operations,
      recheck: async () => ({ ok: !(await isRevoked()) }),
    });
    return c.json(out, out.status === 'committed' ? 200 : 409);
  },
);

/** Sign a refund for `signed`, send `sent` as the JSON body. */
function request(signed: { chargeId: string; amount: number }, sent = signed) {
  const p = a.act('stripe.refund', `charge:${signed.chargeId}`, signed);
  return { headers: { ...pcaHeaders(p.encoded), 'content-type': 'application/json' }, body: sent, id: hashCanonical(p.pcactn) };
}

async function send(r: ReturnType<typeof request>): Promise<{ status: number; body: unknown }> {
  const [mw, handler] = app.routes as [(c: unknown, next: () => Promise<void>) => Promise<Response | void>, (c: unknown) => Promise<Response>];
  const headers = new Headers(r.headers);
  const vars = new Map<string, unknown>();
  const c = {
    req: { header: (n: string) => headers.get(n) ?? undefined, json: async () => r.body, method: 'POST', url: 'http://localhost/refunds' },
    set: (k: string, v: unknown) => void vars.set(k, v),
    get: (k: string) => vars.get(k),
    json: (b: unknown, status?: number) => new Response(JSON.stringify(b), { status: status ?? 200 }),
  };
  let handled: Response | undefined;
  const denied = await mw(c, async () => {
    handled = await handler(c);
  });
  const out = denied ?? handled;
  if (!out) throw new Error('no response');
  return { status: out.status, body: await out.json() };
}

describe('README: binding to the operation', () => {
  it('runs the refund once with the operation id as idempotency key; a replay and a rebound body never reach the handler', async () => {
    const ok = request({ chargeId: 'ch_1', amount: 50 });
    const first = await send(ok);
    expect([first.status, first.body]).toEqual([200, { status: 'committed', operationId: ok.id, result: { id: 're_1' }, replayed: false, recorded: true }]);
    expect(created).toEqual([{ body: { chargeId: 'ch_1', amount: 50 }, idempotencyKey: ok.id }]);
    expect((await send(ok)).status).toBe(403);
    const rebound = request({ chargeId: 'ch_2', amount: 50 }, { chargeId: 'ch_2', amount: 400 });
    expect((await send(rebound)).status).toBe(403);
    revoked = true;
    expect((await send(request({ chargeId: 'ch_3', amount: 5 }))).status).toBe(403);
    revoked = false;
    expect(created).toHaveLength(1);
  });
});
