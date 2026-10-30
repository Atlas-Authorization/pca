import { describe, expect, it } from 'vitest';
import { agent, atomicMemoryPcaStore, executeAuthorized, generateKeyPair, hashCanonical, memoryOperationStore, pcaHeaders, type Capability, type VerifyContext } from '@atlasauth/pca';
import { pcaFastify, type PcaAttachment } from './index';

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

const operations = memoryOperationStore();        // operation records; production: durableOperationStore or your DB

app.post(
  '/refunds',
  {
    preHandler: pcaFastify({
      audience: 'ins_acme',
      resolveGrant: async (ref) => grants.get(ref) ?? null,
      budgetStore: atomicMemoryPcaStore(),         // production: a shared store (atomic `claim` or `withKeyLock`)
      hooks: { revocation: myRevocationChecker },
      // what this route executes, from YOUR routing and the parsed body (never from the PCActn)
      operation: (req) => ({ verb: 'stripe.refund', resource: `charge:${(req.body as any).chargeId}`, params: req.body as any }),
      plan: 'single-step',                         // a one-step action: the grant alone limits it
      risk: () => ({ semanticDistance: 0, reversibility: 1, blastRadius: 0.05, taint: 0, confidence: 1 }), // the server prices the risk; any input left out counts as the worst case
    }),
  },
  async (req, reply) => {
    const pca = (req as unknown as { pca: PcaAttachment }).pca; // { verdict, pcactn, operation }
    const out = await executeAuthorized(pca, ({ idempotencyKey }) => refunds.create(req.body, { idempotencyKey }), {
      store: operations,
      recheck: async () => ({ ok: !(await isRevoked()) }),
    });
    return reply.code(out.status === 'committed' ? 200 : 409).send(out);
  },
);

/** Sign a refund for `signed`, send `sent` as the JSON body. */
function request(signed: { chargeId: string; amount: number }, sent = signed) {
  a.provenance!.principal(`Refund ${signed.amount} on charge ${signed.chargeId}`); // the user's request: the action derives from it
  const p = a.act('stripe.refund', `charge:${signed.chargeId}`, signed);
  return { headers: { ...pcaHeaders(p.encoded, p.provenance), 'content-type': 'application/json' }, body: sent, id: hashCanonical(p.pcactn) };
}

async function send(r: ReturnType<typeof request>): Promise<{ status: number; body: unknown }> {
  const [{ preHandler }, handler] = app.routes as [{ preHandler: (req: unknown, reply: unknown) => Promise<void> }, (req: unknown, reply: unknown) => Promise<unknown>];
  const req: Record<string, unknown> = { headers: Object.fromEntries(Object.entries(r.headers).map(([k, v]) => [k.toLowerCase(), v])), body: r.body, method: 'POST', url: '/refunds' };
  let status = 200;
  let body: unknown;
  let sent = false;
  const reply = { code(c: number) { status = c; return reply; }, header() { return reply; }, send(b: unknown) { sent = true; body = b; return reply; } };
  await preHandler(req, reply);
  if (!sent) await handler(req, reply);
  return { status, body };
}
void (undefined as unknown as PcaAttachment);

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
