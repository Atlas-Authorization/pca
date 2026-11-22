import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { describe, expect, it, vi } from 'vitest';
import * as pca from '@atlasauth/pca';
import * as frost from '@atlasauth/pca/ext/frost';
import * as ledger from '@atlasauth/pca/ext/ledger';
import * as research from '@atlasauth/pca/ext/research';
import { verifyAction } from '../templates/express-rs/src/guard';
import { createServer } from '../../../examples/pca-quickstart/src/server';

/**
 * R6-CORE-04: every template must AUTHORIZE with the full server verifier (`verifyPCActn` / `requirePCA`: the grant from
 * the server's own store, predicates / limits / caveats, plan authorization, allowedSuites, server-decided time and
 * threshold). `verifyPCActnCore` alone checks only the proof's structure and signatures, so with the template's own
 * refund-only grant a compromised agent holding its own key got HTTP 200 for `stripe.delete_customer` and
 * `github.delete_repo`. Each template: the in-scope refund is allowed, an action outside the grant's scope is denied
 * (even when the principal has registered the plan root, so the denial is the SCOPE check, not plan authorization).
 */
const AUD = 'ins_quickstart';
const OUT_OF_SCOPE: ReadonlyArray<readonly [string, string, Record<string, unknown>]> = [
  ['stripe.delete_customer', 'cus_ALL', {}],
  ['github.delete_repo', 'repo:prod', {}],
];

function refundAgent() {
  const principal = pca.generateKeyPair();
  return pca.agent({ principal, goal: 'reconcile October refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
}

describe('R6-CORE-04 express-rs: the guard enforces the grant scope (full server verifier)', () => {
  function setup() {
    const a = refundAgent();
    const authorized = new Set<string>();
    const grants = {
      get: (ref: string) => (ref === a.grant.id ? a.grant : null),
      isPlanAuthorized: (ref: string, root: string) => ref === a.grant.id && authorized.has(root),
      isRevoked: () => false,
    };
    const cfg = { audience: AUD, grants, state: pca.memoryPcaStore() };
    return { a, authorized, cfg };
  }

  it('allows the in-scope $42 refund', async () => {
    const { a, authorized, cfg } = setup();
    const params = { amount: 42, currency: 'usd' };
    const { pcactn, encoded } = a.act('stripe.refund', 'charge:ch_123', params, { counter: 1 });
    authorized.add(pcactn.plan.root);
    const r = await verifyAction(encoded, cfg, { verb: 'stripe.refund', resource: 'charge:ch_123', params });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body['allow']).toBe(true);
  });

  for (const [verb, resource, params] of OUT_OF_SCOPE) {
    it(`denies ${verb} on a refund-only grant even with the plan root registered`, async () => {
      const { a, authorized, cfg } = setup();
      const { pcactn, encoded } = a.act(verb, resource, params, { counter: 1 });
      authorized.add(pcactn.plan.root);
      const r = await verifyAction(encoded, cfg, { verb, resource, params });
      expect(r.status).toBe(403);
      expect(r.body['allow']).toBe(false);
      expect(JSON.stringify(r.body)).toMatch(/no predicate permits/);
    });
  }

  it('denies an over-limit refund and a replayed counter', async () => {
    const { a, authorized, cfg } = setup();
    const big = { amount: 1_000_000, currency: 'usd' };
    const over = a.act('stripe.refund', 'charge:ch_123', big, { counter: 1 });
    authorized.add(over.pcactn.plan.root);
    expect((await verifyAction(over.encoded, cfg, { verb: 'stripe.refund', resource: 'charge:ch_123', params: big })).status).toBe(403);
    const ok = { amount: 42, currency: 'usd' };
    const once = a.act('stripe.refund', 'charge:ch_9', ok, { counter: 2 });
    authorized.add(once.pcactn.plan.root);
    expect((await verifyAction(once.encoded, cfg, { verb: 'stripe.refund', resource: 'charge:ch_9', params: ok })).status).toBe(200);
    expect((await verifyAction(once.encoded, cfg, { verb: 'stripe.refund', resource: 'charge:ch_9', params: ok })).status).not.toBe(200);
  });

  it('denies an unregistered plan root and a revoked grant', async () => {
    const { a, cfg } = setup();
    const params = { amount: 42, currency: 'usd' };
    const { encoded } = a.act('stripe.refund', 'charge:ch_123', params, { counter: 1 });
    expect((await verifyAction(encoded, cfg, { verb: 'stripe.refund', resource: 'charge:ch_123', params })).status).toBe(403);
    const { a: a2, authorized: auth2, cfg: cfg2 } = setup();
    const x = a2.act('stripe.refund', 'charge:ch_1', params, { counter: 1 });
    auth2.add(x.pcactn.plan.root);
    const revoked = { ...cfg2, grants: { ...cfg2.grants, isRevoked: () => true } };
    expect((await verifyAction(x.encoded, revoked, { verb: 'stripe.refund', resource: 'charge:ch_1', params })).status).toBe(403);
  });

  it('the guard source authorizes with the full verifier, never verifyPCActnCore', () => {
    const src = readFileSync(new URL('../templates/express-rs/src/guard.ts', import.meta.url), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '');
    expect(src).not.toMatch(/verifyPCActnCore/);
    expect(src).toMatch(/requirePCA\(/);
  });
});

describe('R6-CORE-04 pca-quickstart: requirePCA enforces the grant scope', () => {
  it('the template server is the example server (one source of truth)', () => {
    const t = readFileSync(new URL('../templates/pca-quickstart/src/server.ts', import.meta.url), 'utf8');
    const e = readFileSync(new URL('../../../examples/pca-quickstart/src/server.ts', import.meta.url), 'utf8');
    expect(t).toBe(e);
  });

  it('allows the in-scope refund and denies stripe.delete_customer / github.delete_repo', async () => {
    const a = refundAgent();
    a.provenance?.principal('refund charge ch_1, 42 usd'); // the user's request: the harness records it (provenance by default)
    const { app, authorize } = createServer({ grant: a.grant, audience: AUD });
    const server = app.listen(0);
    await new Promise<void>((res) => server.once('listening', () => res()));
    const { port } = server.address() as AddressInfo;
    const post = async (verb: string, resource: string, params: Record<string, unknown>, counter: number) => {
      const { pcactn, encoded, provenance } = a.act(verb, resource, params, { counter });
      authorize(pcactn.plan.root);
      const res = await fetch(`http://127.0.0.1:${port}/refunds`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ pcactn: encoded, pca_provenance: provenance, charge: resource.replace(/^charge:/, ''), params }) });
      return { status: res.status, body: (await res.json()) as unknown };
    };
    try {
      const ok = await post('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' }, 1);
      expect(ok.status, JSON.stringify(ok.body)).toBe(200);
      let c = 2;
      for (const [verb, resource, params] of OUT_OF_SCOPE) {
        const r = await post(verb, resource, params, c++);
        expect(r.status).toBe(403);
        expect(JSON.stringify(r.body)).toMatch(/no predicate permits/);
      }
    } finally {
      server.close();
    }
  });
});

describe('R6-CORE-04 node-quickstart: the offline verdict is the full verifier', () => {
  it('ALLOWs the in-scope refund and DENIEs an out-of-scope action (no predicate permits)', async () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as never);
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    try {
      await import('../templates/node-quickstart/src/index');
      await new Promise((r) => setTimeout(r, 800));
      expect(exit).not.toHaveBeenCalled();
      const out = log.mock.calls.flat().join('\n');
      expect(out).toMatch(/Valid action:\s+ALLOW/);
      expect(out).toMatch(/Out-of-scope action[^\n]*:\s+DENY/);
      expect(out).toMatch(/no predicate permits/);
    } finally {
      exit.mockRestore();
      log.mockRestore();
    }
    const src = readFileSync(new URL('../templates/node-quickstart/src/index.ts', import.meta.url), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '');
    expect(src).not.toMatch(/verifyPCActnCore/);
  });
});

describe('R6-CORE-04 pca-demo: the demo server (withPCA = requirePCA) enforces scope', () => {
  it('allows the in-plan refund and denies the action the grant never held', async () => {
    const story = (await import('../templates/pca-demo/story.mjs')) as { runStory: (o: unknown) => Promise<{ rows: Array<{ step: unknown; actual: string; reason: string }> }> };
    const fetchGuard = await import('../../pca-fetch/dist/index.js');
    const ui = { step: async () => undefined, info: () => undefined, wire: () => undefined, outcome: () => undefined };
    const res = await story.runStory({ pca: { ...pca, ...frost, ...ledger, ...research }, fetchGuard, ui }); // the demo uses the root and the extension subpaths
    const by = Object.fromEntries(res.rows.map((r) => [String(r.step), r]));
    expect(by['2']?.actual).toBe('ALLOWED');
    expect(by['8c']?.actual).toBe('DENIED');
    expect(by['8c']?.reason).toMatch(/no predicate permits/);
    const t = readFileSync(new URL('../templates/pca-demo/story.mjs', import.meta.url), 'utf8');
    const e = readFileSync(new URL('../../../examples/pca-demo/story.mjs', import.meta.url), 'utf8');
    expect(t).toBe(e);
  }, 60_000);
});
