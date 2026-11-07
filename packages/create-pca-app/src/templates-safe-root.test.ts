import { describe, expect, it, vi } from 'vitest';
import type { AddressInfo } from 'node:net';
import * as pca from '@atlasauth/pca';
import { verifyAction } from '../templates/express-rs/src/guard';
import { createServer } from '../../../examples/pca-quickstart/src/server';

/**
 * R5-B1: a template must never use a grant (or `cap_chain[0]`) that arrives with the request as the trusted
 * root. A pure-PQ root that names the victim principal as `issuer` but is signed with the attacker's own ML-DSA
 * key verifies against ITSELF; only a server-decided root (own store / pins / allowedSuites) refuses it.
 */
const AUD = 'ins_quickstart';
/** The express-rs guard config: grants from the server's own store (plus authorized plan roots), replay/budget state. */
const rsCfg = (grant: pca.Capability | null, plans: ReadonlySet<string> = new Set()) => ({
  audience: AUD,
  state: pca.memoryPcaStore(),
  grants: {
    get: (ref: string) => (grant && ref === grant.id ? grant : null),
    isPlanAuthorized: (_ref: string, root: string) => plans.has(root),
    isRevoked: () => false,
  },
});

function attack() {
  const victim = pca.generateKeyPair();
  const real = pca.agent({ principal: victim, goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
  const vPub = pca.encodeKey(victim.publicKey);
  const atk = pca.generateKeyPair();
  const aPub = pca.encodeKey(atk.publicKey);
  const aMl = pca.mlDsa65Keygen(new Uint8Array(32).fill(9));
  const plan = [{ id: 'n', verb: 'stripe.refund', resource: 'charge:ch_1', reversibility_class: 'reversible' as const }];
  const forged = pca.mintRoot({ principalSecret: atk.secretKey, principalPublic: vPub, holder: aPub, caveats: [{ type: 'ttl', secs: 3600 }], suite: { alg: 'ml-dsa-65', mlDsa: aMl } });
  const actn = pca.buildPCActn({ grant: forged, chain: [forged], plan, nodeId: 'n', counter: 1, signerSecret: atk.secretKey, aud: AUD, now: Date.now() });
  return { real, forged, actn, vPub };
}

/** The operation the forged proof claims (verb, resource, no params), as the route would name it. */
const FORGED_OP = { verb: 'stripe.refund', resource: 'charge:ch_1', params: {} };

describe('R5-B1: templates never take the trusted root from the request', () => {
  it('control: the OLD express-rs shape (grant lifted from the artifact) accepts the forged pure-PQ root', async () => {
    const { forged, actn } = attack();
    const r = await pca.verifyPCActnCore(actn, { insecureSkipPlanRootCheck: true, grant: forged, audience: AUD });
    expect(r.allow).toBe(true); // this is the vulnerability the templates must not reproduce
  });

  it('express-rs: the forged pure-PQ root is refused (grant comes from the server store)', async () => {
    const { real, forged, actn } = attack();
    const r = await verifyAction(pca.encodePCActn(actn), rsCfg(real.grant), FORGED_OP);
    expect([401, 403]).toContain(r.status);
    expect(r.body['allow']).toBe(false);
    expect(forged.id).not.toBe(real.grant.id);
  });

  it('express-rs: still refused if the operator registered nothing, and a legitimate action still passes', async () => {
    const { real, actn } = attack();
    const empty = await verifyAction(pca.encodePCActn(actn), rsCfg(null), FORGED_OP);
    expect([401, 403]).toContain(empty.status);
    const params = { amount: 42, currency: 'usd' };
    const { pcactn, encoded } = real.act('stripe.refund', 'charge:ch_1', params, { counter: 1 });
    const ok = await verifyAction(encoded, rsCfg(real.grant, new Set([pcactn.plan.root])), { verb: 'stripe.refund', resource: 'charge:ch_1', params });
    expect(ok.status).toBe(200);
  });

  it('express-rs: allowedSuites refuses a pure-PQ artifact even when its grant IS registered', async () => {
    const { forged, actn } = attack();
    const r = await verifyAction(pca.encodePCActn(actn), rsCfg(forged, new Set([actn.plan.root])), FORGED_OP);
    expect([401, 403]).toContain(r.status);
    expect(r.body['allow']).toBe(false);
  });

  it('express-rs: the server source never reads a grant from the request', async () => {
    const { readFileSync } = await import('node:fs');
    const src = ['server.ts', 'guard.ts'].map((f) => readFileSync(new URL(`../templates/express-rs/src/${f}`, import.meta.url), 'utf8')).join('\n').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    expect(src).not.toMatch(/PCA-Grant|cap_chain\[0\]/);
  });

  it('pca-quickstart: the forged pure-PQ root is denied over HTTP (resolveGrant is a server lookup)', async () => {
    const { real, actn } = attack();
    const { app } = createServer({ grant: real.grant, audience: AUD });
    const server = app.listen(0);
    await new Promise<void>((res) => server.once('listening', () => res()));
    const { port } = server.address() as AddressInfo;
    try {
      const res = await fetch(`http://127.0.0.1:${port}/refunds`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ pcactn: pca.encodePCActn(actn), charge: 'ch_1', params: {} }) });
      expect(res.ok).toBe(false);
      expect([401, 403]).toContain(res.status);
    } finally {
      server.close();
    }
  });

  it('node-quickstart: runs end to end, including its own forged-root refusal step', async () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as never);
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    try {
      await import('../templates/node-quickstart/src/index');
      await new Promise((r) => setTimeout(r, 500));
      expect(exit).not.toHaveBeenCalled();
      expect(log.mock.calls.flat().join('\n')).toMatch(/forged/i);
    } finally {
      exit.mockRestore();
      log.mockRestore();
    }
  });
});
