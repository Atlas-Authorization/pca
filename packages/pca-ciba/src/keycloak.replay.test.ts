/**
 * Offline replay of the committed real-Keycloak transcripts (fixtures/keycloak-ciba-transcripts.json).
 * The OP's recorded answers are served to the client, so the client's mapping of real provider replies
 * (pending, slow_down, access_denied, expired_token, error bodies) is checked on every run without a
 * Keycloak. Provenance of the capture is in fixtures/PROVENANCE.json.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, reviewAction } from '@atlasauth/pca';
import { CibaProviderError, createCibaClient } from './index';

const PKG = join(__dirname, '..');
const FILE = 'keycloak-ciba-transcripts.json';
interface Exchange { label: string; request: { method: string; url: string; headers: Record<string, string>; body: string }; response: { status: number; body: string } }
const raw = readFileSync(join(PKG, 'fixtures', FILE));
const T = JSON.parse(raw.toString('utf8')) as { provider: string; version: string; exchanges: Exchange[] };

function stepUp() {
  const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['payout'] }, limits: { payout: '$100' }, aud: 'x', riskPolicy: { theta1: 0.3, theta2: 0.6 }, now: 0 });
  const r = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 80, currency: 'USD', payee: 'bob' }, { insecureUnboundApproval: true, now: 1, goal: 'g' });
  if (r.kind !== 'step_up') throw new Error('expected step_up');
  return r.request;
}

const find = (label: string, pred: (e: Exchange) => boolean): Exchange => {
  const e = T.exchanges.find((x) => x.label === label && pred(x));
  if (!e) throw new Error(`transcript lacks ${label}`);
  return e;
};
const reply = (e: Exchange): Response => new Response(e.response.body, { status: e.response.status, headers: { 'content-type': 'application/json' } });

describe('Keycloak transcripts (recorded from a real provider)', () => {
  it('are the file whose sha256 PROVENANCE.json records, with no credentials or tokens in them', () => {
    const prov = JSON.parse(readFileSync(join(PKG, 'fixtures', 'PROVENANCE.json'), 'utf8')) as { files: { file: string; sha256: string }[] };
    expect(prov.files.find((f) => f.file === FILE)?.sha256).toBe(createHash('sha256').update(raw).digest('hex'));
    const text = raw.toString('utf8');
    expect(text).not.toMatch(/eyJ[A-Za-z0-9_-]{10,}/);
    expect(text).not.toContain('pca-ciba-test-secret');
    expect(text).not.toContain('alice-pass');
    expect(T.provider).toBe('keycloak');
  });

  it('the client turns the recorded provider replies into the right outcomes', async () => {
    const authOk = find('poll-approve', (e) => e.request.url.endsWith('/ext/ciba/auth') && e.response.status === 200);
    const pending = find('poll-approve', (e) => e.response.body.includes('authorization_pending'));
    const slow = find('poll-approve', (e) => e.response.body.includes('slow_down'));
    const approved = find('poll-approve', (e) => e.response.body.includes('"access_token"'));
    const queue = [pending, slow, approved];
    const sleeps: number[] = [];
    let now = 0;
    const client = createCibaClient({ allowInsecureHttp: true,
      backchannelAuthenticationEndpoint: 'http://op/auth',
      tokenEndpoint: 'http://op/token',
      clientId: 'c',
      clientSecret: 's',
      fetch: (async (url: string) => (url.endsWith('/auth') ? reply(authOk) : reply(queue.shift() as Exchange))) as unknown as typeof fetch,
      sleep: async (ms) => { sleeps.push(ms); now += ms; },
      now: () => now,
    });
    const flow = await client.initiate(stepUp(), { loginHint: 'alice', bindingMessage: { tokenOnly: true }, stepUpScope: false });
    const poller = client.poller(flow);
    const r = await poller.wait();
    expect(r.status).toBe('approved');
    expect(sleeps.slice(2)).toEqual([flow.intervalSec * 1000 + 5000]); // one slow_down -> +5s
  });

  it('denial and expiry transcripts map to denied / expired, and provider errors keep their codes', async () => {
    for (const [label, needle, status] of [['deny-cancelled', 'access_denied', 'denied'], ['deny-unauthorized', 'access_denied', 'denied']] as const) {
      const authOk = find(label, (e) => e.request.url.endsWith('/ext/ciba/auth') && e.response.status === 200);
      const tok = find(label, (e) => e.response.body.includes(needle));
      let now = 0;
      const c = createCibaClient({ allowInsecureHttp: true,
        backchannelAuthenticationEndpoint: 'http://op/auth', tokenEndpoint: 'http://op/token', clientId: 'c', clientSecret: 's',
        fetch: (async (url: string) => (url.endsWith('/auth') ? reply(authOk) : reply(tok))) as unknown as typeof fetch,
        sleep: async (ms) => { now += ms; }, now: () => now,
      });
      expect((await c.poller(await c.initiate(stepUp(), { loginHint: 'alice' })).poll()).status).toBe(status);
    }
    const expired = find('expiry', (e) => e.response.body.includes('expired_token'));
    const authOk = find('expiry', (e) => e.request.url.endsWith('/ext/ciba/auth') && e.response.status === 200);
    let now = 0;
    const c = createCibaClient({ allowInsecureHttp: true,
      backchannelAuthenticationEndpoint: 'http://op/auth', tokenEndpoint: 'http://op/token', clientId: 'c', clientSecret: 's',
      fetch: (async (url: string) => (url.endsWith('/auth') ? reply(authOk) : reply(expired))) as unknown as typeof fetch,
      sleep: async (ms) => { now += ms; }, now: () => now,
    });
    const p = c.poller(await c.initiate(stepUp(), { loginHint: 'alice' }));
    now = 1; // before the local deadline, so the provider's expired_token is what ends the flow
    expect((await p.poll()).status).toBe('expired');

    const badBm = T.exchanges.find((e) => e.response.body.includes('invalid_binding_message'));
    expect(badBm).toBeDefined();
    const bad = createCibaClient({ allowInsecureHttp: true,
      backchannelAuthenticationEndpoint: 'http://op/auth', tokenEndpoint: 'http://op/token', clientId: 'c', clientSecret: 's',
      fetch: (async () => reply(badBm as Exchange)) as unknown as typeof fetch,
    });
    await expect(bad.initiate(stepUp(), { loginHint: 'alice' })).rejects.toBeInstanceOf(CibaProviderError);
    await expect(bad.initiate(stepUp(), { loginHint: 'alice' })).rejects.toMatchObject({ error: 'invalid_binding_message', status: 400 });
  });
});
