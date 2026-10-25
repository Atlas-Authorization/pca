/**
 * 0.4.2 mutation kills (Stryker run 39706550807): the default transport is the real globalThis.fetch (forwarding url and init),
 * the channel `kind` is part of the contract, and an absent inbox URL leaves no `inbox_url` key at all (not an undefined one).
 */
import { describe, expect, it } from 'vitest';
import { buildWebhookBody, slackApprovalChannel, textApprovalChannel, webhookApprovalChannel } from './approval-channels';
import type { StepUpRequest } from './approvals';

const req = {
  id: 'su_9', verb: 'stripe.payout', resource: 'acct:1', params: { amount: 80 }, tier: 3, reason: 'risk', goalCommit: 'G'.repeat(43),
  goal: 'g', lineage: { because: 'b', chain: [] }, r: 0.5, requestedAt: 1,
} as unknown as StepUpRequest;

describe('approval channels: default transport and shape', () => {
  it('a channel built without a transport delivers through globalThis.fetch, passing the url and init through', async () => {
    const g = globalThis as { fetch?: unknown };
    const saved = g.fetch;
    const calls: Array<[unknown, unknown]> = [];
    g.fetch = (url: unknown, init: unknown) => {
      calls.push([url, init]);
      return Promise.resolve({ ok: true, status: 200 });
    };
    try {
      const slack = await slackApprovalChannel({ webhookUrl: 'https://hooks.example/s' }).notify(req);
      const hook = await webhookApprovalChannel({ url: 'https://w.example/h' }).notify(req);
      expect(slack).toMatchObject({ kind: 'slack', delivered: true });
      expect(hook).toMatchObject({ kind: 'webhook', delivered: true });
    } finally {
      g.fetch = saved;
    }
    expect(calls.map((c) => c[0])).toEqual(['https://hooks.example/s', 'https://w.example/h']);
    for (const c of calls) expect(c[1]).toMatchObject({ method: 'POST', headers: { 'content-type': 'application/json' } });
  });
  it('every channel reports its kind, enabled or not', () => {
    expect(slackApprovalChannel({}).kind).toBe('slack');
    expect(slackApprovalChannel({ webhookUrl: 'https://h.example' }).kind).toBe('slack');
    expect(webhookApprovalChannel({}).kind).toBe('webhook');
    expect(textApprovalChannel('email', {}).kind).toBe('email');
  });
  it('without an inbox URL the webhook body has no inbox_url key (not even an undefined one); with one it does', () => {
    for (const ctx of [undefined, {}, { inboxUrl: undefined }, { inboxUrl: '' }]) {
      const body = buildWebhookBody(req, ctx as never);
      expect(Object.keys(body)).not.toContain('inbox_url');
      expect('inbox_url' in body).toBe(false);
    }
    expect(buildWebhookBody(req, { inboxUrl: 'https://app.example/i' })).toHaveProperty('inbox_url', 'https://app.example/i');
  });
});
