/**
 * 0.4.2 r11 mutation kills (approval-channels.ts): a channel whose config is present but unusable (an empty webhook url, a
 * sender that is not a function) is NOT configured - notify reports that and never touches the transport / sender.
 */
import { describe, expect, it } from 'vitest';
import { textApprovalChannel, webhookApprovalChannel } from './approval-channels';
import type { StepUpRequest } from './approvals';

const req = {
  id: 'su_11', verb: 'stripe.payout', resource: 'acct:1', params: { amount: 80 }, tier: 3, reason: 'risk', goalCommit: 'G'.repeat(43),
  goal: 'g', lineage: { because: 'b', chain: [] }, r: 0.5, requestedAt: 1,
} as unknown as StepUpRequest;

describe('r11: present-but-unusable channel config is "not configured"', () => {
  it('webhook with an empty url: no transport call, reported as not configured', async () => {
    const calls: unknown[] = [];
    const fetch = async (...a: unknown[]) => {
      calls.push(a);
      return { ok: true, status: 200 };
    };
    const ch = webhookApprovalChannel({ url: '', fetch: fetch as never });
    expect(ch.enabled).toBe(false);
    const out = await ch.notify(req);
    expect(out).toMatchObject({ kind: 'webhook', requestId: 'su_11', delivered: false, reason: 'webhook channel not configured' });
    expect(calls).toEqual([]);
  });
  it('text channel with a non-function sender: reported as not configured, not as a send error', async () => {
    for (const kind of ['email', 'sms', 'push'] as const) {
      for (const send of [null, 'smtp://x', {}]) {
        const ch = textApprovalChannel(kind, { send: send as never });
        expect(ch.enabled).toBe(false);
        const out = await ch.notify(req);
        expect(out).toMatchObject({ kind, requestId: 'su_11', delivered: false, reason: `${kind} channel not configured` });
      }
    }
  });
});
