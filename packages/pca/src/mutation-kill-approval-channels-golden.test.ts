/**
 * 0.4.2 mutation kills: what a human reads and what a webhook receives is a contract, so every formatter and every delivery outcome
 * of the approval channels is pinned against a reviewed golden (testdata/approval-channels-golden.json). Set GEN_GOLDEN=<path> to
 * regenerate it (and review the diff).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import {
  actionSummary, buildSlackMessage, buildTextBody, buildWebhookBody, createApprovalDispatcher, lineageLines,
  slackApprovalChannel, textApprovalChannel, webhookApprovalChannel,
} from './approval-channels';
import type { StepUpRequest } from './approvals';

const req = {
  id: 'su_1', verb: 'stripe.payout', resource: 'acct:1', params: { amount: 80 }, tier: 3, reason: 'risk 0.75 above theta2', goalCommit: 'G'.repeat(43),
  goal: 'process October payouts',
  lineage: { because: 'because you asked to process October payouts', chain: [{ label: 'Goal: process October payouts', detail: 'committed' }, { label: 'Authority: stripe.payout' }] },
  r: 0.754, requestedAt: 1,
} as unknown as StepUpRequest;
const req2 = { ...req, tier: 2, r: 1, lineage: { because: 'b', chain: [] } } as unknown as StepUpRequest;
const INBOX = 'https://app.example/inbox';
const ok = { ok: true, status: 200 };

async function scenarios(): Promise<unknown> {
  const sent: unknown[] = [];
  const f = (res: { ok: boolean; status: number }) => (url: string, init: unknown) => { sent.push({ url, init }); return Promise.resolve(res); };
  const out: Record<string, unknown> = {
    summary: [actionSummary(req), actionSummary(req2)],
    lineage: [lineageLines(req), lineageLines(req2)],
    slack: [buildSlackMessage(req), buildSlackMessage(req, { inboxUrl: INBOX }), buildSlackMessage(req2, { inboxUrl: `${INBOX}?x=1` }), buildSlackMessage(req, { inboxUrl: '' })],
    webhook: [buildWebhookBody(req), buildWebhookBody(req, { inboxUrl: INBOX }), buildWebhookBody(req, { inboxUrl: '' })],
    text: [buildTextBody(req), buildTextBody(req, { inboxUrl: INBOX }), buildTextBody(req2, { inboxUrl: `${INBOX}?x=1` }), buildTextBody(req, { inboxUrl: '' })],
  };
  const slackUrl = 'https://hooks.example/s';
  out.slackNotify = [
    await slackApprovalChannel({ webhookUrl: slackUrl, fetch: f(ok) as never }).notify(req, { inboxUrl: INBOX }),
    await slackApprovalChannel({ webhookUrl: slackUrl, fetch: f({ ok: false, status: 502 }) as never }).notify(req),
    await slackApprovalChannel({ webhookUrl: slackUrl, fetch: (() => Promise.reject(new Error('boom'))) as never }).notify(req),
    await slackApprovalChannel({ webhookUrl: slackUrl, fetch: (() => Promise.reject('str')) as never }).notify(req),
    await slackApprovalChannel({}).notify(req),
    await slackApprovalChannel({ webhookUrl: '' }).notify(req),
  ];
  out.slackEnabled = [slackApprovalChannel({}).enabled, slackApprovalChannel({ webhookUrl: '' }).enabled, slackApprovalChannel({ webhookUrl: slackUrl }).enabled];
  out.webhookNotify = [
    await webhookApprovalChannel({ url: 'https://w.example', headers: { 'x-sig': 's' }, fetch: f(ok) as never }).notify(req, { inboxUrl: INBOX }),
    await webhookApprovalChannel({ url: 'https://w.example', fetch: f({ ok: false, status: 500 }) as never }).notify(req),
    await webhookApprovalChannel({ url: 'https://w.example', fetch: (() => Promise.reject(new Error('down'))) as never }).notify(req),
    await webhookApprovalChannel({ url: 'https://w.example', fetch: (() => Promise.reject(7)) as never }).notify(req),
    await webhookApprovalChannel({}).notify(req),
  ];
  out.webhookEnabled = [webhookApprovalChannel({}).enabled, webhookApprovalChannel({ url: '' }).enabled, webhookApprovalChannel({ url: 'u' }).enabled];
  const texts: unknown[] = [];
  for (const kind of ['email', 'sms', 'push'] as const) {
    out[`${kind}Notify`] = [
      await textApprovalChannel(kind, { send: async (b) => { texts.push(b); return { id: 'm1' }; } }).notify(req, { inboxUrl: INBOX }),
      await textApprovalChannel(kind, { send: async () => { throw new Error('smtp'); } }).notify(req),
      await textApprovalChannel(kind, { send: async () => { throw 'x'; } }).notify(req),
      await textApprovalChannel(kind, {}).notify(req),
    ];
    out[`${kind}Enabled`] = [textApprovalChannel(kind, {}).enabled, textApprovalChannel(kind, { send: async () => ({}) }).enabled];
  }
  out.sent = sent;
  out.texts = texts;
  const disabled = slackApprovalChannel({});
  const d = createApprovalDispatcher([disabled, webhookApprovalChannel({ url: 'https://w.example', fetch: f(ok) as never }), textApprovalChannel('email', { send: async () => ({}) })]);
  out.dispatch = (await d.notifyAll(req, { inboxUrl: INBOX })).map((x) => [x.kind, x.delivered]);
  out.dispatchCount = [d.channels.length];
  return JSON.parse(JSON.stringify(out));
}

it('every formatter and delivery outcome is exactly the reviewed golden', async () => {
  const got = await scenarios();
  if (process.env.GEN_GOLDEN) writeFileSync(process.env.GEN_GOLDEN, JSON.stringify(got, null, 1) + '\n');
  expect(got).toEqual(JSON.parse(readFileSync(resolve(__dirname, '..', 'testdata', 'approval-channels-golden.json'), 'utf8')));
});
it('the default transport fails clearly when there is no fetch', async () => {
  const g = globalThis as { fetch?: unknown };
  const saved = g.fetch;
  g.fetch = undefined;
  try {
    const r = await webhookApprovalChannel({ url: 'https://w.example' }).notify(req);
    expect(r).toMatchObject({ delivered: false, reason: 'no fetch available: pass a FetchLike transport to the channel' });
  } finally {
    g.fetch = saved;
  }
});
