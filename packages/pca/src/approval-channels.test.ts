import { describe, expect, it, vi } from 'vitest';
import {
  type ApprovalChannel,
  type FetchLike,
  buildSlackMessage,
  buildTextBody,
  buildWebhookBody,
  createApprovalDispatcher,
  slackApprovalChannel,
  textApprovalChannel,
  webhookApprovalChannel,
} from './approval-channels';
import { reviewAction, type StepUpRequest } from './approvals';
import { agent } from './facade';
import { generateKeyPair } from './keys';

const AUD = 'ins_test';
const mkAgent = () =>
  agent({
    principal: generateKeyPair(),
    goal: 'process October payouts',
    permissions: { stripe: ['payout'] },
    limits: { payout: '$100' },
    aud: AUD,
    riskPolicy: { theta1: 0.3, theta2: 0.6 },
    now: 0,
  });

/** A real pending step-up (tier >= 2) carrying goal-lineage, as the channels consume it. */
function pendingStepUp(): StepUpRequest {
  const r = reviewAction(mkAgent(), 'stripe.payout', 'acct:1', { amount: 80 }, { now: 1, goal: 'process October payouts' });
  if (r.kind !== 'step_up') throw new Error('expected a step_up');
  return r.request;
}

/** A FetchLike mock with a pinned result, usable as both the transport and a spy. */
function mockFetch(result: { ok: boolean; status: number }) {
  return vi.fn((_url: string, _init: { method: string; headers: Record<string, string>; body: string }) => Promise.resolve(result));
}

const SLACK_URL = 'https://hooks.slack.com/services/T000/B000/XXXXSECRETXXXX';

describe('slack approval channel', () => {
  it('formats a well-formed Block Kit message carrying the action summary + goal lineage + approve/deny links', () => {
    const req = pendingStepUp();
    const msg = buildSlackMessage(req, { inboxUrl: 'https://dash.atlas/inbox' });

    // fallback text + a header/section/section/actions block set
    expect(msg.text).toContain('stripe.payout on acct:1');
    expect(msg.blocks[0]?.type).toBe('header');
    const whyBlock = msg.blocks.find((b) => b.type === 'section' && b.text.text.includes('Why this is requested'));
    expect(whyBlock).toBeDefined();
    // the "because you asked to …" lineage sentence is present
    const flat = JSON.stringify(msg.blocks);
    expect(flat).toContain('because you asked to');
    expect(flat).toContain('process October payouts');
    // approve/deny affordance links to the inbox, scoped to this step-up
    const actions = msg.blocks.find((b) => b.type === 'actions');
    expect(actions).toBeDefined();
    if (actions && actions.type === 'actions') {
      expect(actions.elements.map((e) => e.action_id)).toEqual(['pca_approve', 'pca_deny']);
      expect(actions.elements[0]?.url).toContain(`stepup=${encodeURIComponent(req.id)}`);
      expect(actions.elements[0]?.url).toContain('decision=approve');
    }
  });

  it('dispatches the message to the configured webhook URL (mocked HTTP) and reports delivered', async () => {
    const req = pendingStepUp();
    const fetchMock = mockFetch({ ok: true, status: 200 });
    const channel = slackApprovalChannel({ webhookUrl: SLACK_URL, fetch: fetchMock });
    expect(channel.enabled).toBe(true);

    const out = await channel.notify(req, { inboxUrl: 'https://dash.atlas/inbox' });
    expect(out.delivered).toBe(true);
    expect(out.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const call = fetchMock.mock.calls[0];
    expect(call).toBeDefined();
    if (!call) throw new Error('transport was not called');
    const [url, init] = call;
    expect(url).toBe(SLACK_URL);
    expect(init.method).toBe('POST');
    expect(init.headers['content-type']).toBe('application/json');
    // body parses to a Block Kit message with the lineage
    const body = JSON.parse(init.body) as { blocks: unknown[]; text: string };
    expect(Array.isArray(body.blocks)).toBe(true);
    expect(JSON.stringify(body.blocks)).toContain('process October payouts');
  });

  it('is gated by config: no URL => disabled, never calls the transport, reports not delivered', async () => {
    const req = pendingStepUp();
    const fetchMock = mockFetch({ ok: true, status: 200 });
    const channel = slackApprovalChannel({ fetch: fetchMock });
    expect(channel.enabled).toBe(false);
    const out = await channel.notify(req);
    expect(out.delivered).toBe(false);
    expect(out.reason).toContain('not configured');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('never leaks the webhook secret URL into the returned delivery payload', async () => {
    const req = pendingStepUp();
    const out = await slackApprovalChannel({ webhookUrl: SLACK_URL, fetch: mockFetch({ ok: true, status: 200 }) }).notify(req);
    expect(JSON.stringify(out)).not.toContain('XXXXSECRETXXXX');
    expect(JSON.stringify(out)).not.toContain('hooks.slack.com');
  });

  it('reports a non-2xx response as not delivered without throwing', async () => {
    const req = pendingStepUp();
    const out = await slackApprovalChannel({ webhookUrl: SLACK_URL, fetch: mockFetch({ ok: false, status: 404 }) }).notify(req);
    expect(out.delivered).toBe(false);
    expect(out.status).toBe(404);
  });
});

describe('webhook + text channels (shared port)', () => {
  it('webhook channel POSTs a JSON body carrying the step-up, summary and lineage', async () => {
    const req = pendingStepUp();
    const body = buildWebhookBody(req, { inboxUrl: 'https://dash.atlas/inbox' });
    expect(body.type).toBe('pca.step_up.created');
    expect(body.lineage.join(' ')).toContain('process October payouts');

    const fetchMock = mockFetch({ ok: true, status: 202 });
    const out = await webhookApprovalChannel({ url: 'https://acme.example/hooks', fetch: fetchMock }).notify(req);
    expect(out.delivered).toBe(true);
    expect(out.status).toBe(202);
    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://acme.example/hooks');
  });

  it('text channel (email) formats subject + body with lineage and dispatches via the injected sender', async () => {
    const req = pendingStepUp();
    const text = buildTextBody(req);
    expect(text.subject).toContain('stripe.payout');
    expect(text.text).toContain('process October payouts');

    const send = vi.fn(() => Promise.resolve({ id: 'msg_1' }));
    const channel = textApprovalChannel('email', { send });
    expect(channel.enabled).toBe(true);
    const out = await channel.notify(req);
    expect(out.delivered).toBe(true);
    expect(send).toHaveBeenCalledTimes(1);
  });
});

describe('dispatcher', () => {
  it('fans a step-up out to enabled channels only and collects one delivery each', async () => {
    const req = pendingStepUp();
    const channels: ApprovalChannel[] = [
      slackApprovalChannel({ webhookUrl: SLACK_URL, fetch: mockFetch({ ok: true, status: 200 }) }),
      webhookApprovalChannel({ fetch: mockFetch({ ok: true, status: 200 }) }), // disabled: no url
      textApprovalChannel('sms'), // disabled: no sender
    ];
    const dispatcher = createApprovalDispatcher(channels);
    const out = await dispatcher.notifyAll(req, { inboxUrl: 'https://dash.atlas/inbox' });
    expect(out.map((d) => d.kind)).toEqual(['slack']); // only the enabled channel ran
    expect(out[0]?.delivered).toBe(true);
  });
});
