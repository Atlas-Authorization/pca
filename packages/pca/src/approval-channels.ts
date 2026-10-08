/**
 * Approval-notification channels for PCA step-ups.
 *
 * `approvals.ts` is the HEADLESS core; this is the channel layer its docstring promises — "the approval
 * inbox (mobile push / Slack / web) renders". Given a pending {@link StepUpRequest} (which now carries
 * structured {@link GoalLineage}), each channel FORMATS a human-readable notification — action summary,
 * the "because you asked to …" goal lineage, and an approve/deny affordance or a link to the inbox — and
 * DISPATCHES it over an injected transport.
 *
 * Every channel shares one port, {@link ApprovalChannel}, and is registered the same way, so a new
 * channel (here: Slack) slots in beside the others. Channels are:
 *   - gated by config: an unconfigured channel reports `enabled: false` and never dispatches;
 *   - offline/testable: the HTTP transport is injected ({@link FetchLike}), defaulting to `globalThis.fetch`;
 *   - secret-free in their output: a returned {@link ApprovalDelivery} never carries the webhook URL,
 *     token, or signing secret, and nothing here logs.
 *
 * HONEST: a channel only *reports* a step-up the verifier already produced. It authorizes nothing.
 */

import type { StepUpRequest } from './approvals';
import { describeGoalLineage } from './approvals';

// ---- shared channel port --------------------------------------------------------------------------

export type ApprovalChannelKind = 'slack' | 'webhook' | 'email' | 'push' | 'sms';

/**
 * The minimal HTTP surface a channel needs, injected so channels stay offline-testable and free of any
 * DOM/Node `fetch` type dependency. The default adapter wraps `globalThis.fetch`.
 */
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string },
) => Promise<{ ok: boolean; status: number }>;

/** Context for a notification: where the human approves, and the clock. */
export interface ApprovalNotifyContext {
  /** Absolute URL of the approval inbox — the "open to approve or deny" link. */
  inboxUrl?: string;
  now?: number;
}

/** Outcome of one delivery attempt. Carries the formatted payload for inspection — never a secret. */
export interface ApprovalDelivery {
  kind: ApprovalChannelKind;
  /** The step-up this delivery was for. */
  requestId: string;
  /** True iff the channel accepted the notification for delivery. */
  delivered: boolean;
  /** The formatted, secret-free payload (Block Kit message, webhook body, text, …). */
  payload: unknown;
  /** HTTP status when the channel made a request. */
  status?: number;
  /** Why delivery did not happen (disabled, transport error, non-2xx). */
  reason?: string;
}

/** The common channel contract. Mirrors the repo's narrow `*Sender` port style. */
export interface ApprovalChannel {
  readonly kind: ApprovalChannelKind;
  /** True iff the channel is configured enough to deliver (the config gate). */
  readonly enabled: boolean;
  /** Format the step-up for this channel and dispatch it. Resolves (never rejects) with the outcome. */
  notify(request: StepUpRequest, ctx?: ApprovalNotifyContext): Promise<ApprovalDelivery>;
}

function defaultFetch(): FetchLike {
  const g = globalThis as unknown as { fetch?: FetchLike };
  const f = g.fetch;
  if (!f) {
    return () => Promise.reject(new Error('no fetch available: pass a FetchLike transport to the channel'));
  }
  return (url, init) => f(url, init);
}

// ---- human-readable formatting (shared by every channel) ------------------------------------------

/** One-line action summary: `verb on resource (tier N, risk R)`. */
export function actionSummary(request: StepUpRequest): string {
  return `${request.verb} on ${request.resource} (tier ${request.tier}, risk ${request.r.toFixed(2)})`;
}

/**
 * The goal-lineage lines a human reads to understand WHY: the "because you asked to …" sentence,
 * followed by the goal → authority → action chain. Derived purely from the request's own lineage.
 */
export function lineageLines(request: StepUpRequest): string[] {
  return [request.lineage.because, ...describeGoalLineage(request.lineage)];
}

// ---- Slack channel (Block Kit over an incoming webhook) -------------------------------------------

export interface SlackChannelConfig {
  /** Slack incoming-webhook URL. Absent/empty => the channel is disabled (config gate). */
  webhookUrl?: string;
  /** Injected transport (default: `globalThis.fetch`). */
  fetch?: FetchLike;
}

/** A Slack `section` block with Markdown text. */
interface SlackSectionBlock {
  type: 'section';
  text: { type: 'mrkdwn'; text: string };
}
/** A Slack `header` block (plain text). */
interface SlackHeaderBlock {
  type: 'header';
  text: { type: 'plain_text'; text: string; emoji: boolean };
}
/** A Slack `context` block (small print). */
interface SlackContextBlock {
  type: 'context';
  elements: { type: 'mrkdwn'; text: string }[];
}
/** A Slack `actions` block carrying link buttons. */
interface SlackActionsBlock {
  type: 'actions';
  elements: {
    type: 'button';
    text: { type: 'plain_text'; text: string; emoji: boolean };
    url: string;
    style?: 'primary' | 'danger';
    action_id: string;
  }[];
}
type SlackBlock = SlackHeaderBlock | SlackSectionBlock | SlackContextBlock | SlackActionsBlock;

/** A Block Kit message, as posted to an incoming webhook. */
export interface SlackMessage {
  /** Fallback/notification text (shown in the Slack notification + accessibility). */
  text: string;
  blocks: SlackBlock[];
}

/** Build the Block Kit message for a step-up — action summary, goal lineage, approve/deny affordance. */
export function buildSlackMessage(request: StepUpRequest, ctx: ApprovalNotifyContext = {}): SlackMessage {
  const blocks: SlackBlock[] = [
    { type: 'header', text: { type: 'plain_text', text: `Approval needed · tier ${request.tier}`, emoji: true } },
    { type: 'section', text: { type: 'mrkdwn', text: `*${request.verb}* on \`${request.resource}\`\n_${request.reason}_` } },
    { type: 'section', text: { type: 'mrkdwn', text: `*Why this is requested*\n${lineageLines(request).map((l) => `• ${l}`).join('\n')}` } },
  ];

  if (ctx.inboxUrl !== undefined && ctx.inboxUrl !== '') {
    const approveUrl = appendQuery(ctx.inboxUrl, { stepup: request.id, decision: 'approve' });
    const denyUrl = appendQuery(ctx.inboxUrl, { stepup: request.id, decision: 'deny' });
    blocks.push({
      type: 'actions',
      elements: [
        { type: 'button', text: { type: 'plain_text', text: 'Approve', emoji: true }, url: approveUrl, style: 'primary', action_id: 'pca_approve' },
        { type: 'button', text: { type: 'plain_text', text: 'Deny', emoji: true }, url: denyUrl, style: 'danger', action_id: 'pca_deny' },
      ],
    });
  } else {
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: `Approve or deny step-up \`${request.id}\` in your Atlas inbox.` }] });
  }

  return { text: `Approval needed: ${actionSummary(request)}`, blocks };
}

function appendQuery(url: string, params: Record<string, string>): string {
  const query = Object.entries(params)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
  return url.includes('?') ? `${url}&${query}` : `${url}?${query}`;
}

/** Slack approval channel. Disabled (and a no-op) unless a webhook URL is configured. */
export function slackApprovalChannel(config: SlackChannelConfig = {}): ApprovalChannel {
  const url = config.webhookUrl;
  const enabled = typeof url === 'string' && url.length > 0;
  const transport = config.fetch ?? defaultFetch();
  return {
    kind: 'slack',
    enabled,
    async notify(request, ctx) {
      const message = buildSlackMessage(request, ctx ?? {});
      if (!enabled || url === undefined) {
        return { kind: 'slack', requestId: request.id, delivered: false, payload: message, reason: 'slack channel not configured' };
      }
      try {
        const res = await transport(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(message) });
        return res.ok
          ? { kind: 'slack', requestId: request.id, delivered: true, payload: message, status: res.status }
          : { kind: 'slack', requestId: request.id, delivered: false, payload: message, status: res.status, reason: `slack webhook returned ${res.status}` };
      } catch (err) {
        return { kind: 'slack', requestId: request.id, delivered: false, payload: message, reason: err instanceof Error ? err.message : 'slack transport error' };
      }
    },
  };
}

// ---- webhook channel (signed JSON POST — the channel Slack mirrors) --------------------------------

export interface WebhookChannelConfig {
  /** Destination URL. Absent/empty => disabled. */
  url?: string;
  /** Injected transport (default: `globalThis.fetch`). */
  fetch?: FetchLike;
  /** Optional extra headers (e.g. a caller-computed signature header). Never logged. */
  headers?: Record<string, string>;
}

/** The webhook body: the step-up plus its pre-formatted human summary + lineage. */
export interface WebhookApprovalBody {
  type: 'pca.step_up.created';
  stepup: StepUpRequest;
  summary: string;
  lineage: string[];
  inbox_url?: string;
}

/** Build the webhook JSON body. */
export function buildWebhookBody(request: StepUpRequest, ctx: ApprovalNotifyContext = {}): WebhookApprovalBody {
  return {
    type: 'pca.step_up.created',
    stepup: request,
    summary: actionSummary(request),
    lineage: lineageLines(request),
    ...(ctx.inboxUrl !== undefined && ctx.inboxUrl !== '' ? { inbox_url: ctx.inboxUrl } : {}),
  };
}

/** Generic webhook approval channel — the existing-style channel Slack is modelled on. */
export function webhookApprovalChannel(config: WebhookChannelConfig = {}): ApprovalChannel {
  const url = config.url;
  const enabled = typeof url === 'string' && url.length > 0;
  const transport = config.fetch ?? defaultFetch();
  const headers = { 'content-type': 'application/json', ...(config.headers ?? {}) };
  return {
    kind: 'webhook',
    enabled,
    async notify(request, ctx) {
      const body = buildWebhookBody(request, ctx ?? {});
      if (!enabled || url === undefined) {
        return { kind: 'webhook', requestId: request.id, delivered: false, payload: body, reason: 'webhook channel not configured' };
      }
      try {
        const res = await transport(url, { method: 'POST', headers, body: JSON.stringify(body) });
        return res.ok
          ? { kind: 'webhook', requestId: request.id, delivered: true, payload: body, status: res.status }
          : { kind: 'webhook', requestId: request.id, delivered: false, payload: body, status: res.status, reason: `webhook returned ${res.status}` };
      } catch (err) {
        return { kind: 'webhook', requestId: request.id, delivered: false, payload: body, reason: err instanceof Error ? err.message : 'webhook transport error' };
      }
    },
  };
}

// ---- text channels (email / sms / push) over an injected sender -----------------------------------

/** Deliver a formatted text body. Returns a channel-native message id, or throws on failure. */
export type TextSender = (body: { subject: string; text: string }) => Promise<{ id?: string }>;

export interface TextChannelConfig {
  /** Injected sender (the existing per-instance mailer / SMS / push port). Absent => disabled. */
  send?: TextSender;
}

/** Build the plain-text body (subject + body) shared by email / sms / push surfaces. */
export function buildTextBody(request: StepUpRequest, ctx: ApprovalNotifyContext = {}): { subject: string; text: string } {
  const lines = [
    actionSummary(request),
    '',
    ...lineageLines(request),
  ];
  if (ctx.inboxUrl !== undefined && ctx.inboxUrl !== '') lines.push('', `Approve or deny: ${appendQuery(ctx.inboxUrl, { stepup: request.id })}`);
  return { subject: `Approval needed: ${request.verb} on ${request.resource}`, text: lines.join('\n') };
}

/** A text-formatter channel (email / sms / push) over an injected sender — same port as Slack/webhook. */
export function textApprovalChannel(kind: 'email' | 'sms' | 'push', config: TextChannelConfig = {}): ApprovalChannel {
  const send = config.send;
  const enabled = typeof send === 'function';
  return {
    kind,
    enabled,
    async notify(request, ctx) {
      const body = buildTextBody(request, ctx ?? {});
      if (!enabled || send === undefined) {
        return { kind, requestId: request.id, delivered: false, payload: body, reason: `${kind} channel not configured` };
      }
      try {
        await send(body);
        return { kind, requestId: request.id, delivered: true, payload: body };
      } catch (err) {
        return { kind, requestId: request.id, delivered: false, payload: body, reason: err instanceof Error ? err.message : `${kind} send error` };
      }
    },
  };
}

// ---- registry / dispatcher ------------------------------------------------------------------------

export interface ApprovalDispatcher {
  readonly channels: readonly ApprovalChannel[];
  /** Fan a step-up out to every ENABLED channel; collects one {@link ApprovalDelivery} per channel. */
  notifyAll(request: StepUpRequest, ctx?: ApprovalNotifyContext): Promise<ApprovalDelivery[]>;
}

/** Register a set of channels behind one dispatcher. Disabled channels are skipped at `notifyAll`. */
export function createApprovalDispatcher(channels: ApprovalChannel[]): ApprovalDispatcher {
  return {
    channels,
    async notifyAll(request, ctx) {
      const out: ApprovalDelivery[] = [];
      for (const channel of channels) {
        if (!channel.enabled) continue;
        out.push(await channel.notify(request, ctx));
      }
      return out;
    },
  };
}
