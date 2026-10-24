import { verifyIntentRequired, type ActionSchemaKey, type ApprovalDelivery, type FetchLike, type SignedIntentRequired, type TextChannelConfig, type WebhookChannelConfig } from '@atlasauth/pca';
import { cleanText } from './card';

/**
 * QUESTION DELIVERY over the existing approval-channel transports (`@atlasauth/pca` approval-channels: the webhook
 * `FetchLike`, and the email / sms / push `TextSender`). A delivery only tells the principal's device that a question is
 * waiting and hands it the SIGNED question. It never carries a rendered card, agent text, the map, or p:
 *
 *   - a site question carries the site-signed `pca-intent-required` body exactly as received (coordinates, not text);
 *     the device re-verifies it and renders the card itself from fixed templates;
 *   - a wallet-originated question (an agent clarification) carries only its session and question id;
 *   - canaries get no delivery of their own: they wait in the queue with the real question and are shown beside it,
 *     so a notification never reveals which question is a canary.
 *
 * Text surfaces (email, SMS, push) use one fixed template: "<site> has a question about your request", where the site
 * name is the wallet's verified display name, plus the inbox link. Slack is deliberately NOT offered: a shared
 * workspace would expose the principal's pending decisions to other members.
 */

export type QuestionChannelKind = 'webhook' | 'email' | 'sms' | 'push';

export type QuestionNotice =
  | { type: 'pca.intent.question'; session: string; question_id: string; site: string; friction: SignedIntentRequired['friction']; expires_at: number; intent_required: SignedIntentRequired; inbox_url?: string }
  | { type: 'pca.intent.clarification'; session: string; question_id: string; inbox_url?: string };

export interface NoticeContext {
  /** The site's discovery keys: the body is re-verified before anything is sent (signed payloads only). */
  keys: readonly ActionSchemaKey[];
  /** The site origin as verified from discovery. */
  site: string;
  now: number;
  inboxUrl?: string;
}

/** A notice for a site-signed question. Throws when the signature or expiry does not verify (nothing unsigned leaves). */
export function siteQuestionNotice(ir: SignedIntentRequired, ctx: NoticeContext): QuestionNotice {
  const v = verifyIntentRequired(ir, ctx.keys, ctx.now);
  if (!v.ok) throw new Error(`siteQuestionNotice: ${v.reason}`);
  return {
    type: 'pca.intent.question',
    session: ir.session,
    question_id: ir.question_id,
    site: ctx.site,
    friction: ir.friction,
    expires_at: ir.expires_at,
    intent_required: ir,
    ...(ctx.inboxUrl ? { inbox_url: ctx.inboxUrl } : {}),
  };
}

/** A notice for a wallet-originated question (clarification): ids only. */
export function clarificationNotice(session: string, questionId: string, inboxUrl?: string): QuestionNotice {
  return { type: 'pca.intent.clarification', session, question_id: questionId, ...(inboxUrl ? { inbox_url: inboxUrl } : {}) };
}

export interface QuestionDelivery extends Omit<ApprovalDelivery, 'kind' | 'requestId'> {
  kind: QuestionChannelKind;
  questionId: string;
}

export interface QuestionChannel {
  readonly kind: QuestionChannelKind;
  readonly enabled: boolean;
  notify(notice: QuestionNotice): Promise<QuestionDelivery>;
}

function defaultFetch(): FetchLike {
  const f = (globalThis as unknown as { fetch?: FetchLike }).fetch;
  return f ? (url, init) => f(url, init) : () => Promise.reject(new Error('no fetch available: pass a FetchLike transport'));
}

/** Webhook delivery (the principal's own wallet push endpoint): the JSON notice, signed question included. */
export function questionWebhookChannel(config: WebhookChannelConfig = {}): QuestionChannel {
  const url = config.url;
  const enabled = typeof url === 'string' && url.length > 0;
  const transport = config.fetch ?? defaultFetch();
  const headers = { 'content-type': 'application/json', ...(config.headers ?? {}) };
  return {
    kind: 'webhook',
    enabled,
    async notify(notice) {
      const base = { kind: 'webhook' as const, questionId: notice.question_id, payload: notice };
      if (!enabled || url === undefined) return { ...base, delivered: false, reason: 'webhook channel not configured' };
      try {
        const res = await transport(url, { method: 'POST', headers, body: JSON.stringify(notice) });
        return res.ok ? { ...base, delivered: true, status: res.status } : { ...base, delivered: false, status: res.status, reason: `webhook returned ${res.status}` };
      } catch (err) {
        return { ...base, delivered: false, reason: err instanceof Error ? err.message : 'webhook transport error' };
      }
    },
  };
}

/** The fixed text of a text-surface notice. */
export function questionText(notice: QuestionNotice, siteName: string): { subject: string; text: string } {
  const who = notice.type === 'pca.intent.question' ? cleanText(siteName, 64) || 'A site' : 'Your agent';
  const subject = notice.type === 'pca.intent.question' ? `${who} has a question about your request` : `${who} needs a decision about your request`;
  const link = notice.inbox_url ? `${notice.inbox_url}${notice.inbox_url.includes('?') ? '&' : '?'}question=${encodeURIComponent(notice.question_id)}` : null;
  return { subject, text: [subject, '', link ? `Open your wallet to answer: ${link}` : 'Open your wallet to answer.'].join('\n') };
}

/** Email / SMS / push delivery through the existing per-instance sender port (fixed text only). */
export function questionTextChannel(kind: 'email' | 'sms' | 'push', config: TextChannelConfig & { siteName: string }): QuestionChannel {
  const send = config.send;
  const enabled = typeof send === 'function';
  return {
    kind,
    enabled,
    async notify(notice) {
      const body = questionText(notice, config.siteName);
      const base = { kind, questionId: notice.question_id, payload: body };
      if (!enabled || send === undefined) return { ...base, delivered: false, reason: `${kind} channel not configured` };
      try {
        await send(body);
        return { ...base, delivered: true };
      } catch (err) {
        return { ...base, delivered: false, reason: err instanceof Error ? err.message : `${kind} send error` };
      }
    },
  };
}

export interface QuestionDispatcher {
  readonly channels: readonly QuestionChannel[];
  notifyAll(notice: QuestionNotice): Promise<QuestionDelivery[]>;
}

/** Fan a notice out to every enabled channel (disabled channels are skipped). */
export function createQuestionDispatcher(channels: QuestionChannel[]): QuestionDispatcher {
  return {
    channels,
    async notifyAll(notice) {
      const out: QuestionDelivery[] = [];
      for (const c of channels) if (c.enabled) out.push(await c.notify(notice));
      return out;
    },
  };
}
