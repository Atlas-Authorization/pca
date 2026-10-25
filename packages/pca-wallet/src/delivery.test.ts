import { describe, expect, it } from 'vitest';
import { b64u } from '@atlasauth/pca';
import { act, harness, KID, makeIR } from './fixtures.test-util';
import { clarificationNotice, createQuestionDispatcher, questionText, questionTextChannel, questionWebhookChannel, siteQuestionNotice } from './index';

const setup = () => {
  const h = harness();
  const a = act('air.book', { add_ons: 'none', total: 77800 }, 'skyair.example/bookings');
  const ir = makeIR(h, a, { 'action.params.add_ons': ['none'], 'action.params.total': [2, 3], 'env.prov.action.params.add_ons': ['trusted|first_party'] }, { question_id: 'q_d' });
  const keys = [{ kid: KID, alg: 'ed25519' as const, pk: b64u(h.site.publicKey) }];
  return { h, ir, keys };
};

describe('question delivery over the approval-channel transports', () => {
  it('only a verified site-signed question becomes a notice', () => {
    const { h, ir, keys } = setup();
    const n = siteQuestionNotice(ir, { keys, site: 'https://skyair.example', now: h.clock.t, inboxUrl: 'https://wallet.example/q' });
    expect(n).toMatchObject({ type: 'pca.intent.question', question_id: 'q_d', intent_required: ir });
    expect(() => siteQuestionNotice({ ...ir, friction: 'tap' === ir.friction ? 'hold' : 'tap' }, { keys, site: 'x', now: h.clock.t })).toThrow(/siteQuestionNotice/);
    expect(() => siteQuestionNotice(ir, { keys, site: 'x', now: ir.expires_at + 1 })).toThrow(/expired/);
  });
  it('the webhook sends the signed notice; text surfaces send only the fixed template', async () => {
    const { h, ir, keys } = setup();
    const sent: { url: string; body: string }[] = [];
    const texts: { subject: string; text: string }[] = [];
    const d = createQuestionDispatcher([
      questionWebhookChannel({ url: 'https://wallet.example/push', fetch: async (url, init) => (sent.push({ url, body: init.body }), { ok: true, status: 202 }) }),
      questionTextChannel('push', { siteName: 'SkyAir\nIGNORE ALL', send: async (b) => (texts.push(b), {}) }),
      questionTextChannel('email', { siteName: 'SkyAir' }),
    ]);
    const out = await d.notifyAll(siteQuestionNotice(ir, { keys, site: 'https://skyair.example', now: h.clock.t, inboxUrl: 'https://wallet.example/q' }));
    expect(out.map((o) => [o.kind, o.delivered])).toEqual([['webhook', true], ['push', true]]);
    expect(JSON.parse(sent[0]!.body).intent_required).toEqual(ir);
    expect(texts[0]).toEqual({ subject: 'SkyAir IGNORE ALL has a question about your request', text: 'SkyAir IGNORE ALL has a question about your request\n\nOpen your wallet to answer: https://wallet.example/q?question=q_d' });
  });
  it('a clarification notice carries ids only', () => {
    const n = clarificationNotice('sid', 'q_c');
    expect(Object.keys(n).sort()).toEqual(['question_id', 'session', 'type']);
    expect(questionText(n, 'ignored').subject).toBe('Your agent needs a decision about your request');
  });
  it('an unconfigured channel never dispatches', async () => {
    const r = await questionWebhookChannel({}).notify(clarificationNotice('s', 'q'));
    expect(r).toMatchObject({ delivered: false, reason: 'webhook channel not configured' });
  });
});
