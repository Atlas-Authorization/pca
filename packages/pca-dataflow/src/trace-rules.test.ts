// Track K9: trace rules compile to K1 derive caveats that refuse exactly the forbidden order; the Invariant subset imports
// fail-strict; the lethal-trifecta lint; detector adapters are one-sided (only a well-formed clean answer is no_finding).
import { describe, expect, it } from 'vitest';
import { b64u, detectorInputDigest, detectorSignal, deriveError, encodeKey, evaluateDerive, generateKeyPair, type HistoryEvent } from '@atlasauth/pca';
import { compileTraceRules, lethalTrifecta, parseInvariantRule, parseTraceRule, TraceRuleError, type VerbTable } from './trace-rules';
import { categoryId, genericReceipt, lakeraReceipt, promptSecurityReceipt } from './detectors';

const TABLE: VerbTable = {
  'web.fetch': { traits: ['pca.network_egress'], effects: ['read'] },
  'crm.read': { traits: ['pca.pii_access'], effects: ['read'] },
  'mail.send': { traits: ['pca.external_communication'], effects: ['create'] },
  'slack.post': { traits: ['pca.external_communication'], effects: ['create'] },
  'notes.write': { traits: [], effects: ['create'] },
};
const NOW = 1_800_000_000_000;
const H = (verb: string, ago: number, resource = 'r'): HistoryEvent => ({ t: NOW - ago, verb, resource });
/** All compiled caveats hold (the conjunction the verifier evaluates): true, false or null (unknown, refused). */
function allow(caveats: ReturnType<typeof compileTraceRules>['caveats'], verb: string | undefined, history: HistoryEvent[] | undefined): boolean | null {
  let unknown = false;
  for (const c of caveats) {
    const r = evaluateDerive(c, { now: NOW, ...(verb !== undefined ? { action: { verb, resource: 'x' } } : {}), ...(history !== undefined ? { history } : {}), claims: {} });
    if (r === false) return false;
    if (r === null) unknown = true;
  }
  return unknown ? null : true;
}
const code = (f: () => unknown): string => {
  try {
    f();
    return 'no error';
  } catch (e) {
    return e instanceof TraceRuleError ? e.code : `other: ${(e as Error).message}`;
  }
};

describe('trace rules compile to checked edges', () => {
  const rule = parseTraceRule('no_exfil', 'never trait:pca.external_communication after tool:web.fetch within 1h', 'untrusted web content precedes a send');
  const compiled = compileTraceRules([rule], TABLE);

  it('one caveat per A action and chunk of B actions, every one a well-formed derive caveat; edges list each pair', () => {
    expect(compiled.caveats).toHaveLength(1);
    for (const c of compiled.caveats) expect(deriveError(c)).toBeNull();
    expect(compiled.caveats[0]).toEqual({
      type: 'derive',
      id: 'trace.no_exfil.0',
      defs: [
        { name: 'seen', kind: 'count', window_ms: 3_600_000, verb: 'web.fetch' },
        { name: 'verb', kind: 'action', field: 'verb' },
        { name: 'is_b', kind: 'expr', expr: { op: 'or', args: [{ op: 'eq', a: { ref: 'verb' }, b: { const: 'mail.send' } }, { op: 'eq', a: { ref: 'verb' }, b: { const: 'slack.post' } }] } },
      ],
      check: { op: 'not', arg: { op: 'and', args: [{ op: 'gt', a: { ref: 'seen' }, b: { const: 0 } }, { ref: 'is_b' }] } },
    });
    expect(compiled.edges).toEqual([
      { rule: 'no_exfil', from: { tool: 'web.fetch' }, to: 'mail.send', within_ms: 3_600_000 },
      { rule: 'no_exfil', from: { tool: 'web.fetch' }, to: 'slack.post', within_ms: 3_600_000 },
    ]);
    expect(compiled.digest).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('refuses a send after a fetch inside the window, and nothing else', () => {
    expect(allow(compiled.caveats, 'mail.send', [H('web.fetch', 600_000)])).toBe(false);
    expect(allow(compiled.caveats, 'slack.post', [H('crm.read', 1), H('web.fetch', 3_599_999)])).toBe(false);
    expect(allow(compiled.caveats, 'mail.send', [H('web.fetch', 3_600_000)])).toBe(true); // window is (now - w, now]
    expect(allow(compiled.caveats, 'mail.send', [H('crm.read', 10)])).toBe(true);
    expect(allow(compiled.caveats, 'crm.read', [H('web.fetch', 10)])).toBe(true);
    expect(allow(compiled.caveats, 'mail.send', [])).toBe(true);
  });

  it('fails closed: a send with no history, or no verb, is refused (unknown); a non-send with no history is fine', () => {
    expect(allow(compiled.caveats, 'mail.send', undefined)).toBeNull();
    expect(allow(compiled.caveats, undefined, [H('web.fetch', 1)])).toBeNull();
    expect(allow(compiled.caveats, 'crm.read', undefined)).toBe(true);
    expect(allow(compiled.caveats, 'mail.send', [{ t: 1.5, verb: 'web.fetch', resource: 'r' } as never])).toBeNull();
  });

  it('resource prefixes on the earlier side; large selectors split into chunks of eight', () => {
    const big: Record<string, { traits: string[]; effects: string[] }> = { 'inbox.read': { traits: [], effects: ['read'] } };
    for (let i = 0; i < 20; i++) big[`send.v${String(i).padStart(2, '0')}`] = { traits: ['pca.external_communication'], effects: ['create'] };
    const c = compileTraceRules([parseTraceRule('r', 'never trait:pca.external_communication after resource:inbox/,tool:inbox.read within 7d')], big);
    expect(c.caveats).toHaveLength(2 * 3);
    expect(c.caveats.map((x) => x.defs[0])).toContainEqual({ name: 'seen', kind: 'count', window_ms: 7 * 86_400_000, resource_prefix: 'inbox/' });
    expect(allow(c.caveats, 'send.v19', [H('x', 5, 'inbox/42')])).toBe(false);
    expect(allow(c.caveats, 'send.v00', [H('inbox.read', 5)])).toBe(false);
    expect(allow(c.caveats, 'send.v00', [H('x', 5, 'outbox/1')])).toBe(true);
  });

  it.each([
    ['unknown tool', () => compileTraceRules([parseTraceRule('r', 'never tool:mail.sned after tool:web.fetch within 1h')], TABLE), 'unknown_tool'],
    ['a trait nothing has', () => compileTraceRules([parseTraceRule('r', 'never trait:pca.money_moving after tool:web.fetch within 1h')], TABLE), 'empty_selector'],
    ['resource on the later side', () => parseTraceRule('r', 'never resource:x after tool:web.fetch within 1h'), 'resource_on_effect'],
    ['window over 30 days', () => parseTraceRule('r', 'never tool:mail.send after tool:web.fetch within 31d'), 'window'],
    ['no window', () => parseTraceRule('r', 'never tool:mail.send after tool:web.fetch'), 'syntax'],
    ['bad atom', () => parseTraceRule('r', 'never mail.send after tool:web.fetch within 1h'), 'selector'],
    ['bad id', () => parseTraceRule('R-1', 'never tool:mail.send after tool:web.fetch within 1h'), 'id'],
    ['duplicate ids', () => compileTraceRules([parseTraceRule('r', 'never tool:mail.send after tool:web.fetch within 1h'), parseTraceRule('r', 'never tool:slack.post after tool:web.fetch within 1h')], TABLE), 'id'],
  ])('compile errors are errors, never skipped: %s', (_n, f, c) => {
    expect(code(f)).toBe(c);
  });

  it('more than 64 caveats is refused', () => {
    const t: Record<string, { traits: string[] }> = {};
    for (let i = 0; i < 70; i++) t[`a${i}`] = { traits: ['src'] };
    t.out = { traits: ['dst'] };
    expect(code(() => compileTraceRules([parseTraceRule('r', 'never trait:dst after trait:src within 1h')], t))).toBe('too_large');
  });
});

describe('Invariant subset', () => {
  const CANON = `raise "Don't use send_email after get_website" if:
    (output: ToolOutput) -> (call2: ToolCall)
    output is tool:get_website
    prompt_injection(output.content, threshold=0.7)
    call2 is tool:send_email`;
  const T: VerbTable = { get_website: { traits: [], effects: ['read'] }, send_email: { traits: [], effects: ['create'] }, search: { traits: [], effects: ['read'] } };

  it('the canonical example has a detector condition: refused unless dropUnsupported, which only widens the refusal', () => {
    expect(code(() => parseInvariantRule('inv', CANON, { horizon: '1d' }))).toBe('unsupported');
    const r = parseInvariantRule('inv', CANON, { horizon: '1d', dropUnsupported: true });
    expect(r.dropped).toEqual(['prompt_injection(output.content, threshold=0.7)']);
    expect(r.rule).toEqual({ id: 'inv', never: { tools: ['send_email'], traits: [], resources: [], any: false }, after: { tools: ['get_website'], traits: [], resources: [], any: false }, within_ms: 86_400_000, reason: "Don't use send_email after get_website" });
    const c = compileTraceRules([r.rule], T);
    expect(allow(c.caveats, 'send_email', [H('get_website', 5)])).toBe(false);
    expect(allow(c.caveats, 'send_email', [H('search', 5)])).toBe(true);
  });

  it('a binding with no tool line means any tool', () => {
    const r = parseInvariantRule('inv', 'raise "x" if:\n(a: ToolOutput) -> (b: ToolCall)\nb is tool:send_email', { horizon: '1h' });
    expect(r.rule.after.any).toBe(true);
    expect(compileTraceRules([r.rule], T).caveats).toHaveLength(3);
  });

  it.each([
    ['no horizon', 'raise "x" if:\n(a: ToolCall) -> (b: ToolCall)', {} as never, 'horizon'],
    ['three events', 'raise "x" if:\n(a: ToolCall) -> (b: ToolCall) -> (c: ToolCall)', { horizon: '1h' }, 'unsupported'],
    ['a message', 'raise "x" if:\n(a: Message) -> (b: ToolCall)', { horizon: '1h' }, 'unsupported'],
    ['argument pattern', 'raise "x" if:\n(a: ToolCall) -> (b: ToolCall)\nb is tool:send_email({to: ".*@evil.com"})', { horizon: '1h' }, 'unsupported'],
    ['two tools for one event', 'raise "x" if:\n(a: ToolCall) -> (b: ToolCall)\na is tool:x\na is tool:y', { horizon: '1h' }, 'unsatisfiable'],
    ['not a raise', 'deny if:\n(a: ToolCall) -> (b: ToolCall)', { horizon: '1h' }, 'syntax'],
  ])('%s', (_n, text, o, c) => {
    expect(code(() => parseInvariantRule('inv', text, o))).toBe(c);
  });

  it('dropping an argument pattern keeps the tool (wider match)', () => {
    const r = parseInvariantRule('inv', 'raise "x" if:\n(a: ToolCall) -> (b: ToolCall)\na is tool:get_website\nb is tool:send_email({to: ".*@evil.com"})', { horizon: '1h', dropUnsupported: true });
    expect(r.rule.never.tools).toEqual(['send_email']);
    expect(r.dropped).toHaveLength(1);
  });
});

describe('lethal trifecta lint', () => {
  it('flags every send that both untrusted and private reads can reach, and clears it once a rule cuts a leg', () => {
    const none = lethalTrifecta(TABLE, []);
    expect(none).toEqual({ private_reads: ['crm.read'], untrusted_reads: ['web.fetch'], sends: ['mail.send', 'slack.post'], findings: [
      { send: 'mail.send', from_untrusted: ['web.fetch'], from_private: ['crm.read'] },
      { send: 'slack.post', from_untrusted: ['web.fetch'], from_private: ['crm.read'] },
    ] });
    const cut = compileTraceRules([parseTraceRule('r', 'never tool:mail.send after tool:web.fetch within 1d')], TABLE);
    expect(lethalTrifecta(TABLE, cut.edges).findings.map((f) => f.send)).toEqual(['slack.post']);
    const cutPrivate = compileTraceRules([parseTraceRule('r', 'never trait:pca.external_communication after tool:crm.read within 1d')], TABLE);
    expect(lethalTrifecta(TABLE, cutPrivate.edges).findings).toEqual([]);
  });
  it('no trifecta without all three legs; explicit untrusted sources count', () => {
    const { 'crm.read': _p, ...noPrivate } = TABLE;
    expect(lethalTrifecta(noPrivate, []).findings).toEqual([]);
    const t: VerbTable = { 'mail.read': { traits: ['pca.pii_access'], effects: ['read'] }, 'mail.send': { traits: ['pca.external_communication'], effects: ['create'] } };
    expect(lethalTrifecta(t, []).findings).toEqual([]);
    expect(lethalTrifecta(t, [], { untrusted: ['mail.read'] }).findings).toEqual([{ send: 'mail.send', from_untrusted: ['mail.read'], from_private: ['mail.read'] }]);
  });
});

describe('detector adapters are one-sided', () => {
  const gw = generateKeyPair();
  const ctx = { detector: 'lakera', version: 'v2', content: 'hello', secretKey: gw.secretKey, now: NOW };
  const policy = { detectors: [{ id: 'lakera', keys: [{ pk: encodeKey(gw.publicKey) }], on_suspicious: 'escalate' as const, max_age_ms: 60_000 }, { id: 'ps', keys: [{ pk: encodeKey(gw.publicKey) }], on_suspicious: 'deny' as const, max_age_ms: 60_000 }, { id: 'gen', keys: [{ pk: encodeKey(gw.publicKey) }], on_suspicious: 'escalate' as const, max_age_ms: 60_000 }] };
  const fold = (r: unknown) => detectorSignal({ receipts: [r], policy, input_digests: [detectorInputDigest('hello')], now: NOW }).signal;

  it('Lakera: clean, flagged, detect-mode breakdown, malformed', () => {
    const clean = lakeraReceipt({ flagged: false, breakdown: [{ detector_type: 'prompt_attack', detected: false }], metadata: { request_uuid: 'u' } }, ctx);
    expect(clean).toMatchObject({ verdict: 'no_finding', categories: [] });
    expect(fold(clean)).toBe('ok');
    expect(lakeraReceipt({ flagged: true }, ctx)).toMatchObject({ verdict: 'suspicious', categories: ['flagged'] });
    // detect mode: flagged stays false, the breakdown says detected
    expect(lakeraReceipt({ flagged: false, breakdown: [{ detector_type: 'prompt_attack', detected: true }, { detector_type: 'moderated_content/hate', detected: true }] }, ctx)).toMatchObject({ verdict: 'suspicious', categories: ['moderated_content_hate', 'prompt_attack'] });
    for (const bad of [null, {}, { flagged: 'no' }, { flagged: false, breakdown: {} }, { flagged: false, breakdown: [{ detected: 'yes' }] }]) {
      const r = lakeraReceipt(bad, ctx);
      expect(r).toMatchObject({ verdict: 'suspicious', categories: ['detector_error'] });
      expect(fold(r)).toBe('escalate');
    }
  });
  it('Prompt Security: block, modify, violations, clean, malformed', () => {
    const c = { ...ctx, detector: 'ps' };
    expect(promptSecurityReceipt({ result: { prompt: { action: 'log', violations: [] } } }, c)).toMatchObject({ verdict: 'no_finding' });
    expect(promptSecurityReceipt({ result: { prompt: { action: 'block', violations: ['Prompt Injection'] } } }, c)).toMatchObject({ verdict: 'suspicious', categories: ['blocked', 'prompt_injection'] });
    expect(promptSecurityReceipt({ result: { prompt: { action: 'modify', violations: [] } } }, c)).toMatchObject({ verdict: 'suspicious', categories: ['modified'] });
    expect(promptSecurityReceipt({ result: { prompt: { action: 'log', violations: ['Secrets'] } } }, c)).toMatchObject({ verdict: 'suspicious', categories: ['secrets'] });
    expect(promptSecurityReceipt({ result: {} }, c)).toMatchObject({ verdict: 'suspicious', categories: ['detector_error'] });
    // the NeMo Guardrails reading: result.action at the top
    expect(promptSecurityReceipt({ result: { action: 'log' } }, c)).toMatchObject({ verdict: 'no_finding' });
    expect(promptSecurityReceipt({ result: { action: 'block' } }, c)).toMatchObject({ verdict: 'suspicious', categories: ['blocked'] });
    expect(promptSecurityReceipt({ result: { action: 'log', prompt: { action: 'modify', violations: [] } } }, c)).toMatchObject({ verdict: 'suspicious', categories: ['modified'] });
    expect(promptSecurityReceipt({ result: { action: 7 } }, c)).toMatchObject({ verdict: 'suspicious', categories: ['detector_error'] });
    expect(promptSecurityReceipt({ result: { prompt: { action: 'log', violations: 'x' } } }, c)).toMatchObject({ verdict: 'suspicious', categories: ['detector_error'] });
    expect(fold(promptSecurityReceipt({ result: { prompt: { action: 'block', violations: [] } } }, c))).toBe('deny');
  });
  it('generic: categories on a clean answer are ambiguous, hence suspicious', () => {
    const c = { ...ctx, detector: 'gen' };
    expect(genericReceipt({ flagged: false }, c)).toMatchObject({ verdict: 'no_finding' });
    expect(genericReceipt({ flagged: false, categories: ['pii'] }, c)).toMatchObject({ verdict: 'suspicious', categories: ['detector_error'] });
    expect(genericReceipt({ flagged: true, categories: ['PII', 'pii'] }, c)).toMatchObject({ verdict: 'suspicious', categories: ['pii'] });
  });
  it('category ids are normalised, never empty', () => {
    expect(categoryId('Prompt Injection!')).toBe('prompt_injection');
    expect(categoryId('9lives')).toBe('c_9lives');
    expect(categoryId('***')).toBe('other');
    expect(categoryId(5)).toBe('other');
  });
  it('a receipt is about the content the gateway saw', () => {
    const r = lakeraReceipt({ flagged: true }, { ...ctx, session: b64u(new Uint8Array(32).fill(1)) });
    expect(detectorSignal({ receipts: [r], policy, input_digests: [detectorInputDigest('other')], session: b64u(new Uint8Array(32).fill(1)), now: NOW }).rejected[0]!.reason).toContain('other content');
  });
});
