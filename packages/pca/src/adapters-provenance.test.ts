import { describe, expect, it } from 'vitest';
import { createProvenanceRecorder, decideArgProvenance, PROV_HEADER, type ProvenanceBundle } from './arg-provenance';
import { guard, messageSegments, pcaHeaders, PCA_HEADER, provenanceFrom, provenanceHeaders, PROV_HEADER_MAX, recordInput, recordMessages, withPrincipalInput } from './adapters';
import { agent } from './facade';
import { generateKeyPair } from './keys';
import { b64u } from './hash';
import { readEnvelope } from './envelope';

const rec = () => createProvenanceRecorder({ mediator: 'm', kid: 'k1', secretKey: new Uint8Array(32).fill(2) });
const origins = (r: ReturnType<typeof rec>) => r.receipts().map((x) => `${x.origin}:${x.source}`);

describe('messageSegments: roles decide trust', () => {
  it('user / human turns are the principal; tool, function and unknown roles are untrusted; assistant and system add nothing', () => {
    expect(messageSegments({ role: 'user', content: 'hi' })).toEqual([{ origin: 'principal', source: 'user', content: 'hi' }]);
    expect(messageSegments({ _getType: () => 'human', content: 'hi' })).toEqual([{ origin: 'principal', source: 'user', content: 'hi' }]);
    expect(messageSegments({ role: 'tool', tool_call_id: 'c1', content: 'r' })).toEqual([{ origin: 'tool', source: 'c1', content: 'r' }]);
    expect(messageSegments({ role: 'function', name: 'search', content: 'r' })).toEqual([{ origin: 'tool', source: 'search', content: 'r' }]);
    expect(messageSegments({ role: 'weird', content: 'r' })[0]!.origin).toBe('tool');
    for (const role of ['assistant', 'system', 'developer', 'ai', 'model']) expect(messageSegments({ role, content: 'x' })).toEqual([]);
    expect(messageSegments(null)).toEqual([]);
  });
  it('a tool result part inside a user turn (Anthropic, AI SDK, Responses) is untrusted; the text parts are the principal', () => {
    const m = { role: 'user', content: [{ type: 'text', text: 'a' }, { type: 'tool_result', tool_use_id: 't1', content: 'evil' }, { type: 'text', text: 'b' }, { type: 'tool-result', toolName: 'web', result: 'x' }] };
    expect(messageSegments(m)).toEqual([
      { origin: 'principal', source: 'user', content: 'a\nb' },
      { origin: 'tool', source: 't1', content: 'evil' },
      { origin: 'tool', source: 'web', content: 'x' },
    ]);
  });
});

describe('recordMessages / recordInput', () => {
  it('records only new messages; a shorter list starts over', () => {
    const r = rec();
    const msgs = [{ role: 'user', content: 'pay bob' }, { role: 'assistant', content: 'ok' }];
    recordMessages(r, msgs);
    recordMessages(r, [...msgs, { role: 'tool', tool_call_id: 'c', content: 'x' }]);
    expect(origins(r)).toEqual(['principal:user', 'tool:c']);
    recordMessages(r, [{ role: 'user', content: 'again' }]);
    expect(origins(r)).toEqual(['principal:user', 'tool:c', 'principal:user']);
  });
  it('strings, message lists and the usual input keys are the principal; anything else records nothing', () => {
    const r = rec();
    recordInput(r, 'a');
    recordInput(r, { input: 'b', other: 'z' });
    recordInput(r, { messages: [{ role: 'user', content: 'c' }] });
    recordInput(r, 42);
    recordInput(undefined, 'ignored');
    expect(origins(r)).toEqual(['principal:user', 'principal:user', 'principal:user']);
    const f = withPrincipalInput(r, (x: string) => x.toUpperCase());
    expect(f('d')).toBe('D');
    expect(r.receipts()).toHaveLength(4);
  });
});

describe('transport', () => {
  it('provenanceFrom reads an object, its JSON, or a header value; anything else is no bundle', () => {
    const b = { v: 1, kind: 'pca-provenance', receipts: [] };
    expect(provenanceFrom(b)).toBe(b);
    expect(provenanceFrom(JSON.stringify(b))).toEqual(b);
    expect(provenanceFrom(b64u(new TextEncoder().encode(JSON.stringify(b))))).toEqual(b);
    for (const x of [undefined, null, '', '%%%', 5]) expect(provenanceFrom(x)).toBeUndefined();
  });
  it('the header carries a bundle that fits; a larger one is left for the body', () => {
    const r = rec();
    r.principal('x');
    const small = r.forAction({ verb: 'v', resource: 'r', params: {} });
    expect(Object.keys(provenanceHeaders(small))).toEqual([PROV_HEADER]);
    expect(provenanceFrom(provenanceHeaders(small)[PROV_HEADER])).toEqual(small);
    expect(provenanceHeaders(undefined)).toEqual({});
    const big: ProvenanceBundle = { ...small, contents: { '0': 'y'.repeat(PROV_HEADER_MAX) } };
    expect(provenanceHeaders(big)).toEqual({});
    expect(Object.keys(pcaHeaders('e', small)).sort()).toEqual([PCA_HEADER, PROV_HEADER].sort());
    expect(Object.keys(pcaHeaders('e'))).toEqual([PCA_HEADER]);
  });
});

describe('facade agent and guard', () => {
  it("agent() names its recorder's key in the signed grant; act() returns a bundle that verifies under it", () => {
    const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: 'rs' });
    const env = readEnvelope(a.grant);
    expect(env?.provenance?.mediators).toEqual([a.provenance!.pin]);
    a.provenance!.principal('Refund 20 on charge ch_1');
    const r = a.act('stripe.refund', 'charge:ch_1', { amount: 20 });
    expect(r.provenance?.receipts.at(-1)?.origin).toBe('action');
    const d = decideArgProvenance({ bundle: r.provenance, operation: { verb: 'stripe.refund', resource: 'charge:ch_1', params: { amount: 20 } }, mediators: env!.provenance!.mediators! });
    expect(d.outcome).toBe('pass');
    expect(a.subAgent().provenance).toBe(a.provenance); // one session chain across delegation
  });
  it('guard sends the bundle with the call and records what the tool returned as untrusted', async () => {
    const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: 'rs' });
    a.provenance!.principal('Refund 20 on charge ch_1');
    let seen: Record<string, string> = {};
    const refund = guard(a, { verb: 'stripe.refund', resource: 'charge:ch_1' }, async (_p, call) => ((seen = call.headers), { status: 'ok' }));
    await refund({ amount: 20 });
    expect(seen[PROV_HEADER]).toBeDefined();
    expect(a.provenance!.receipts().map((x) => x.origin)).toEqual(['principal', 'action', 'tool']);
  });
});
