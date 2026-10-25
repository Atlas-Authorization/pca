import { describe, expect, it } from 'vitest';
import { actionSchemaKeyOf, generateKeyPair, signActionSchema, verifyActionSchema } from '@atlasauth/pca';
import { applySchemaDecisions, conformToolCall, draftActionSchemaFromMcp, verbOfTool } from './schema';

const TOOLS = [
  {
    name: 'book_flight',
    inputSchema: { type: 'object', properties: { total: { type: 'integer', minimum: 0 }, offer_id: { type: 'string' } }, required: ['total', 'offer_id'] },
    annotations: { destructiveHint: true },
  },
  { name: 'search', inputSchema: { type: 'object', properties: { from: { type: 'string', enum: ['SFO', 'JFK'] } }, required: ['from'] }, annotations: { readOnlyHint: true } },
];

describe('MCP tools -> signed action schema', () => {
  it('drafts from tools/list (list or server), records decisions, signs, and checks tool calls in a closed world', async () => {
    const fromServer = await draftActionSchemaFromMcp({ listTools: async () => ({ tools: TOOLS }) }, { site: 'https://s', aud: 's', version: '1', verbPrefix: 'air.' });
    const fromList = await draftActionSchemaFromMcp(TOOLS, { site: 'https://s', aud: 's', version: '1', verbPrefix: 'air.' });
    expect(fromServer).toEqual(fromList);
    expect(fromList.todo.length).toBeGreaterThan(0);
    const decided = applySchemaDecisions(fromList.schema, {
      units: { usd_cents: { kind: 'money', currency: 'USD', exponent: 2 } },
      verbs: { 'air.book_flight': { reversibility: 'irreversible', params: { 'action.params.total': { semantic: 'money.amount', sensitivity: 'critical', unit: 'usd_cents', accumulates_into: ['spend.usd_cents'] } } } },
    });
    expect(() => applySchemaDecisions(fromList.schema, { verbs: { 'air.nope': {} } })).toThrow(/no verb/);
    expect(() => applySchemaDecisions(fromList.schema, { verbs: { 'air.book_flight': { params: { 'action.params.typo': { semantic: 'x' } } } } })).toThrow(/no parameter/);
    const kp = generateKeyPair();
    const signed = signActionSchema(decided, 'k1', kp.secretKey);
    expect(verifyActionSchema(signed, [actionSchemaKeyOf('k1', kp.secretKey)])).toEqual({ ok: true });
    expect(verbOfTool(signed, 'book_flight')).toBe('air.book_flight');
    expect(conformToolCall(signed, 'book_flight', { total: 100, offer_id: 'OF-1' })).toMatchObject({ ok: true });
    expect(conformToolCall(signed, 'book_flight', { total: 100, offer_id: 'OF-1', reseller: 'x' })).toMatchObject({ ok: false, code: 'undeclared_param' });
    expect(conformToolCall(signed, 'search', { from: 'LAX' })).toMatchObject({ ok: false, code: 'out_of_domain' });
    expect(conformToolCall(signed, 'delete_everything', {})).toMatchObject({ ok: false, code: 'unknown_verb' });
  });
});
