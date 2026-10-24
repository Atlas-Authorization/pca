/**
 * r13 (g3) mutation kills, intent-v2.ts outside the golden tables: the verifier env after a W-B DENY (no golden case
 * has an earlier W-B check passing and a later one failing), the key order of env.canon, and intentV2Active on a
 * missing PCActn view.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import type { ActionSchema } from './action-schema';
import { b64u } from './hash';
import { canonProjection, decideIntentV2, intentV2Active } from './intent-v2';

const cases: any[] = JSON.parse(gunzipSync(readFileSync(resolve(__dirname, '..', 'testdata', 'k042-intentv2-r13-subset.json.gz'))).toString('utf8')).cases;
const byName = (n: string) => { const c = cases.find((x) => x.name === n); if (!c) throw new Error('no case ' + n); return c; };

describe('decideIntentV2: W-B env after a deny', () => {
  it('facts pass then classes fail: the decision is a deny and carries NO W-B env (no world, prov or class)', () => {
    const c = byName('wb16/wb16-median-3');
    const p = JSON.parse(c.p), g = JSON.parse(c.grant), ctx = JSON.parse(c.ctx);
    // the base: facts passes and fills env.world
    const ok = decideIntentV2(p, g, ctx, c.now);
    expect(ok.checks.find((k) => k.name === 'facts')).toEqual({ name: 'facts', ok: true });
    expect(Object.keys(ok.env?.world ?? {}).length).toBeGreaterThan(0);
    // the same action with a committed class but no classifier policy / verdicts: rule 18 denies after facts passed
    p.intent_session.classes = [b64u(new Uint8Array(32).fill(7))];
    const d = decideIntentV2(p, g, ctx, c.now);
    const names = d.checks.map((k) => [k.name, k.ok]);
    expect(names.slice(-2)).toEqual([['facts', true], ['classes', false]]);
    expect(d.checks.at(-1)!.reason).toMatch(/^classes: /);
    expect(d.env?.world).toBeUndefined();
    expect(d.env?.prov).toBeUndefined();
    expect(d.env?.class).toBeUndefined();
  });
});

describe('canonProjection: env.canon keys in UTF-8 byte order of the declared paths', () => {
  it('declared out of order, projected in order', () => {
    const doc = { verbs: [{ verb: 'v', params: {
      'action.params.zeta': { type: 'boolean' }, 'action.params.Alpha': { type: 'set' }, 'action.params.beta': { type: 'array' }, 'action.params.aa': { type: 'boolean' }, 'action.params.é': { type: 'boolean' }, 'action.params.Ａ': { type: 'boolean' },
    } }] } as unknown as ActionSchema;
    const out = canonProjection(doc, 'v', { zeta: true, Alpha: ['b', 'a'], beta: [2, 1], aa: false, 'é': 1, 'Ａ': true });
    expect(Object.keys(out)).toEqual(['Alpha', 'aa', 'beta', 'zeta', 'é', 'Ａ']);
    expect(out).toEqual({ Alpha: '["a","b"]', aa: 'false', beta: '[2,1]', zeta: 'true', 'é': 'false', 'Ａ': 'true' });
  });
});

describe('intentV2Active on a missing PCActn view', () => {
  it('reads only the context (never throws on it)', () => {
    expect(() => intentV2Active(undefined as never, undefined)).not.toThrow();
    expect(intentV2Active(undefined as never, undefined)).toBe(false);
    expect(intentV2Active(null as never, { policy: { schema: { closed_world: true } } })).toBe(true);
    expect(intentV2Active(undefined as never, { policy: { map: { require: true } } })).toBe(true);
  });
});
