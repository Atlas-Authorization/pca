/** A classical (Ed25519) grant from an issuer that HAS a PQ pin is refused: the pin would otherwise protect nothing. */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { PCActn } from '../pcactn';
import { verifyPCActn } from './verify';

/* eslint-disable @typescript-eslint/no-explicit-any */
const core = JSON.parse(readFileSync(join(__dirname, '..', '..', 'conformance', 'vectors.json'), 'utf8'));
const v = core.vectors.find((x: any) => x.name === 'valid-in-plan-action');
const REASON = 'pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused';
const run = (pins: Record<string, unknown> | undefined) =>
  verifyPCActn(v.pcactn as PCActn, { grant: v.grant, now: v.context.now, audience: v.context.aud, insecureSkipPlanRootCheck: true, ...(pins !== undefined ? { pqPins: pins as Record<string, string> } : {}) });

describe('pq_pin: classical grant from a pinned issuer', () => {
  it('the vector is a classical grant', () => expect(v.grant.alg).toBeUndefined());
  it('a pinned issuer: refused, whatever the pin is', async () => {
    for (const pin of ['any-pq-key', '', 'x'.repeat(2600)]) {
      const r = await run({ [v.grant.issuer]: pin });
      expect(r.allow, pin.slice(0, 8)).toBe(false);
      expect(r.checks['pq_pin']).toBe('fail');
      expect(r.reasons).toContain(REASON);
    }
  });
  it('a pin entry that is not a string still pins the issuer (fail closed)', async () => {
    for (const bad of [7, null, {}, []]) expect((await run({ [v.grant.issuer]: bad })).checks['pq_pin'], String(bad)).toBe('fail');
  });
  it('an inherited property is not a pin (own properties only)', async () => {
    const r = await run(Object.create({ [v.grant.issuer]: 'k' }));
    expect(r.checks['pq_pin']).toBe('pass');
  });
  it('unpinned issuer, empty map and unset pins: unchanged', async () => {
    expect((await run({ other: 'k' })).checks['pq_pin']).toBe('pass');
    expect((await run({})).checks['pq_pin']).toBe('pass');
    expect('pq_pin' in (await run(undefined)).checks).toBe(false);
  });
});
