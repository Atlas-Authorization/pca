// Replays the 0.5 hardening vectors (budget_alloc monotonicity, core plan_root_authorized, server-side PQ pins) and the
// NVIDIA CRL-coverage rows' option name against the TypeScript reference. The expectations are hand-derived in
// scripts/gen-conformance-hardening.mjs; this file is what proves the reference agrees, so natives can copy the exact reasons.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { allocationsMonotone } from './capability';
import { verifyPCActnCore, type PCActn } from './pcactn';
import { verifyPCActn } from './server/verify';

const CONF = join(__dirname, '..', 'conformance');
const read = (f: string) => JSON.parse(readFileSync(join(CONF, f), 'utf8'));
/* eslint-disable @typescript-eslint/no-explicit-any */
const core = read('vectors.json');
const byName = (n: string): any => {
  const v = core.vectors.find((x: any) => x.name === n);
  if (!v) throw new Error(`vectors.json has no vector ${n}`);
  return v;
};

describe('hardening vectors: the files are exactly what the generator writes', () => {
  it('node scripts/gen-conformance-hardening.mjs --check', () => {
    execFileSync(process.execPath, [join(__dirname, '..', 'scripts', 'gen-conformance-hardening.mjs'), '--check'], { stdio: 'pipe' });
  });
});

describe('budget_alloc monotonicity (budget-alloc-vectors.json)', () => {
  const f = read('budget-alloc-vectors.json');
  it('covers equal, widening and malformed limits', () => {
    const names = f.budget_alloc.map((c: any) => c.name);
    for (const n of ['equal', 'widen', 'negative', 'string-limit', 'missing-limit', 'malformed-after-valid', 'caveats-not-an-array']) expect(names).toContain(n);
    expect(new Set(names).size).toBe(names.length);
  });
  it.each(f.budget_alloc.map((c: any) => [c.name, c] as const))('%s', (_n: string, c: any) => {
    expect(allocationsMonotone(c.caveats)).toEqual(c.expect);
  });
});

describe('plan_root_authorized at the core (plan-root-vectors.json)', () => {
  const f = read('plan-root-vectors.json');
  it.each(f.plan_root_authorized.map((c: any) => [c.name, c] as const))('%s', async (_n: string, c: any) => {
    const v = byName(c.vector);
    const root = v.pcactn.plan.root as string;
    const options: Record<string, unknown> = { ...c.options };
    if (Array.isArray(options.authorizedPlanRoots)) options.authorizedPlanRoots = (options.authorizedPlanRoots as string[]).map((x) => (x === '$plan_root' ? root : x));
    const r = await verifyPCActnCore(v.pcactn as PCActn, { grant: v.grant, nowEpoch: v.context.now, audience: v.context.aud, ...options } as never);
    expect(r.checks['plan_root_authorized']).toBe(c.expect.check);
    expect(r.allow).toBe(c.expect.allow);
    if (c.expect.reason !== undefined) expect(r.reason).toBe(c.expect.reason);
    else expect(r.reason).toBeUndefined();
  });
});

describe('server-side PQ pins (pq-pin-vectors.json)', () => {
  const f = read('pq-pin-vectors.json');
  it.each(f.pq_pin.map((c: any) => [c.name, c] as const))('%s', async (_n: string, c: any) => {
    const v = byName(c.vector);
    const sub = (s: string): string => (s === '$grant.issuer' ? v.grant.issuer : s === '$grant.pq_pk' ? v.grant.pq_pk : s === '$grant.pq_pk[0:20]' ? String(v.grant.pq_pk).slice(0, 20) : s);
    const pins = c.pq_pins === null ? undefined : Object.fromEntries(Object.entries(c.pq_pins as Record<string, string>).map(([k, val]) => [sub(k), sub(val)]));
    const verdict = await verifyPCActn(v.pcactn as PCActn, { grant: v.grant, now: v.context.now, audience: v.context.aud, insecureSkipPlanRootCheck: true, ...(pins !== undefined ? { pqPins: pins } : {}) });
    if (c.expect.check === 'absent') expect('pq_pin' in verdict.checks).toBe(false);
    else expect(verdict.checks['pq_pin']).toBe(c.expect.check);
    if (c.expect.reason !== undefined) expect(verdict.reasons).toContain(c.expect.reason);
    else expect(verdict.reasons.some((r: string) => r.startsWith('pq_pin:'))).toBe(false);
  });
});
