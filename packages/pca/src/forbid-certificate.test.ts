import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { MAX_CLAUSES, certificateConsistent, certify, checkForbidCertificate, clausesError, decideClauses, type ForbidCertificate, type PolicyClause } from './forbid-certificate';
import type { ActionContext } from './predicates';
import { buildForbidCertificateVectors, CLAUSES } from './test-support/forbid-certificate-vectors';

const act = (verb: string, resource: string, params?: Record<string, unknown>): ActionContext => ({ action: { verb, resource, ...(params ? { params } : {}) } });
const file = JSON.parse(readFileSync(new URL('../conformance/forbid-certificate-vectors.json', import.meta.url), 'utf8')) as ReturnType<typeof buildForbidCertificateVectors> as {
  decide: Array<{ name: string; clauses: PolicyClause[]; action: ActionContext; options?: { precedence?: string[]; permitSigners?: string[] }; expect: { decision: string; winner: unknown; shadowed: string[]; values: unknown[]; certificate_digest: string } }>;
  table: Array<{ name: string; certificate: ForbidCertificate; options?: { precedence?: string[] }; expect: { consistent: boolean } }>;
};

describe('forbid-certificate-vectors.json', () => {
  it('is what the generator writes', () => {
    expect(`${JSON.stringify(buildForbidCertificateVectors(), null, 2)}\n`).toBe(readFileSync(new URL('../conformance/forbid-certificate-vectors.json', import.meta.url), 'utf8'));
  });
  it.each(file.decide)('decide: $name', (v) => {
    const d = decideClauses(v.clauses, v.action, v.options);
    expect({ decision: d.decision, winner: d.witness.winner, shadowed: d.witness.shadowed, values: d.values }).toEqual({ decision: v.expect.decision, winner: v.expect.winner, shadowed: v.expect.shadowed, values: v.expect.values });
    const cert = certify(v.clauses, v.action, v.options);
    expect(checkForbidCertificate(cert, v.clauses, v.action, v.options)).toEqual({ ok: true });
  });
  it.each(file.table)('table: $name', (v) => expect(certificateConsistent(v.certificate, v.options)).toBe(v.expect.consistent));
});

describe('decideClauses', () => {
  it('forbid beats permit, whoever signed either', () => {
    const cl: PolicyClause[] = [
      { id: 'org-forbid', kind: 'forbid', signer: 'org', when: { verb: 'v', resource: '/secret/*' } },
      { id: 'user-permit', kind: 'permit', signer: 'user', when: { verb: 'v' } },
    ];
    expect(decideClauses(cl, act('v', '/secret/1'), { precedence: ['user', 'org'] }).decision).toBe('deny');
    expect(decideClauses(cl, act('v', '/open/1')).decision).toBe('allow');
  });

  it('is deny by default and for malformed input', () => {
    expect(decideClauses([], act('v', '/x')).witness.winner).toEqual({ kind: 'none', id: null });
    expect(decideClauses(CLAUSES, { action: {} } as never).witness.winner.kind).toBe('malformed');
    expect(decideClauses([{ id: 'a', kind: 'permit', when: {} as never }, { id: 'a', kind: 'permit', when: {} as never }], act('v', '/x')).decision).toBe('deny');
  });

  it('an escalate clause caps allow at escalate but never lifts a deny', () => {
    const cl: PolicyClause[] = [
      { id: 'p', kind: 'permit', when: { verb: 'v' } },
      { id: 'e', kind: 'escalate', when: { verb: 'v', resource: '/big/*' } },
    ];
    expect(decideClauses(cl, act('v', '/big/1')).decision).toBe('escalate');
    expect(decideClauses(cl, act('w', '/big/1')).decision).toBe('deny');
  });

  it('an order-independent decision', () => {
    const rev = [...CLAUSES].reverse();
    for (const c of [act('pay.send', '/vip/1', { amount: 6000 }), act('pay.send', '/acct/1', { amount: 90 }), act('pay.send', '/blocked/x', { amount: 1 })]) {
      expect(decideClauses(rev, c).decision).toBe(decideClauses(CLAUSES, c).decision);
    }
  });
});

describe('clausesError', () => {
  it('names the first problem', () => {
    expect(clausesError('x')).toBe('clauses must be an array');
    expect(clausesError(Array.from({ length: MAX_CLAUSES + 1 }, (_, i) => ({ id: `c${i}`, kind: 'permit', when: {} })))).toMatch(/more than 512/);
    expect(clausesError([{ id: '', kind: 'permit', when: {} }])).toMatch(/id must be a string/);
    expect(clausesError([{ id: 'a', kind: 'allow', when: {} }])).toMatch(/kind must be/);
    expect(clausesError([{ id: 'a', kind: 'permit', when: 5 }])).toMatch(/when must be/);
    expect(clausesError([{ id: 'a', kind: 'permit', signer: 5, when: {} }])).toMatch(/signer/);
    expect(clausesError([null])).toMatch(/must be an object/);
    expect(clausesError(CLAUSES)).toBeNull();
  });
});

describe('checkForbidCertificate', () => {
  const ctx = act('pay.send', '/blocked/x', { amount: 6000 });
  const opts = { precedence: ['org', 'user'] };
  const cert = certify(CLAUSES, ctx, opts);

  it('accepts the genuine certificate', () => expect(checkForbidCertificate(cert, CLAUSES, ctx, opts)).toEqual({ ok: true }));

  it('refuses a certificate for another action or another policy', () => {
    expect(checkForbidCertificate(cert, CLAUSES, act('pay.send', '/acct/1', { amount: 1 }), opts).ok).toBe(false);
    expect(checkForbidCertificate(cert, CLAUSES.slice(1), ctx, opts).ok).toBe(false);
  });

  it('refuses a certificate whose table does not entail its decision', () => {
    const forged = structuredClone(cert);
    forged.decision = 'allow';
    expect(checkForbidCertificate(forged, CLAUSES, ctx, opts)).toEqual({ ok: false, reason: 'certificate table does not entail its decision' });
  });

  it('refuses a self-consistent forgery that does not match the recomputed decision', () => {
    // flip the table AND the decision: consistent on its own, wrong against the evaluator
    const forged = structuredClone(cert);
    for (const r of forged.clauses) if (r.kind === 'forbid') r.value = 'false';
    forged.decision = 'allow';
    forged.winner = { kind: 'permit', id: 'p-vip' };
    forged.shadowed = ['e-review'];
    expect(certificateConsistent(forged, opts)).toBe(false); // p-vip is not marked matched either: the table has no permit
    for (const r of forged.clauses) if (r.id === 'p-vip') r.value = 'true';
    forged.shadowed = ['e-review'].filter(() => false);
    expect(checkForbidCertificate(forged, CLAUSES, ctx, opts).ok).toBe(false);
  });

  it('is fail closed on garbage', () => {
    expect(certificateConsistent(null as never)).toBe(false);
    expect(checkForbidCertificate({} as never, CLAUSES, ctx).ok).toBe(false);
    expect(checkForbidCertificate(cert, 'x' as never, ctx)).toEqual({ ok: false, reason: 'malformed clauses' });
  });
});

describe('boundaries of the clause list', () => {
  const mk = (n: number): PolicyClause[] => Array.from({ length: n }, (_, i) => ({ id: `c${i}`, kind: 'permit', when: { verb: 'v' } }));
  it('512 clauses are accepted and 513 are not', () => {
    expect(clausesError(mk(MAX_CLAUSES))).toBeNull();
    expect(clausesError(mk(MAX_CLAUSES + 1))).toBe('more than 512 clauses');
  });
  it('an id of 128 characters is accepted and 129 is not; a signer of 256 and 257', () => {
    expect(clausesError([{ id: 'a'.repeat(128), kind: 'permit', when: {} }])).toBeNull();
    expect(clausesError([{ id: 'a'.repeat(129), kind: 'permit', when: {} }])).toMatch(/id must be a string of 1..128/);
    expect(clausesError([{ id: 'a', kind: 'permit', signer: 's'.repeat(256), when: {} }])).toBeNull();
    expect(clausesError([{ id: 'a', kind: 'permit', signer: 's'.repeat(257), when: {} }])).toMatch(/signer must be a string of at most 256/);
    expect(clausesError([{ id: 'a', kind: 'permit', when: {} }, { id: 'a', kind: 'forbid', when: {} }])).toBe("clauses[1].id 'a' is a duplicate");
  });
});

describe('which forbid is named', () => {
  const f = (id: string, signer?: string): PolicyClause => ({ id, kind: 'forbid', ...(signer !== undefined ? { signer } : {}), when: { verb: 'v' } });
  const ctx = act('v', '/x');
  it('the more authoritative signer wins even when its id sorts later; an unlisted or absent signer ranks last, equal to each other', () => {
    const opts = { precedence: ['org'] };
    expect(decideClauses([f('a', 'other'), f('z', 'org')], ctx, opts).witness.winner.id).toBe('z');
    expect(decideClauses([f('z', 'org'), f('a', 'other')], ctx, opts).witness.winner.id).toBe('z');
    expect(decideClauses([f('b'), f('a', 'other')], ctx, opts).witness.winner.id).toBe('a'); // absent and unlisted tie, then the id
    expect(decideClauses([f('a', 'other'), f('b')], ctx, opts).witness.winner.id).toBe('a');
    expect(decideClauses([f('a'), f('z', 'org')], ctx, opts).witness.winner.id).toBe('z');
  });
  it('equal rank is broken by id and the shadowed list is in the same order', () => {
    const d = decideClauses([f('c'), f('a'), f('b')], ctx);
    expect(d.witness).toEqual({ winner: { kind: 'forbid', id: 'a' }, shadowed: ['b', 'c'] });
    expect(decideClauses([f('b'), f('c'), f('a')], ctx).witness.shadowed).toEqual(['b', 'c']);
    expect(decideClauses([f('b'), f('a')], ctx).witness.winner.id).toBe('a');
    expect(decideClauses([f('a'), f('b')], ctx).witness.winner.id).toBe('a');
  });
});

describe('permitSigners', () => {
  const p = (id: string, signer?: string): PolicyClause => ({ id, kind: 'permit', ...(signer !== undefined ? { signer } : {}), when: { verb: 'v' } });
  const ctx = act('v', '/x');
  it('keeps a permit from a listed signer and drops one from another signer or with no signer', () => {
    expect(decideClauses([p('a', 'org')], ctx, { permitSigners: ['org'] }).decision).toBe('allow');
    expect(decideClauses([p('a', 'user')], ctx, { permitSigners: ['org'] }).decision).toBe('deny');
    expect(decideClauses([p('a')], ctx, { permitSigners: ['org'] }).decision).toBe('deny');
    expect(decideClauses([p('a')], ctx, { permitSigners: [] }).decision).toBe('deny');
    expect(decideClauses([p('a')], ctx).decision).toBe('allow');
  });
  it('a dropped permit is recorded as false in the table', () => {
    expect(decideClauses([p('a', 'user')], ctx, { permitSigners: ['org'] }).values).toEqual([{ id: 'a', kind: 'permit', value: 'false' }]);
  });
});

describe('certificateConsistent rejects each malformed header on its own', () => {
  const base = certify(CLAUSES, act('pay.send', '/acct/1', { amount: 10 }));
  it.each([
    ['version', { v: 2 }],
    ['kind', { kind: 'other' }],
    ['clauses', { clauses: 'x' }],
  ])('%s', (_n, over) => expect(certificateConsistent({ ...base, ...over } as never)).toBe(false));
  it('the untampered certificate is consistent', () => expect(certificateConsistent(base)).toBe(true));
  it('a shadowed list in the wrong order is not consistent', () => {
    const c = certify(CLAUSES, act('pay.send', '/blocked/x', { amount: 6000 }), { precedence: ['org', 'user'] });
    expect(c.shadowed.length).toBeGreaterThan(1);
    expect(certificateConsistent({ ...c, shadowed: [...c.shadowed].reverse() }, { precedence: ['org', 'user'] })).toBe(false);
  });
});
