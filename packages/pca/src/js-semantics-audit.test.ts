/**
 * Regressions for the 2026-10-12 JavaScript-semantics audit of the decision code (server verifier, objective risk): each
 * case is an input on which a JS quirk (an Object.prototype key, a missing vocabulary entry ranked as "unknown") used to
 * produce a different decision than the strict rule. Every expectation here also kills the mutant that reverts the fix.
 */
import { describe, expect, it } from 'vitest';
import { AUD, NOW, setup } from './server/fixture.test-util';
import { verifyPCActn } from './server/verify';
import { ResourceGraph, blastRadius, harmReport } from './objective-risk';

const risk = { reversibility: 0, blastRadius: 0.5, confidence: 0.5, semanticDistance: 1 };

/** The plan's reversible node, re-declared under `declared`, verified against the authoritative class `authoritative`. */
async function classVerdict(declared: string, authoritative: string, capClass: string) {
  const s = setup({ taskCaveats: [{ type: 'reversibility_max', class: capClass }] });
  const p = s.mk(s.plan[0]!, { tweak: (a) => { a.reversibility_class = declared; } });
  return verifyPCActn(p, { grant: s.grant, now: NOW, audience: AUD, context: { risk, params: {}, reversibilityClass: authoritative } });
}

describe('server verifier: reversibility class ranking covers the caveat vocabulary (rate_limited)', () => {
  it('a declared rate_limited does not replace an authoritative costly (same tier): the caveat reads the authoritative class', async () => {
    // before: rate_limited ranked as an unknown (most restrictive) class, became the effective class and satisfied
    // reversibility_max: rate_limited, although the authoritative costly is not a class that caveat accepts.
    const v = await classVerdict('rate_limited', 'costly', 'rate_limited');
    expect(v.checks.reversibility).toBe('pass');
    expect(v.checks.delegated_caveats).toBe('fail');
  });
  it('a declared rate_limited understates an authoritative irreversible: the reversibility check fails', async () => {
    const v = await classVerdict('rate_limited', 'irreversible', 'irreversible');
    expect(v.checks.reversibility).toBe('fail');
    expect(v.allow).toBe(false);
  });
  it('a declared rate_limited is stricter than an authoritative reversible and stays the effective class', async () => {
    const strict = await classVerdict('rate_limited', 'reversible', 'reversible');
    expect(strict.checks.reversibility).toBe('pass');
    expect(strict.checks.delegated_caveats).toBe('fail'); // rate_limited is more severe than the reversible cap
    const ok = await classVerdict('rate_limited', 'reversible', 'rate_limited');
    expect(ok.checks.delegated_caveats).toBe('pass');
  });
});

describe('objective risk: harm dimensions and denominations spelled like Object.prototype members are ordinary keys', () => {
  const graph = (harm: Record<string, number>) => new ResourceGraph().addNode({ id: 'db', harm });

  it('a harm dimension named __proto__ is counted (it used to be dropped: the assignment only touched the prototype)', () => {
    const b = blastRadius({ resource: 'db' }, graph(JSON.parse('{"__proto__": 7}') as Record<string, number>));
    expect(Object.keys(b.harm)).toEqual(['__proto__']);
    expect(Object.prototype.hasOwnProperty.call(b.harm, '__proto__')).toBe(true);
    expect(Object.getPrototypeOf(b.harm)).toBe(Object.prototype);
    expect(harmReport(b.harm, [{ id: '__proto__', ceiling: 14, weight: 1 }]).normalized).toBe(0.5);
  });
  it('a harm dimension named constructor starts from 0, not from the inherited function', () => {
    const b = blastRadius({ resource: 'db' }, graph({ constructor: 3, rows: 2 } as Record<string, number>));
    expect(b.harm).toEqual({ constructor: 3, rows: 2 });
    expect(harmReport(b.harm, [{ id: 'constructor', ceiling: 6, weight: 1 }]).normalized).toBe(0.5);
  });
  it('a denomination the units do not carry reads 0 even when it is named like an inherited member', () => {
    // before: units.toString (a function) made the sum NaN, which clamps to the maximum harm 1
    expect(harmReport({ rows: 1 }, [{ id: 'toString', ceiling: 10, weight: 1 }, { id: 'rows', ceiling: 2, weight: 1 }]).normalized).toBe(0.25);
    expect(harmReport({}, [{ id: 'valueOf', ceiling: 1, weight: 1 }]).normalized).toBe(0);
  });
});
