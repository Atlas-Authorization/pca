/**
 * r13 g6 kills for module-level constants that the statically-importing tests never see mutated (Stryker applies static
 * mutants before any test runs): the safe-regex character classes (\d \w \s and the dot's line terminators), the taint
 * lattice constants and helpers, the predicate path roots / forbidden segments / record guard, and the regex budget's
 * installation of the regex-cache source provider. Each test re-evaluates the modules (vi.resetModules + dynamic import)
 * and compares exact outcomes.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
  vi.unstubAllEnvs();
});

async function fresh() {
  // these pin the DEFAULT (hand-written) paths: the verified-core CI job sets PCA_VERIFIED_CORE for the whole suite, which
  // routes regexes through the proved engine instead; the fresh module reads the variable on first use
  vi.stubEnv('PCA_VERIFIED_CORE', '');
  vi.resetModules();
  const safeRegex = await import('./safe-regex');
  const taint = await import('./taint');
  const predicates = await import('./predicates');
  const budget = await import('./regex-budget');
  const cache = await import('./regex-cache');
  return { safeRegex, taint, predicates, budget, cache };
}

type Settled<T> = { ok: true; value: T } | { ok: false; error: { name: string; message: string } };
function settle<T>(f: () => T): Settled<T> {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    const x = e as Error;
    return { ok: false, error: { name: x?.name, message: x?.message } };
  }
}
const ok = <T>(value: T) => ({ ok: true as const, value });

describe('safe-regex character classes (fresh module)', () => {
  const run = async (src: string, subjects: string[]) => {
    const { safeRegex } = await fresh();
    return subjects.map((s) => safeRegex.safeRegexFullMatch(src, s));
  };
  it('\\d is exactly 0-9', async () => {
    expect(await run('\\d', ['0', '5', '9', '/', ':', 'a'])).toEqual([true, true, true, false, false, false]);
    expect(await run('\\D', ['0', 'a'])).toEqual([false, true]);
  });
  it('\\w is exactly 0-9 A-Z _ a-z', async () => {
    expect(await run('\\w', ['0', '9', 'A', 'Z', '_', 'a', 'z', '@', '[', '`', '{', '/', ':', '^'])).toEqual([
      true, true, true, true, true, true, true, false, false, false, false, false, false, false,
    ]);
  });
  it('\\s is exactly the ECMAScript white space and line terminators', async () => {
    const ws = ['\u0009', '\u000a', '\u000b', '\u000c', '\u000d', '\u0020', '\u00a0', '\u1680', '\u2000', '\u2005', '\u200a', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000', '\ufeff'];
    expect(await run('\\s', ws)).toEqual(ws.map(() => true));
    // non-space code units chosen so the binary search over the ranges visits every range (an emptied range would match)
    expect(await run('\\s', ['\u0061', '\u0008', '\u001f', '\u200b', '\u1681', '\u202b', '\u2100', '\u4e00', '\uffff'])).toEqual([false, false, false, false, false, false, false, false, false]);
    expect(await run('\\S', [' ', 'a'])).toEqual([false, true]);
  });
  it('. matches anything but \\n \\r \\u2028 \\u2029', async () => {
    expect(await run('.', ['\u0061', '\u0020', '\u0009', '\u000a', '\u000d', '\u2028', '\u2029', '\u2027', '\u202a'])).toEqual([
      true, true, true, false, false, false, false, true, true,
    ]);
  });
});

describe('taint lattice constants (fresh module)', () => {
  it('ranks, levels, bottom / top and the normalised value', async () => {
    const { taint } = await fresh();
    expect(taint.TAINT_LEVELS.map((k) => [taint.isTaintLevel(k), taint.labelRank({ kind: k } as never)])).toEqual([
      [true, 0], [true, 1], [true, 2], [true, 3], [true, 4],
    ]);
    expect(taint.labelRank({ kind: 'bogus' } as never)).toBe(4);
    expect(taint.TAINT_LEVELS.map((k) => taint.taintValue({ kind: k } as never))).toEqual([0, 0.25, 0.5, 0.75, 1]);
    expect(taint.BOTTOM).toEqual({ kind: 'trusted' });
    expect(taint.TOP).toEqual({ kind: 'agent' });
    expect(taint.joinLabels([])).toEqual({ kind: 'agent' });
  });
  it('join keeps an agreed id and collapses different ids', async () => {
    const { taint } = await fresh();
    expect(taint.joinLabel({ kind: 'tool', id: 'x' }, { kind: 'tool', id: 'y' })).toEqual({ kind: 'tool' });
    expect(taint.joinLabel({ kind: 'tool', id: 'x' }, { kind: 'tool', id: 'x' })).toEqual({ kind: 'tool', id: 'x' });
  });
  it('the in-memory registry returns copies of what it recorded; the empty registry vouches for nothing', async () => {
    const { taint } = await fresh();
    const reg = new taint.InMemoryTrustedInputRegistry().recordTool('d1', 't1').recordWeb('d2');
    expect([reg.lookup('d1'), reg.lookup('d2'), reg.lookup('d3'), reg.size]).toEqual([{ kind: 'tool', id: 't1' }, { kind: 'web' }, undefined, 2]);
    expect(settle(() => taint.EMPTY_REGISTRY.lookup('d1'))).toEqual(ok(undefined));
  });
});

describe('predicate paths (fresh module)', () => {
  it('subject and env are roots; an own __proto__ / constructor / prototype segment is never followed', async () => {
    const { predicates } = await fresh();
    const evil = JSON.parse('{"__proto__":1,"constructor":2,"prototype":3,"ok":4}');
    const ctx = { action: evil, subject: { id: 's' }, env: { e: 1 } } as never;
    expect(['subject.id', 'env.e', 'action.ok', 'action.__proto__', 'action.constructor', 'action.prototype', 'other.x'].map((p) => predicates.resolvePath(ctx, p))).toEqual([
      { found: true, value: 's' }, { found: true, value: 1 }, { found: true, value: 4 }, { found: false }, { found: false }, { found: false }, { found: false },
    ]);
  });
  it('group conditions are recognised', async () => {
    const { predicates } = await fresh();
    expect([{ all_of: [] }, { any_of: [] }, { not: {} }, { field: 'x', op: 'eq', value: 1 }, null, []].map((c) => predicates.isGroupCondition(c as never))).toEqual([
      true, true, true, false, false, false,
    ]);
  });
});

describe('regex budget installs the regex-cache source provider (fresh module)', () => {
  it('a pattern first compiled inside a request budget is owned by that request source', async () => {
    const { budget, cache, safeRegex } = await fresh();
    const src = 'r13g6-src-[a-z]+';
    expect(budget.RegexBudget.request('198.51.100.7').run(() => safeRegex.safeRegexFullMatch(src, 'r13g6-src-abc'))).toBe(true);
    expect(cache.regexCacheStats().bySource['198.51.100.7']).toBe(1);
  });
});
