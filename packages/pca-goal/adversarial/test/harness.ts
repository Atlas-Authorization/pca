import { test } from 'node:test';
import assert from 'node:assert/strict';
import { REF_ONLY, REQUIRE, loadRealSubject, refSubject, type Subject } from '../src/subject.ts';

export const real = await loadRealSubject();
export const subjects: Subject[] = [refSubject, ...(real ? [real] : [])];
// Registers `name` once per subject. A subject lacking a capability is skipped locally; with GOAL_REQUIRE_SUBJECT=1 (CI, after T1
// integrates) a missing real subject or capability FAILS, so a skipped weakness test can never pass a release gate.
export function each(name: string, caps: Array<keyof Subject>, fn: (s: Subject) => void | Promise<void>): void {
  for (const s of subjects) test(`${name} [${s.name}]`, async (t) => {
    const miss = caps.filter((c) => s[c] === undefined);
    if (miss.length) return void t.skip(`subject lacks ${miss.join(',')}`);
    await fn(s);
  });
  const need = caps.filter((c) => !REF_ONLY.has(c));
  if (REQUIRE && need.length) test(`${name} [real subject required]`, () => {
    assert.ok(real, 'GOAL_REQUIRE_SUBJECT=1 but @atlasauth/pca-goal could not be imported');
    const miss = need.filter((c) => real![c] === undefined);
    assert.deepEqual(miss, [], `real subject lacks ${miss.join(',')}`);
  });
}
export { assert };
