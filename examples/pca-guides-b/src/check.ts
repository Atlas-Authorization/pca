// Tiny outcome checker shared by the scripts: print each result, remember failures, exit non-zero at the end.
let failed = 0;

// JSON with object keys sorted, so two equal values print and compare the same however they were built.
function stable(v: unknown): string {
  return JSON.stringify(v, (_k, x: unknown) =>
    x !== null && typeof x === 'object' && !Array.isArray(x)
      ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : x,
  ) ?? 'undefined';
}

export function expectOutcome(label: string, actual: unknown, expected: unknown): void {
  const a = stable(actual);
  const ok = a === stable(expected);
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label} -> ${a}`);
  if (!ok) console.log(`     expected ${stable(expected)}`);
}

export function finish(): never {
  console.log(failed === 0 ? '\nAll outcomes as expected.' : `\n${failed} outcome(s) were not as expected.`);
  process.exit(failed === 0 ? 0 : 1);
}
