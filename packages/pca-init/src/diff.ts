import type { FileChange } from './types';

/** A line diff with two lines of context. LCS for ordinary files; trimmed prefix/suffix when the file is huge. */
export function diffLines(a: string, b: string): string[] {
  const x = a.split('\n');
  const y = b.split('\n');
  let lo = 0;
  while (lo < x.length && lo < y.length && x[lo] === y[lo]) lo++;
  let hx = x.length;
  let hy = y.length;
  while (hx > lo && hy > lo && x[hx - 1] === y[hy - 1]) {
    hx--;
    hy--;
  }
  const mx = x.slice(lo, hx);
  const my = y.slice(lo, hy);
  const ops: { t: ' ' | '-' | '+'; s: string }[] = [];
  for (const s of x.slice(0, lo)) ops.push({ t: ' ', s });
  if (mx.length * my.length > 4_000_000) {
    for (const s of mx) ops.push({ t: '-', s });
    for (const s of my) ops.push({ t: '+', s });
  } else {
    const n = mx.length;
    const m = my.length;
    const L = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i]![j] = mx[i] === my[j] ? L[i + 1]![j + 1]! + 1 : Math.max(L[i + 1]![j]!, L[i]![j + 1]!);
    let i = 0;
    let j = 0;
    while (i < n && j < m) {
      if (mx[i] === my[j]) ops.push({ t: ' ', s: mx[i++]! }), j++;
      else if (L[i + 1]![j]! >= L[i]![j + 1]!) ops.push({ t: '-', s: mx[i++]! });
      else ops.push({ t: '+', s: my[j++]! });
    }
    while (i < n) ops.push({ t: '-', s: mx[i++]! });
    while (j < m) ops.push({ t: '+', s: my[j++]! });
  }
  for (const s of x.slice(hx)) ops.push({ t: ' ', s });
  const out: string[] = [];
  ops.forEach((o, k) => {
    if (o.t !== ' ') out.push(`${o.t} ${o.s}`);
    else if (ops.slice(Math.max(0, k - 2), k + 3).some((p) => p.t !== ' ')) out.push(`  ${o.s}`);
  });
  return out;
}

export function renderChange(c: FileChange): string {
  if (c.generated !== undefined) return `+++ ${c.path}  (new, ${c.generated === 'secret' ? 'secret, generated now, never printed' : 'generated now'}; ${c.why})`;
  if (c.before === null) return [`+++ ${c.path}  (new; ${c.why})`, ...c.after.replace(/\n$/, '').split('\n').map((l) => `+ ${l}`)].join('\n');
  return [`--- ${c.path}  (edited; ${c.why})`, ...diffLines(c.before, c.after)].join('\n');
}
