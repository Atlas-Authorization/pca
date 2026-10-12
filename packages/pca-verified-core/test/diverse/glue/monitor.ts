// Contract-violation recorder shared by the vi.mock wrappers and the test drivers. A violation = the value the production glue
// produced differs from the independent re-computation. We RECORD (not throw) inside the wrapped call because pca catches errors
// in its own checks and would convert a thrown violation into an ordinary denial; the drivers assert on the record afterwards.
import { appendFileSync, writeFileSync } from 'node:fs';

export interface Violation { id: string; detail: Record<string, unknown> }

export class Monitor {
  readonly counts: Record<string, number> = {};
  readonly violations: Violation[] = [];
  private readonly seenDump = new Set<string>();
  dumpPath = process.env.GLUE_DUMP ?? '';
  dumpMax = Number(process.env.GLUE_DUMP_MAX ?? 300_000);
  private dumped = 0;

  note(id: string, n = 1): void { this.counts[id] = (this.counts[id] ?? 0) + n; }
  violate(id: string, detail: Record<string, unknown>): void { this.note('VIOLATION:' + id); if (this.violations.length < 200) this.violations.push({ id, detail }); }
  /** Append a primitive-call tuple for later replay through the multi-implementation harness (tools/pca-trustbase/primitives run.mjs --suite replay). */
  dump(op: string, ...args: string[]): void {
    if (!this.dumpPath || this.dumped >= this.dumpMax) return;
    const line = [op, ...args].join('\t');
    const k = line.length > 400 ? line.slice(0, 200) + line.length + line.slice(-200) : line;
    if (this.seenDump.has(k)) return;
    this.seenDump.add(k); this.dumped++;
    appendFileSync(this.dumpPath, line + '\n');
  }
  get violationCount(): number { return Object.entries(this.counts).filter(([k]) => k.startsWith('VIOLATION:')).reduce((s, [, n]) => s + n, 0); }
  summary(): Record<string, unknown> { return { counts: this.counts, violations: this.violations }; }
  write(path: string): void { writeFileSync(path, JSON.stringify(this.summary(), null, 1)); }
}
export const monitor = new Monitor();
