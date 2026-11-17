/** Test fixtures: small JSONL logs. Not exported from the package. */
export const NOW = 1_800_000_000_000;
export const DAY = 86_400_000;

export const row = (i: number, o: Record<string, unknown> = {}): string =>
  JSON.stringify({ at: NOW - DAY + i * 1000, verb: 'gmail.draft', resource: `/drafts/${i}`, params: { recipients: 1 + (i % 3) }, ...o });

export const benign = (n = 6): string[] => Array.from({ length: n }, (_, i) => row(i));
export const jsonl = (rows: string[]): string => rows.join('\n');
