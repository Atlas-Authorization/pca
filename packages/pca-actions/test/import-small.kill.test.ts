// Exact outcomes of the import pipeline helpers: the rules digest recorded for a caller-supplied rule set, the order of
// JSON Lines output (including equal verbs), and the lines jsonlToDefs skips or refuses.
import { describe, expect, it } from 'vitest';
import { ActionKitError, DEFAULT_RULES, defsToJsonl, importMcp, jsonlToDefs, suggestDefs, validateDef, type ActionDef, type SuggestRules } from '../src';
import { DEFAULT_RULES_SEALED } from '../src/import/rules';
import { rulesDigest } from '../src/import/suggest';

const thrown = (f: () => unknown): ActionKitError => {
  try { f(); } catch (e) { return e as ActionKitError; }
  throw new Error('expected a throw');
};
const lines = (text: string): string[] => text.split('\n').filter((l) => l.length > 0);
const field = (line: string, k: 'verb' | 'title'): string => (JSON.parse(line) as Record<string, string>)[k]!;

describe('suggestDefs records the digest of the rules it ran', () => {
  it('a caller-supplied rule set is digested, not replaced by the default digest', async () => {
    const imported = importMcp([{ name: 'send_email', inputSchema: { type: 'object', properties: { to: { type: 'string', format: 'email' } } } }], { ns: 'm' }).defs;
    const custom: SuggestRules = { ...DEFAULT_RULES, version: '9.9.9' };
    const s = await suggestDefs(imported, { rules: custom });
    const sb = s.defs[0]!.review.suggested_by as { rules: { digest: string; version: string } };
    expect(sb.rules.version).toBe('9.9.9');
    expect(sb.rules.digest).toBe(rulesDigest(custom));
    expect(sb.rules.digest).not.toBe(DEFAULT_RULES_SEALED.digest);
  });
});

describe('defsToJsonl order', () => {
  it('sorts by verb', () => {
    const defs = importMcp([{ name: 'zeta' }, { name: 'alpha' }, { name: 'mid' }], { ns: 'x' }).defs;
    expect(lines(defsToJsonl(defs)).map((l) => field(l, 'verb'))).toEqual(['x.alpha', 'x.mid', 'x.zeta']);
  });
  it('keeps the input order of defs that share a verb', () => {
    const base = importMcp([{ name: 'alpha' }], { ns: 'x' }).defs[0]!;
    const x: ActionDef = { ...base, title: 'X' };
    const y: ActionDef = { ...base, title: 'Y' };
    expect(lines(defsToJsonl([x, y])).map((l) => field(l, 'title'))).toEqual(['X', 'Y']);
    expect(lines(defsToJsonl([y, x])).map((l) => field(l, 'title'))).toEqual(['Y', 'X']);
  });
});

describe('jsonlToDefs', () => {
  const defs = importMcp([{ name: 'alpha' }], { ns: 'x' }).defs;
  const text = defsToJsonl(defs);

  it('skips lines that are only whitespace and tolerates CRLF', () => {
    const padded = `  \t \n${text.replace(/\n/g, '\r\n')}   \n\r\n`;
    expect(jsonlToDefs(padded).map((d) => d.verb)).toEqual(['x.alpha']);
  });
  it('refuses a line that is JSON but not a def, naming the 1-based line', () => {
    const bad = validateDef({ v: 1 });
    expect(bad).not.toBeNull();
    for (const [input, line] of [[`${text}{"v":1}\n`, 2], [`${text}\n{"v":1}`, 3]] as const) {
      const e = thrown(() => jsonlToDefs(input));
      expect(e).toBeInstanceOf(ActionKitError);
      expect(e.code).toBe('bad_defs');
      expect(e.message).toBe(`line ${line}: ${bad}`);
    }
  });
});
