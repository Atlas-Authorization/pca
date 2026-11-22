// Oracle: the YAML text pca-actions' defsToYaml (import/registry.ts) writes, TS reference (the yaml package's default stringify). Written for the
// Java lane; reusable by any native that writes the same text.
// PORTING: defsToYaml(ns, defs, rules) -> the document text (ends in "\n"); `rules` maps a verb to the value re-attached as the def's `rules` member
//   (an own-key lookup; {} when none). defs are plain JSON objects here (no shared references: the reference would write anchors and aliases for those).
//   A throw is not expected for these inputs. The cases stress the scalar rules: plain vs quoted vs block scalars, folding at 80 columns, escapes,
//   numbers (-0, 1e21, 0.1), empty collections, index-like and awkward keys, nested sequences, `rules` merging.
import { Oracle, refWrite, rng } from './lib.mjs';
const { defsToYaml }: any = await import('../../../packages/pca-actions/src/import/registry.ts');
const o = new Oracle('core-yaml-java', 'tools/pca-audit/oracles/core-yaml-java.mts', 'TS-reference oracle for defsToYaml (the yaml package default stringify).');
const R = rng(20260);
const FRAG = ['alpha', 'beta', 'gamma', 'the', 'quick', 'brown', 'fox', 'jumps', 'over', 'lazy', 'dog', 'refund', 'a customer', 'charge', 'x', '-', '--', '---', '...', '#', ' #c', ':', ': ', ' :', '?', '? ', '- ', '"', "'", '\\', '\n', '\n\n', ' \n', '\n ', '\t', '  ', '{', '}', '[', ']', ',', '&', '*', '!', '|', '>', '%', '@', '`', 'null', 'true', 'false', '~', 'yes', 'no', '0', '1', '-1', '1.5', '1e3', '0x1f', '0o7', '.inf', '.nan', 'é', '☃', '\u{1F600}', '\u0007', '\u0000', '\u007f', '\u0085', ' ', ' ', ' ', '\ud800', 'x'.repeat(30), 'y'.repeat(90), 'word '.repeat(20)];
const str = (maxParts = 8) => { const n = R.int(0, maxParts); let s = ''; for (let i = 0; i < n; i++) s += R.pick(FRAG) + (R.next() < 0.5 ? ' ' : ''); return s; };
const NUMS = [0, -0, 1, -1, 5, 42, 0.1, 1.5, -2.5, 1e21, 1e-7, 123456789012, 2 ** 53 - 1, 0.30000000000000004, 1e300, 5e-324];
const scalar = () => { const k = R.int(0, 9); return k < 5 ? str() : k < 7 ? R.pick(NUMS) : k < 8 ? R.next() < 0.5 : null; };
function value(depth: number): any {
  const k = R.int(0, depth > 0 ? 5 : 3);
  if (k <= 3) return scalar();
  if (k === 4) { const n = R.pick([0, 1, 2, 3, 5]); return Array.from({ length: n }, () => value(depth - 1)); }
  const n = R.pick([0, 1, 2, 3, 4]);
  const m: any = {};
  for (let i = 0; i < n; i++) m[R.next() < 0.7 ? 'k' + R.int(0, 99) : str(2)] = value(depth - 1);
  return m;
}
const def = (verb: string, extra: any = {}) => ({ verb, description: str(14), reversibility: R.pick(['reversible', 'irreversible']), params: value(2), traits: Array.from({ length: R.int(0, 3) }, () => 'pca.' + R.pick(['money_moving', 'destructive', 'pii'])), ...extra });
let k = 0;
await o.run('defsToYaml', 'empty', defsToYaml, ['acme', [], {}]);
await o.run('defsToYaml', 'one', defsToYaml, ['acme', [def('acme.a.create')], {}]);
for (const ns of ['acme', '', 'a b', 'true', '1', 'null', '-', 'é', 'x'.repeat(100), 'a: b', '# c', "it's", 'q"uote', '0x1f', '1e3', '~', 'multi\nline']) await o.run('defsToYaml', 'ns' + k++, defsToYaml, [ns, [def('acme.a.b')], {}]);
for (let i = 0; i < 700; i++) {
  const n = R.int(0, 4);
  const defs = Array.from({ length: n }, (_, j) => def(`acme.n${j}.act${i}`, R.next() < 0.3 ? { [str(2) || 'e']: value(2) } : {}));
  const rules: any = {};
  for (const d of defs) if (R.next() < 0.3) rules[d.verb] = value(2);
  await o.run('defsToYaml', 'r' + i, defsToYaml, [R.pick(['acme', 'shop', str(2)]), defs, rules]);
}
// string-only stress: one description per case, every length around the folding limit
for (let len = 60; len < 120; len++) {
  await o.run('defsToYaml', 'plain' + len, defsToYaml, ['acme', [{ verb: 'acme.a.b', description: 'word '.repeat(Math.ceil(len / 5)).slice(0, len).trimEnd() }], {}]);
  await o.run('defsToYaml', 'long-nospace' + len, defsToYaml, ['acme', [{ verb: 'acme.a.b', description: 'x'.repeat(len) }], {}]);
  await o.run('defsToYaml', 'multi' + len, defsToYaml, ['acme', [{ verb: 'acme.a.b', description: 'line one of the text\n' + 'word '.repeat(Math.ceil(len / 5)).trimEnd() + '\nlast' }], {}]);
  await o.run('defsToYaml', 'multi-indented' + len, defsToYaml, ['acme', [{ verb: 'acme.a.b', description: 'head ' + 'word '.repeat(Math.ceil(len / 5)) + '\n  indented line\n    more\nback ' + 'w'.repeat(len) }], {}]);
  await o.run('defsToYaml', 'quoted-long' + len, defsToYaml, ['acme', [{ verb: 'acme.a.b', description: 'it\'s a "quoted": ' + 'word '.repeat(Math.ceil(len / 5)) }], {}]);
  await o.run('defsToYaml', 'escape-long' + len, defsToYaml, ['acme', [{ verb: 'acme.a.b', description: 'tab\there \u0007 ' + 'word\n'.repeat(3) + 'word '.repeat(Math.ceil(len / 5)) }], {}]);
}
await o.run('defsToYaml', 'rules-merge', defsToYaml, ['acme', [{ verb: 'a.b.c', x: 1 }, { verb: 'a.b.d', rules: 'old' }, { verb: 'a.b.e' }], { 'a.b.c': { required: ['id'] }, 'a.b.d': [1, 2], constructor: 5 }]);
refWrite(o, 'core-yaml-java');
