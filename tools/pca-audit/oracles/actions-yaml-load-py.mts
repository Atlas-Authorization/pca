// Oracle (python lane): loadActionsText of @atlasauth/pca-actions author.ts over YAML and JSON TEXT (the value rules are covered by actions-author.mts).
// PORTING: loadActionsText(text, fmt) -> {ns?, defs, notes, errors, locs, rules}; compare defs/notes/rules/ns/locs exactly. `errors` of a syntax failure
//   ("not YAML: ...", "YAML warning: ...", "not JSON: ...") are compared by prefix and count only (the message text is the YAML library's own); every
//   other error is compared whole including line/column.
import { Oracle, refWrite } from './lib.mjs';
import * as AU0 from '../../../packages/pca-actions/src/author.ts';
const AU: any = (AU0 as any).default ?? AU0;
const o = new Oracle('actions-yaml-load-py', 'tools/pca-audit/oracles/actions-yaml-load-py.mts', 'TS-reference oracle for the authoring-file text loader.');
let n = 0;
const run = (text: string, fmt: string) => o.run('loadActionsText', String(n++), AU.loadActionsText, [text, fmt]);
const ACT = (verb = 'acme.note.read', extra = '') => `  - verb: ${verb}\n    effects: [read]\n    resource: acme.note\n${extra}`;
const BASE = `ns: acme\nactions:\n${ACT()}    params:\n      id: id:acme.note\n      limit: int(0..100)?\n`;
const docs: string[] = [
  BASE,
  `ns: acme\nactions:\n${ACT()}`,
  `ns: acme\nactions:\n${ACT()}${ACT('acme.note.list')}`,
  `# leading comment\n${BASE}# trailing\n`,
  `ns: "acme"\nactions:\n  - {verb: acme.note.read, effects: [read], resource: acme.note, params: {id: "id:acme.note", n: 'int'}}\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects:\n      - read\n    resource: acme.note\n    description: |\n      two\n      lines\n    params:\n      id: id:acme.note\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    description: >-\n      folded\n      text\n`,
  `verb: acme.note.read\neffects: [read]\nresource: acme.note\n`,
  `---\n${BASE}`, `${BASE}...\n`, `${BASE}---\nns: other\n`, `\n\n${BASE}`, '', '# only a comment\n', '~\n', 'null\n', '[]\n', '- a\n- b\n', 'just text\n', '42\n', 'true\n',
  `ns: acme\nactions: []\n`, `ns: acme\n`, `actions:\n${ACT()}`, `ns: 1\nactions:\n${ACT()}`, `ns: true\nactions:\n${ACT()}`, `ns: ~\nactions:\n${ACT()}`,
  `ns: acme\nactions:\n  -\n    verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    params:\n      "quoted key": text\n      'single': text\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    params:\n      1: text\n      true: text\n      null: text\n      1.5: text\n      0x1f: text\n      ~: text\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    params:\n      ? [a, b]\n      : text\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    params:\n      a: text\n      a: text\n`,
  `ns: acme\nns: other\nactions:\n${ACT()}`,
  `ns: acme\nactions:\n  - &x\n    verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n  - *x\n`,
  `base: &b\n  effects: [read]\n  resource: acme.note\nactions:\n  - <<: *b\n    verb: acme.note.read\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    <<: {x: 1}\n`,
  `ns: acme\nactions:\n  - verb: !!str acme.note.read\n    effects: [read]\n    resource: acme.note\n`,
  `ns: acme\nactions:\n  - verb: !custom acme.note.read\n    effects: [read]\n    resource: acme.note\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    params:\n      id: !!binary aGk=\n`,
  `%YAML 1.1\n---\n${BASE}`, `%YAML 1.2\n---\n${BASE}`, `%TAG ! tag:example.com:\n---\n${BASE}`,
  `ns: acme\nactions:\n\t- verb: acme.note.read\n`, `ns: acme\nactions:\n  - verb: acme.note.read\n\teffects: [read]\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n   effects: [read]\n`, `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read\n`, `ns: acme\nactions: [\n`,
  `ns: "unterminated\n`, `ns: 'unterminated\n`, `key: value: nested\n`, `a: b\n  c: d\n`, `- a\nb: c\n`, `ns: acme\n- x\n`, `? a\n? b\n`, `{a: 1, a: 2}\n`, `[1, 2\n`, `a: @bad\n`, `a: \`bad\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    params:\n      amount: money(USD, max=100)\n      when: 2001-12-14\n      t: 2001-12-14t21:59:43.10-05:00\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    extra: yes\n    x2: no\n    x3: on\n    x4: off\n    x5: y\n    x6: n\n    x7: Yes\n    x8: NO\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    n1: 010\n    n2: 0o10\n    n3: 0x1F\n    n4: 1_000\n    n5: .inf\n    n6: -.INF\n    n7: .NaN\n    n8: 1e3\n    n9: 1.5E-3\n    n10: +12\n    n11: -0\n    n12: 0b11\n    n13: 12345678901234567890\n    n14: 0.\n    n15: .5\n    n16: 1.\n    n17: ~\n    n18: Null\n    n19: NULL\n    n20: nULL\n    n21: True\n    n22: tRUE\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    tags: [a, "b", 'c', 1, 2.5, true, null, [x], {y: z}]\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    description: "esc \\n \\t \\u00e9 \\x41 \\\\ \\" \\/ \\  \\_ \\N \\L \\P \\e \\0 \\a \\b \\v \\f \\r"\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    description: 'it''s'\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    description: plain\n      continued\n      here\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    description: "multi\n      line"\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    description: é☃😀\n`,
  `\uFEFFns: acme\nactions:\n${ACT()}`, `ns: acme\r\nactions:\r\n${ACT().replace(/\n/g, '\r\n')}`, `ns: acme\ractions:\r${ACT().replace(/\n/g, '\r')}`,
  `ns: acme   # c\nactions:   # c\n${ACT()}`, `ns: acme\nactions:\n  # c\n${ACT()}`, `ns: acme\nactions:\n${ACT()}\n\n\n   \n`,
  `ns: acme\nactions:\n${ACT()}    rules:\n      required: [id]\n`,
  `ns: acme\nactions:\n${ACT()}    rules:\n      hours: {from: 9, to: 17}\n`,
  `ns: acme\nactions: {verb: acme.note.read}\n`, `ns: acme\nactions:\n  - 1\n  - null\n  - [a]\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    params: {}\n`, `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    params: [a]\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    params:\n      id: id:acme.note\n  - verb: acme.note.list\n    effects: [read]\n    resource: acme.note\n    params:\n      limit: count\n      cursor: text\n`,
  `actions:\n    - verb: acme.note.read\n      effects: [read]\n      resource: acme.note\n      params:\n          id: id:acme.note\n`,
  `actions:\n- verb: acme.note.read\n  effects: [read]\n  resource: acme.note\n`,
  `{"ns": "acme", "actions": [{"verb": "acme.note.read", "effects": ["read"], "resource": "acme.note", "params": {"id": "id:acme.note"}}]}\n`,
  `ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    n: 1e400\n    m: -1e400\n`,
  'x'.repeat(1048577), `ns: acme\ndescription: ${'x'.repeat(1048500)}\n`,
];
for (const d of docs) await run(d, 'yaml');
const J = JSON.stringify;
const jdocs: string[] = [
  J({ ns: 'acme', actions: [{ verb: 'acme.note.read', effects: ['read'], resource: 'acme.note', params: { id: 'id:acme.note' } }] }),
  J({ ns: 'acme', actions: [{ verb: 'acme.note.read', effects: ['read'], resource: 'acme.note', params: { id: 'id:acme.note' } }] }, null, 2),
  J({ verb: 'acme.note.read', effects: ['read'], resource: 'acme.note' }, null, 2), '', '{', '[1,', '{"a":1,}', "{'a': 1}", 'null', '[]', '1', '"s"', '{"ns":"acme","actions":[]}',
  '{"ns":"acme","actions":[{"verb":"acme.note.read","effects":["read"],"resource":"acme.note"}]} trailing', '  \n{"ns":"acme","actions":[{"verb":"acme.note.read","effects":["read"],"resource":"acme.note","params":{"a":"text","a":"int"}}]}',
  '{"ns":"acme","actions":[{"verb":"acme.note.read","effects":["read"],"resource":"acme.note","params":{"a\\tb":"text"}}]}',
  '{"ns":"acme","actions":[{"verb":"acme.note.read","effects":["read"],"resource":"acme.note","description":"\\u00e9\\ud83d\\ude00"}]}',
  '{"ns":"acme","actions":[{"verb":"acme.note.read","effects":["read"],"resource":"acme.note","n":1e400}]}',
  '{"ns":"acme","actions":[{"verb":"acme.note.read","effects":["read"],"resource":"acme.note","n":-0,"m":12345678901234567890}]}',
];
for (const d of jdocs) await run(d, 'json');
for (const d of [BASE]) await run(d, 'json');
refWrite(o, 'actions-yaml-load-py');
