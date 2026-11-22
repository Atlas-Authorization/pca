// Oracle: @atlasauth/pca-policy-bridge (Cedar / OPA-Rego / OpenFGA / strict-CEL translators to PCA predicates, and deny-overrides-permit decide).
// Inputs: the engine-checked policy corpora of packages/pca-policy-bridge/differential/fixtures, hand-written policies and models for every
// construct and refusal, and seeded structural / textual mutations of both (deleted spans, junk tokens, truncations) so the hand-written
// parsers are compared on hostile input too. Everything is JSON and compared by value; a throw is {"$throws"}.
// PORTING (fn(args) -> native entry point, comparison rule: JSON value equality of the whole result):
//   cedarToPca(policyText)                -> Cedar.cedarToPca(String)      {predicates, denies, caveats, report{source, translated, skipped, errors}}
//   translateCedar(policyText, guards)    -> Cedar.translateCedar(String, boolean)
//   regoToPca(moduleText)                 -> Rego.regoToPca(String)
//   openfgaToPca(model, tuples)           -> OpenFga.openfgaToPca(Object, Object)   (a null tuples argument is the reference's non-array error)
//   decide(result, ctx)                   -> PolicyBridge.decide(Map, Map)  {allowed, matched?, reason?}
//   celToCondition(expression, schema)    -> Cel.celToCondition(String, Object)    {ok:true, condition, fields} | {ok:false, code, message, at}
//   celToPredicate(expression, schema, scope{verb, resource?}) -> Cel.celToPredicate(String, Object, verb, resource)
//   celConditionsToPca(items, schema)     -> Cel.celConditionsToPca(List, Object)
//   parseCel(expression)                  -> Cel.parseCel(String)           {ok:true, ast} | {ok:false, code, message, at}
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import * as B0 from '../../../packages/pca-policy-bridge/src/index';
import * as CED0 from '../../../packages/pca-policy-bridge/src/cedar';
import { Oracle, refWrite, rng, variants } from './lib.mjs';

const B: any = (B0 as any).default ?? B0;
const { cedarToPca, regoToPca, openfgaToPca, decide, celToCondition, celToPredicate, celConditionsToPca, parseCel } = B;
const translateCedar: any = ((CED0 as any).default ?? CED0).translateCedar;
const o = new Oracle('policy-bridge', 'tools/pca-audit/oracles/policy-bridge.mts', 'TS-reference oracle for @atlasauth/pca-policy-bridge.');
o.utf16Escape = true; // a lone surrogate is written as {"$utf16": [code units]}; every lane's reader decodes it
const FIX = fileURLToPath(new URL('../../../packages/pca-policy-bridge/differential/fixtures/', import.meta.url));
const load = (f: string): any[] => fs.readFileSync(FIX + f, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const r = rng(0x9e3779b1);
let n = 0;
const run = (fn: string, ref: (...a: any[]) => any, args: any[]) => o.run(fn, `#${n++}`, ref, args);

const JUNK = ['{', '}', '(', ')', '[', ']', '"', '&&', '||', '==', '!=', '<=', '>=', '<', '>', ';', ',', '.', '::', '@', '//', '#', '\n', '\t', ' ', '*', '?', '\\', '-', '1', 'x', ' in ', ' is ', ' has ', ' like ', 'not ', ' when ', ' unless ', 'permit', 'forbid', 'input.', 'principal', 'resource', 'action', 'context', 'true', 'allow', ' if ', ':=', '_', 'é', ' ', ' '];
function mutate(s: string): string {
  let out = s;
  for (let i = r.int(1, 3); i > 0; i--) {
    const pos = r.int(0, out.length);
    const k = r.int(0, 4);
    if (k === 0) out = out.slice(0, pos) + out.slice(pos + r.int(1, 8));
    else if (k === 1) out = out.slice(0, pos) + r.pick(JUNK) + out.slice(pos);
    else if (k === 2) out = out.slice(0, pos) + r.pick(JUNK) + out.slice(pos + 1);
    else if (k === 3) out = out.slice(0, pos);
    else out = out.slice(0, pos) + out.slice(pos, pos + r.int(1, 12)) + out.slice(pos);
  }
  return out;
}

// ---- Cedar -----------------------------------------------------------------------------------------------------------------------
const cedarHand = [
  '', ';', '   ', 'permit (principal, action, resource);', 'PERMIT (principal, action, resource);', 'forbid(principal, action, resource);',
  '@id("a") permit (principal, action, resource);', '@id("a")\n@x("b") permit (principal == User::"alice", action == Action::"view", resource == Photo::"p1");',
  'permit (principal in Group::"g", action in [Action::"a", Action::"b"], resource in Folder::"f");', 'permit (principal is User, action, resource is Photo);',
  'permit (principal is Ns::User, action == Ns::Action::"x", resource == Ns::Photo::"p");', 'permit (principal, action == Action::"edit", resource) when { context.hour >= 9 && context.hour < 17 };',
  'permit (principal, action, resource) when { principal.dept == resource.dept } unless { resource.locked == true };', 'permit (principal, action, resource) when { principal has dept };',
  'permit (principal, action, resource) when { resource has owner.id };', 'permit (principal, action, resource) when { context.ip like "10.*" };', 'permit (principal, action, resource) when { context.p like "a\\*b?\\\\c" };',
  'permit (principal, action, resource) when { principal in Group::"x" || principal in [Group::"a", Group::"b"] };', 'permit (principal, action, resource) when { context.tier in ["gold", "silver", 3, true] };',
  'permit (principal, action, resource) when { action == Action::"view" };', 'permit (principal, action, resource) when { action in [Action::"v", Action::"w"] };', 'permit (principal, action, resource) when { action != Action::"v" };',
  'permit (principal, action, resource) when { action < Action::"v" };', 'permit (principal, action, resource) when { action is Action };', 'permit (principal, action, resource) when { principal == resource };',
  'permit (principal, action, resource) when { principal.a == context.b };', 'permit (principal, action, resource) when { resource.size + 1 < 10 };', 'permit (principal, action, resource) when { resource.tags.contains("x") };',
  'permit (principal, action, resource) when { if true then true else false };', 'permit (principal, action, resource) when { ip("1.2.3.4").isInRange(ip("1.0.0.0/8")) };', 'forbid (principal, action, resource) when { resource.size + 1 < 10 };',
  'forbid (principal, action, resource) unless { principal.a == 1 && (principal.b == 2 || principal.c == 3) };', 'permit (principal, action, resource) when { (((principal.a == 1))) };', 'permit (principal, action, resource) when { };',
  'permit (principal, action, resource) when { principal.a == 1', 'permit (principal, action, resource', 'permit principal, action, resource;', 'permit (principal ==, action, resource);', 'permit (principal == "x", action, resource);',
  'permit (action == "x");', 'permit (principal in User, action, resource);', 'permit (principal is 1, action, resource);', 'permit (action is X, principal, resource);', 'permit (action in Action::"x", principal, resource);', 'permit (foo);',
  'permit (principal inx, action, resource);', 'permit (principals, action, resource);', 'permit (principal, action == Action::"v", resource == Photo::"p", resource == Photo::"q");',
  'permit (principal, action, resource) when { 1 == 1 };', 'permit (principal, action, resource) when { context.x == -1.5 } when { context.y != 3 };', 'permit (principal, action, resource) when { context.x == 007 };',
  'permit (principal, action, resource) when { context.s == "a\nb" };', 'permit (principal, action, resource) when { context.s == "é x" };', 'permit (principal, action, resource) // a comment\nwhen { context.a == 1 }; // end',
  'permit (principal, action, resource) when { context.a == "a//b" };', 'permit (principal, action, resource);permit (principal, action, resource);forbid (principal, action, resource);',
  'permit (principal, action, resource) when { principal.a == 1 || principal.b == 2 || principal.c == 3 } unless { context.d == 4 && context.e == 5 && context.f == 6 };',
  'permit (principal, action, resource) when { principal has a && principal.a.b == 1 };', 'permit (principal, action, resource) when { context.a.b.c has d };', 'permit (principal, action, resource) when { principal in context.group };',
  'permit (principal, action, resource) when { resource in principal.folder };', 'permit (principal, action, resource) when { context in Group::"x" };', 'permit (principal, action, resource) when { principal like "a*" };',
  'permit (principal, action, resource) when { principal.n like 5 };', 'permit (principal, action, resource) when { principal.n is User };', 'permit (principal, action, resource) when { principal.n is 5 };',
  'permit (principal, action, resource) when { principal.n in [Group::"a", 5] };', 'permit (principal, action, resource) when { principal.n in [] };', 'permit (principal, action, resource) when { principal.n in [ };',
  'permit (principal, action, resource) when { principal.n in ["a", Group::"b"] };', 'permit (principal, action, resource) when { x };', 'permit (principal, action, resource) when { true };',
  'permit    (principal, action, resource) when { context.a == 1 };', 'permit (principal, action, resource) whenever { context.a == 1 };', 'permit (principal, action, resource) éwhen { context.a == 1 };',
];
const cedarFix = load('cedar.jsonl');
const cedarTexts: string[] = [...cedarHand];
for (const c of cedarFix.slice(0, 230)) cedarTexts.push(c.policies);
const cedarBase = [...cedarHand, ...cedarFix.slice(0, 60).map((c) => c.policies)];
for (let i = 0; i < 450; i++) cedarTexts.push(mutate(r.pick(cedarBase)));
for (const t of cedarTexts) await run('cedarToPca', cedarToPca, [t]);
for (const t of cedarTexts.slice(0, 120)) await run('translateCedar', translateCedar, [t, false]);
for (const t of cedarTexts.slice(0, 60)) await run('translateCedar', translateCedar, [t, true]);

const uid = (s: string) => s.replace(/"/g, '');
for (const c of cedarFix.slice(0, 110)) {
  const res = JSON.parse(JSON.stringify(cedarToPca(c.policies)));
  const attrs = new Map<string, Record<string, unknown>>();
  const parents: Record<string, string[]> = {};
  for (const e of c.entities) {
    const k = `${e.uid.type}::${e.uid.id}`;
    attrs.set(k, e.attrs);
    parents[k] = e.parents.map((p: any) => `${p.type}::${p.id}`);
  }
  for (const q of c.requests.slice(0, 3)) {
    const p = uid(q.principal), rs = uid(q.resource);
    await run('decide', decide, [res, { subject: { id: p, ...(attrs.get(p) ?? {}) }, action: { verb: uid(q.action).split('::')[1], resource: rs }, env: { ...q.context, resource: attrs.get(rs) ?? {}, entity_parents: parents } }]);
  }
}

// ---- Rego ------------------------------------------------------------------------------------------------------------------------
const regoHand = [
  '', 'package a.b', 'package a\ndefault allow = false\nallow { input.action == "read" }', 'package a\ndefault allow := true\nallow { input.action == "read" }', 'default allow = false',
  'allow { input.action == "read"; input.resource == "r" }', 'allow = true { input.action == "read" }', 'allow := true { input.action == "read" }', 'allow if { input.action == "read" }', 'allow if {\n input.action in {"a","b"}\n input.action in ["b","c"]\n}',
  'allow { input.action == "a"; input.action == "b" }', 'allow { input.resource == "r"; input.resource == "s" }', 'allow { input.action == "a"; input.action in {"a","b"} }', 'allow { input.action in {"a",1} }', 'allow { input.action in input.xs }',
  'allow { input.n < 3; input.n >= 1; input.n > 0; input.n <= 9 }', 'allow { input.n < "x" }', 'allow { input.n != 3; input.s != "x"; input.b == true; input.f == -2.5 }', 'allow { input.a == input.b; input.c != input.d }',
  'allow { input.role in {"a","b"}; input.level == 3 }', 'allow { not input.role == "admin" }', 'allow { not input.n > 3 }', 'allow { not input.a == input.b }', 'allow { not input.action == "x" }', 'allow { not not input.n > 3 }', 'allow { not startswith(input.p, "x") }',
  'allow { startswith(input.p, "/api") }', 'allow { startswith(input.p, "/a\\"pi") }', 'allow { glob.match("a*", null, input.p) }', 'allow { glob.match("a*", [], input.p) }', 'allow { glob.match("abc", [], input.p) }', 'allow { glob.match("a[bc]", null, input.p) }',
  'allow { glob.match("a{b,c}", null, input.p) }', 'allow { glob.match("a?", null, input.p) }', 'allow { glob.match("a\\\\*", null, input.p) }', 'allow { x := 1 }', 'allow { some i; input.xs[i] == 1 }', 'allow { every x in input.xs { x > 1 } }', 'allow { input.xs[_] == 1 }',
  'allow { count(input.xs) > 1 }', 'allow { input.flag }', 'allow { "a" in input.xs }', 'allow { regex.match("a", input.p) }', 'allow { endswith(input.p, "x") }', 'allow { [x | x := 1] }',
  'allow { input.a == 1 }\nallow { input.b == 2 }\nallow { input.c == 3 }', 'allow { input.a == 1', 'allow {', 'allow { input.a == 1 } allow { input.b ==', 'allow { }', 'allow {\n\n}', 'allowx { input.a == 1 }', 'xallow { input.a == 1 }', 'allow   { input.a == 1 }',
  '# comment\nallow { input.a == 1 } # trail', 'allow { input.a == "#" }', 'allow { input.s == "a;b" }', 'allow { input.set in {"a;b", "c"} }', 'allow { input.set in ["a", {"b"}] }', 'allow { input.set in {} }', 'allow { input.set in [1.5, -2, true, "x"] }',
  'allow { input.a.b.c == 1 }', 'allow { input.a == 1; input.b in ["x"]; not input.c == 2 }', 'allow { input.n == 007 }', 'allow { input.s == "é" }', 'allow { input.s ==   "x"   }', 'allow {input.s=="x"}', 'allow {input.n<3}', 'allow {input.k in{"a"}}', 'allow { input.kin {"a"} }',
  'default allow = false\ndefault allow = true', 'package   x.y\n\n', 'package\n', 'allow { input.action == "a" }\n', 'allow { input.action == "read"\n input.n > 2 }',
];
const regoFix = load('rego.jsonl');
const regoTexts: string[] = [...regoHand, ...regoFix.slice(0, 230).map((c) => c.module)];
const regoBase = [...regoHand, ...regoFix.slice(0, 60).map((c) => c.module)];
for (let i = 0; i < 380; i++) regoTexts.push(mutate(r.pick(regoBase)));
for (const t of regoTexts) await run('regoToPca', regoToPca, [t]);
for (const c of regoFix.slice(0, 80)) {
  const res = JSON.parse(JSON.stringify(regoToPca(c.module)));
  for (const input of c.inputs.slice(0, 3)) {
    const { action, resource, ...rest } = input;
    await run('decide', decide, [res, { subject: { id: 's' }, action: { verb: action, resource }, env: rest }]);
  }
}

// ---- OpenFGA ---------------------------------------------------------------------------------------------------------------------
const MODEL = { schema_version: '1.1', type_definitions: [{ type: 'user' }, { type: 'group', relations: { member: { this: {} } } }, { type: 'folder', relations: { owner: { this: {} }, viewer: { this: {} }, can_view: { union: { child: [{ computedUserset: { relation: 'viewer' } }, { computedUserset: { relation: 'owner' } }] } } } }, { type: 'doc', relations: { parent: { this: {} }, owner: { this: {} }, viewer: { this: {} }, banned: { this: {} }, can_read: { difference: { base: { union: { child: [{ this: {} }, { tupleToUserset: { tupleset: { relation: 'parent' }, computedUserset: { relation: 'can_view' } } }] } }, subtract: { computedUserset: { relation: 'banned' } } } }, both: { intersection: { child: [{ computedUserset: { relation: 'viewer' } }, { computedUserset: { relation: 'owner' } }] } } } }] };
const TUPLES = [{ user: 'user:a', relation: 'viewer', object: 'doc:1' }, { user: 'user:b', relation: 'owner', object: 'doc:1' }, { user: 'user:a', relation: 'owner', object: 'doc:1' }, { user: 'user:b', relation: 'banned', object: 'doc:2' }, { user: 'folder:f', relation: 'parent', object: 'doc:2' }, { user: 'user:b', relation: 'viewer', object: 'folder:f' }, { user: 'user:c', relation: 'owner', object: 'folder:f' }, { user: 'user:*', relation: 'viewer', object: 'doc:3' }, { user: 'user:*', relation: 'viewer', object: 'folder:g' }, { user: 'group:eng#member', relation: 'viewer', object: 'doc:1' }, { user: 'user:a', relation: 'banned', object: 'doc:3' }, { user: 'ghost:x', relation: 'viewer', object: 'nothing:1' }, { user: 'doc:1', relation: 'parent', object: 'doc:2' }, { user: 'doc:2', relation: 'parent', object: 'doc:1' }, { user: 'user:d', relation: 'viewer', object: 'doc:4' }, { user: 'user:d', relation: 'owner', object: 'doc:4' }];
const ofgaHand: [any, any][] = [
  [MODEL, TUPLES], [MODEL, []], [MODEL, null], [MODEL, 'x'], [MODEL, {}], [null, TUPLES], [5, []], [[], []], [{}, []], [{ type_definitions: 'x' }, []], [{ type_definitions: [] }, TUPLES],
  [{ type_definitions: [null, 1, 'x', [], { type: 5 }, { type: '' }, { type: 'a' }] }, TUPLES], [{ type_definitions: [{ type: 'doc', relations: { viewer: { this: {} } } }] }, [{ user: 'user:a', relation: 'viewer', object: 'doc:1' }, null, 5, { user: 1 }, { user: 'u', relation: 'r' }, [], { user: 'user:a', relation: 'viewer', object: 'doc:1' }]],
  [{ type_definitions: [{ type: 'doc', relations: [{ this: {} }, { this: {} }] }] }, [{ user: 'user:a', relation: '0', object: 'doc:1' }]],
  [{ type_definitions: [{ type: 'doc', relations: { '2': { this: {} }, b: { this: {} }, '1': { this: {} }, a: { computedUserset: { relation: 'b' } } } }] }, [{ user: 'user:a', relation: 'b', object: 'doc:1' }, { user: 'user:a', relation: '1', object: 'doc:1' }]],
  [{ type_definitions: [{ type: 'doc', relations: { v: { this: {} } } }, { type: 'doc', relations: { w: { this: {} } } }] }, [{ user: 'user:a', relation: 'w', object: 'doc:1' }]],
  [{ type_definitions: [{ type: 'doc', relations: { a: { computedUserset: {} }, b: { computedUserset: { relation: '' } }, c: { union: {} }, d: { union: { child: [] } }, e: { union: { child: [1, {}, { this: {} }] } }, f: { intersection: {} }, g: { intersection: { child: [] } }, h: { intersection: { child: [{ this: {} }, 5] } }, i: { intersection: { child: [{ this: {} }, {}] } }, j: { difference: 5 }, k: { difference: {} }, l: { difference: { base: { this: {} }, subtract: {} } }, m: { difference: { base: {}, subtract: { this: {} } } }, n: { tupleToUserset: 5 }, o: { tupleToUserset: {} }, p: { tupleToUserset: { tupleset: { relation: 'x' } } }, q: { tupleToUserset: { tupleset: { relation: 'x' }, computedUserset: { relation: 'y' } } }, r: {}, s: [], t: 5, u: null, v: { union: { child: [{ union: { child: [{}, { this: {} }] } }] } }, w: { difference: { base: { union: { child: [{}, { this: {} }] } }, subtract: { this: {} } } } } }] }, [{ user: 'user:a', relation: 'e', object: 'doc:1' }, { user: 'user:a', relation: 'q', object: 'doc:1' }, { user: 'doc:2', relation: 'x', object: 'doc:1' }, { user: 'user:a', relation: 'v', object: 'doc:1' }, { user: 'user:a', relation: 'w', object: 'doc:1' }]],
  [{ type_definitions: [{ type: 'doc', relations: { a: { computedUserset: { relation: 'b' } }, b: { computedUserset: { relation: 'a' } }, c: { this: {} } } }] }, [{ user: 'user:a', relation: 'c', object: 'doc:1' }]],
  [{ type_definitions: [{ type: 'doc', relations: { p: { this: {} }, v: { union: { child: [{ this: {} }, { tupleToUserset: { tupleset: { relation: 'p' }, computedUserset: { relation: 'v' } } }] } } } }] }, [{ user: 'doc:2', relation: 'p', object: 'doc:1' }, { user: 'doc:3', relation: 'p', object: 'doc:2' }, { user: 'user:a', relation: 'v', object: 'doc:3' }, { user: 'doc:1', relation: 'p', object: 'doc:3' }]],
  [{ type_definitions: [{ type: 'doc', relations: { v: { this: {} }, w: { difference: { base: { this: {} }, subtract: { computedUserset: { relation: 'v' } } } } } }] }, [{ user: 'user:*', relation: 'w', object: 'doc:1' }, { user: 'user:a', relation: 'v', object: 'doc:1' }, { user: 'user:b', relation: 'w', object: 'doc:1' }, { user: 'team:*', relation: 'w', object: 'doc:2' }, { user: 'a*?\\:*', relation: 'w', object: 'doc:2' }, { user: 'a*?\\:x', relation: 'w', object: 'doc:2' }]],
  [{ type_definitions: [{ type: 'doc', relations: { v: { this: {} } } }] }, [{ user: ':*', relation: 'v', object: 'doc:1' }, { user: 'x:*#y', relation: 'v', object: 'doc:1' }, { user: '*', relation: 'v', object: 'doc:1' }, { user: 'a:b:*', relation: 'v', object: 'doc:1' }, { user: 'noColon', relation: 'v', object: 'doc:1' }, { user: 'u:1', relation: 'v', object: 'nocolon' }, { user: 'u:1', relation: 'v', object: 'a\u0000b' }]],
];
const ofgaFix = load('openfga.jsonl');
const ofgaCases: [any, any][] = [...ofgaHand, ...ofgaFix.slice(0, 80).map((c): [any, any] => [c.model, c.tuples])];
for (const [, v] of [...variants(MODEL, { maxPaths: 400 })].filter((_, i) => i % 6 === 0).slice(0, 220).entries()) ofgaCases.push([v[1], TUPLES]);
for (const [, v] of [...variants(TUPLES, { maxPaths: 400 })].filter((_, i) => i % 9 === 0).slice(0, 140).entries()) ofgaCases.push([MODEL, v[1]]);
for (const [m, t] of ofgaCases) await run('openfgaToPca', openfgaToPca, [m, t]);
for (const c of ofgaFix.slice(0, 50)) {
  const res = JSON.parse(JSON.stringify(openfgaToPca(c.model, c.tuples)));
  for (const k of c.checks.slice(0, 4)) await run('decide', decide, [res, { subject: { id: k.user }, action: { verb: k.relation, resource: k.object } }]);
}

// ---- decide on hand-built results (combining rule, fail-closed paths) ---------------------------------------------------------------
const ctx0 = { subject: { id: 'u1', dept: 'eng' }, action: { verb: 'read', resource: 'doc:1' }, env: { hour: 10 } };
const P = (verb: any, where?: any[]) => ({ verb, ...(where ? { where } : {}) });
const decideCases: any[] = [
  [{ predicates: [P('read')], denies: [] }, ctx0], [{ predicates: [], denies: [] }, ctx0], [{ predicates: [P('read')], denies: [P('read')] }, ctx0], [{ predicates: [P('read')], denies: [P('write')] }, ctx0],
  [{ predicates: [P('write')], denies: [] }, ctx0], [{ predicates: [P('read')], denies: [], report: { source: 'cedar', translated: [], skipped: [], errors: ['x'] } }, ctx0], [{ predicates: [P('read')], denies: [], report: { source: 'cedar', translated: [], skipped: ['s'], errors: [] } }, ctx0],
  [{ predicates: [P(['read', 'write'], [{ field: 'subject.dept', op: 'eq', value: 'eng' }])], denies: [P('*', [{ field: 'env.hour', op: 'gt', value: 20 }])] }, ctx0], [{ predicates: [P(['read', 'write'], [{ field: 'subject.dept', op: 'eq', value: 'eng' }])], denies: [P('*', [{ field: 'env.hour', op: 'lt', value: 20 }])] }, ctx0],
  [{ predicates: [P('read', [{ field: 'env.hour', op: 'gt', value: 20 }])], denies: [] }, ctx0], [{ predicates: [{ verb: 'read', resource: 'doc:*' }], denies: [{ verb: 'read', resource: 'doc:2' }] }, ctx0], [{ predicates: [{ verb: 'read', resource: 'doc:*' }], denies: [{ verb: 'read', resource: 'doc:1' }] }, ctx0],
  [{ predicates: [P('read')], denies: [] }, { action: { verb: 5, resource: 'x' } }], [{ predicates: [P('read')], denies: [] }, {}], [{ predicates: 'x', denies: [] }, ctx0], [{ predicates: [5, null, P('read')], denies: [] }, ctx0],
];
for (const [rs, cx] of decideCases) await run('decide', decide, [rs, cx]);

// ---- CEL -------------------------------------------------------------------------------------------------------------------------
const SCHEMA = { vars: { 'resource.name': { path: 'action.params.name', type: 'string' }, 'object.spec.replicas': { path: 'action.params.count', type: 'int' }, 'request.flag': { path: 'env.flag', type: 'bool' }, 'request.time': { path: 'env.now', type: 'timestamp_ms' }, 'resource.tag': { path: 'action.params.opt', type: 'string', optional: true }, 'principal.org': { path: 'subject.other', type: 'string' }, s: { path: 'env.s', type: 'string' }, n: { path: 'env.n', type: 'int' }, b: { path: 'env.b', type: 'bool' }, a: { path: 'env.a', type: 'string' }, z: { path: 'env.z', type: 'string' }, ob: { path: 'env.ob', type: 'bool', optional: true } } };
const EXPRS = [
  'resource.name == "abc"', 'resource.name != "abc"', '"abc" == resource.name', 'resource.name == principal.org', 'resource.name != principal.org', 'object.spec.replicas <= 5', '5 >= object.spec.replicas', 'object.spec.replicas < 5 || object.spec.replicas > 7',
  '!(object.spec.replicas > 5)', 'object.spec.replicas == -3', 'object.spec.replicas == - 3', 'request.flag == true', '!(request.flag == true)', 'request.flag != false', 'true == request.flag', 'request.flag < true', 'request.time < timestamp("2030-01-01T00:00:00Z")',
  'request.time >= timestamp("2030-01-01T00:00:00.000Z")', 'timestamp("2030-01-01T00:00:00Z") > request.time', 'request.time == timestamp("2030-01-01T00:00:00.5Z")', 'request.time == timestamp("2030-01-01T00:00:00.12Z")', 'request.time == timestamp("0000-01-01T00:00:00Z")',
  'request.time == timestamp("2024-02-29T23:59:59.999Z")', 'request.time == timestamp("2023-02-29T00:00:00Z")', 'request.time == timestamp("2030-13-01T00:00:00Z")', 'request.time == timestamp("2030-01-01T24:00:00Z")', 'request.time == timestamp("2030-01-01T23:59:60Z")',
  'request.time == timestamp("2030-01-01T00:00:00")', 'request.time == timestamp("2030-01-01T00:00:00+01:00")', 'request.time == timestamp("2030-01-01T00:00:00.1234Z")', 'request.time == timestamp(resource.name)', 'request.time == timestamp(1)', 'request.time == timestamp()', 'request.time == timestamp("a", "b")',
  'resource.name in ["abc", "xyz"]', '!(resource.name in ["abc"])', 'object.spec.replicas in [3, 8]', 'object.spec.replicas in ["a"]', 'object.spec.replicas in []', 'object.spec.replicas in 5', 'object.spec.replicas in [object.spec.replicas]', 'resource.name in [resource.name]', '"a" in ["a"]', '3 in [3]',
  'resource.name.startsWith("a")', 'resource.name.endsWith("c")', 'resource.name.contains("b")', '!resource.name.endsWith("c")', 'resource.name.contains("*")', 'resource.name.contains("")', 'resource.name.startsWith("")', 'resource.name.startsWith(resource.name)', 'resource.name.endsWith("a\\\\b?c*")',
  `resource.name.contains("${'x'.repeat(300)}")`, `resource.name.contains("${'x'.repeat(256)}")`, `resource.name.endsWith("${'?'.repeat(255)}")`, 'object.spec.replicas.startsWith("a")', '"abc".startsWith("a")', 'resource.name.startsWith("a", "b")', 'resource.name.startsWith()', 'resource.name.size()', 'resource.name.matches("a")',
  'has(resource.tag)', '!has(resource.tag)', 'has(resource.tag) && resource.tag == "abc"', 'has(resource.name)', 'has(zzz)', 'has(1)', 'has()', 'has(resource.tag, resource.name)', 'has(ob)', 'b', 's', 'zzz', 'zzz == 1', 'zzz.startsWith("a")', 'true', 'false', '1', '"x"', '[1]', '1 == 1', '"a" == "b"', '1 < n == true',
  'resource.name == "abc" && object.spec.replicas <= 5 && request.flag == true', 'resource.name == "abc" || object.spec.replicas <= 5', '(resource.name == "abc" || principal.org == "b") && request.flag != true', 'resource.name < "b"', 'principal.org >= "b"',
  '!(resource.name.startsWith("a") && request.flag == true) || object.spec.replicas == 3', 's == \'x\'', "s == 'it\\'s'", 's == "tab\\there"', 's == "nl\\n"', 's == "cr\\r"', 's == "q\\""', 's == "bs\\\\"', 's == "u\\u0041"', 's == "x\\x41"', 's == "\\a"', 's == "\\', 's == "abc', "s == 'abc", 's == "a\nb"',
  's == r"abc"', 's == R\'abc\'', 's == b"abc"', 's == B"abc"', 's == """abc"""', "s == '''abc'''", 's == rb"x"', 'n == 1.5', 'n == 1e3', 'n == 1E3', 'n == 1u', 'n == 1U', 'n == 0x10', 'n == 0X10', 'n == 007', 'n == 0', 'n == -0', 'n == 9007199254740991', 'n == 9007199254740992', 'n == -9007199254740991', 'n == -9007199254740993', `n == ${'9'.repeat(400)}`,
  'n == 1 + 2', 'n == 1 - 2', 'n - 1 == 2', 'n * 2 == 4', 'n / 2 == 4', 'n % 2 == 0', 'b ? 1 : 2', 'n == (b ? 1 : 2)', 'n == {1}', 'n == a.b', 'n == n[0]', 's[0] == "a"', 'n == [1][0]', 'n == null', 'n @ 1', 'n = 1', 'n & 1', 'n | 1', 'n ^ 1', '~n', '`n` == 1', 'n == 1 // c', 'n == 1 /', 'n == 1 ? 2',
  'n < 1 < 2', 'n == 1 == true', 'n < 1 in [1]', 'n in [1] in [2]', 'n in [1] == b', '-n == 1', '- -1 == n', '!!!!b == true', '!n', '!(n)', '!(n == 1)', '((n == 1))', '(n == 1', 'n == 1)', '()', '(', ')', '', ' ', '\n\t', '&&', 'n == 1 &&', '|| n == 1', 'n == 1 && && n == 2', 'n ==', '== 1', 'n 1', 'n == 1 2', 'in', 'n in', 'in [1]', 'n.', 'n..a', '.n', 'n.1', 'n.a b', '"a".b', '1.a', 'n(', 'n()', 'size(s) > 1', 'int(s) == 1', 'string(n) == "a"', 'duration("1s")', 'type(n) == int', 'dyn(n) == 1', 'matches(s, "a")', 'optional.of(1)', 'foo(1)', 'has', 'timestamp', 'null', 'n == null',
  '[1, 2', '[1, 2,', '[1,, 2]', '[,]', `n in [${Array.from({ length: 64 }, (_, i) => i).join(',')}]`, `n in [${Array.from({ length: 65 }, (_, i) => i).join(',')}]`, `n in [${Array.from({ length: 64 }, () => 's').join(',')}]`,
  Array.from({ length: 40 }, () => '(').join('') + 'n == 1' + Array.from({ length: 40 }, () => ')').join(''), Array.from({ length: 32 }, () => '(').join('') + 'n == 1' + Array.from({ length: 32 }, () => ')').join(''), Array.from({ length: 33 }, () => '(').join('') + 'n == 1' + Array.from({ length: 33 }, () => ')').join(''),
  Array.from({ length: 40 }, () => '!').join('') + 'b == true', Array.from({ length: 32 }, () => '!').join('') + '(b == true)', Array.from({ length: 31 }, () => '!').join('') + '(b == true)',
  Array.from({ length: 130 }, (_, i) => `n == ${i}`).join(' || '), Array.from({ length: 129 }, (_, i) => `n == ${i}`).join(' || '), Array.from({ length: 80 }, () => 's == "a"').join(' && '), `s == "${'x'.repeat(4100)}"`, 'n == 1 ' + ' '.repeat(4100), 'a == z && a == z', 'a != z || z < a',
  'a == "x" && z == "y"', 'z == \'x\' && a == \'y\'', 'z == "x" || a == "y" && n > 3', '(a == "x" || z == "y") && n > 3 || b == true', 'a.startsWith("x") && !z.contains("y") || a.endsWith("*")', 'é == 1', 'n == 1 é', 'n == "é"', 's == "é😀"', 's == " "', ' n == 1', 'n == 1',
  'n == 1 && ob', 'has(ob) && n == 1', '!has(ob) || n == 2', 'has(ob) == true',
];
const exprs: string[] = [...EXPRS];
const exprBase = EXPRS.filter((e) => e.length < 200);
for (let i = 0; i < 520; i++) exprs.push(mutate(r.pick(exprBase)));
for (const e of exprs) {
  await run('celToCondition', celToCondition, [e, SCHEMA]);
  await run('parseCel', parseCel, [e]);
}
for (const e of [null, undefined, '', ' ']) await run('celToCondition', celToCondition, [e, SCHEMA]);
await run('parseCel', parseCel, [null]);
const SMALL = { vars: { s: { path: 'env.s', type: 'string' }, n: { path: 'env.n', type: 'int' } } };
const badSchemas: any[] = [5, null, [], 'x', true, {}, { vars: null }, { vars: [] }, { vars: 5 }, { vars: { s: undefined } }, { vars: { s: null } }, { vars: { s: 5 } }, { vars: { s: [] } }, { vars: { s: {} } }, { vars: { s: { path: 'env.x' } } }, { vars: { s: { path: 'env.x', type: 'float' } } },
  { vars: { s: { path: ['env.x'], type: 'string' } } }, { vars: { s: { path: 'env', type: 'string' } } }, { vars: { s: { path: 'foo.x', type: 'string' } } }, { vars: { s: { path: 'env.x.', type: 'string' } } }, { vars: { s: { path: 'env..x', type: 'string' } } }, { vars: { s: { path: 'env.1x', type: 'string' } } },
  { vars: { s: { path: 'env.__proto__', type: 'string' } } }, { vars: { s: { path: 'env.constructor.x', type: 'string' } } }, { vars: { s: { path: 'env.prototype', type: 'string' } } }, { vars: { '': { path: 'env.x', type: 'string' } } }, { vars: { '1': { path: 'env.x', type: 'string' } } }, { vars: { 'a-b': { path: 'env.x', type: 'string' } } },
  { vars: { 'a.': { path: 'env.x', type: 'string' } } }, { vars: { '.a': { path: 'env.x', type: 'string' } } }, { vars: { 'a.__proto__': { path: 'env.x', type: 'string' } } }, { vars: { constructor: { path: 'env.x', type: 'string' } } }, { vars: { s: { path: 'env.x', type: 'string', optional: 'yes' } } }, { vars: { s: { path: 'env.x', type: 'string', optional: null } } },
  { vars: { s: { path: 'env.x', type: 'string', optional: false } } }, { vars: { s: { path: 'env.x', type: 'string', optional: true } } }, { vars: { b: { path: 'env.y', type: 'string' }, s: { path: 'env.x', type: 'nope' }, '2': { path: 'x', type: 'string' } } }, { vars: { s: { path: 'env.x', type: 'int' }, extra: 1 } }, { vars: {}, other: 1 },
  { vars: { s: { path: 'action.params.x', type: 'string' }, t: { path: 'subject.y.z', type: 'int' } } }, { vars: { 's.t': { path: 'env.a', type: 'string' }, s: { path: 'env.b', type: 'string' } } }];
for (const sc of badSchemas) { await run('celToCondition', celToCondition, ['s == "a"', sc]); await run('celToCondition', celToCondition, ['has(s)', sc]); }
await run('celToCondition', celToCondition, ['s == "a" && n == 1', SMALL]);
await run('celToCondition', celToCondition, ['constructor == 1', SMALL]);
await run('celToCondition', celToCondition, ['toString == 1', SMALL]);
await run('celToCondition', celToCondition, ['__proto__ == 1', SMALL]);
for (const [e, sc, scope] of [
  ['s == "x"', SMALL, { verb: 'read' }], ['s == "x"', SMALL, { verb: 'read', resource: 'R::1' }], ['s == "x"', SMALL, { verb: ['a', 'b'], resource: 'R::1' }], ['n == 1 && s == "y"', SMALL, { verb: '*' }], ['q == 1', SMALL, { verb: 'read' }], ['s ==', SMALL, { verb: 'read', resource: 'r' }],
  ['s == "x"', 5, { verb: 'read' }], ['s == "x"', SMALL, { verb: 'read', resource: '' }], ['has(s)', SMALL, { verb: [] }],
] as any[]) await run('celToPredicate', celToPredicate, [e, sc, scope]);
for (const e of EXPRS.slice(0, 60)) await run('celToPredicate', celToPredicate, [e, SCHEMA, { verb: 'v', resource: 'r' }]);
const items = [{ name: 'p1', expression: 's == "x"', verb: 'read' }, { name: 'p2', expression: 'z == "x" && a == "y"', verb: ['a', 'b'], resource: 'R::1' }, { name: 'bad', expression: 'q == 1', verb: 'read' }, { name: 'bad2', expression: 's ==', verb: 'read' }, { name: 'p3', expression: 'n > 3', verb: 'w' }];
for (const sel of [[], [0], [0, 1], [0, 1, 2], [2], [3], [0, 4], [0, 1, 2, 3, 4], [4, 4]]) await run('celConditionsToPca', celConditionsToPca, [sel.map((i) => items[i]), SCHEMA]);
await run('celConditionsToPca', celConditionsToPca, [[{ name: 'x', expression: 's == "x"', verb: 'read' }], 5]);
for (const it of items) { const res = JSON.parse(JSON.stringify(celConditionsToPca([it], SCHEMA))); await run('decide', decide, [res, { action: { verb: 'read', resource: 'r' }, env: { s: 'x', n: 5, z: 'x', a: 'y' } }]); await run('decide', decide, [res, { action: { verb: 'w', resource: 'r' }, env: { n: 5 } }]); }

refWrite(o, 'policy-bridge');
