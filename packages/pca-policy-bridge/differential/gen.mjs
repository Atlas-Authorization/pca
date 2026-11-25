// Deterministic generator of policy sets + requests for the differential tests.
// usage: node gen.mjs cedar|rego <count> <seed>   -> JSON lines on stdout (inputs only; engines add decisions)
const [, , kind, countArg = '300', seedArg = '1'] = process.argv;
let st = Number(seedArg) >>> 0;
const rnd = () => {
  st = (st + 0x6d2b79f5) >>> 0;
  let t = st;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const int = (n) => Math.floor(rnd() * n);
const pick = (a) => a[int(a.length)];
const chance = (p) => rnd() < p;
const many = (lo, hi, f) => Array.from({ length: lo + int(hi - lo + 1) }, f);

// ---------------------------------------------------------------- Cedar
const USERS = ['alice', 'bob', 'carol'], GROUPS = ['g0', 'g1', 'g2'], PHOTOS = ['p1', 'p2', 'p3', 'p4'], FOLDERS = ['f0', 'f1'];
const ACTIONS = ['view', 'edit', 'delete'], DEPTS = ['eng', 'ops', 'hr'], IPS = ['10.0.0.1', '10.1.2.3', '192.168.1.1', ''];
const uid = (t, i) => `${t}::"${i}"`;
const cedarAtom = () => {
  const roll = int(22);
  switch (roll) {
    case 0: return `principal.dept == "${pick(DEPTS)}"`;
    case 1: return `principal.dept != "${pick(DEPTS)}"`;
    case 2: return `principal.level ${pick(['<', '<=', '>', '>='])} ${int(5)}`;
    case 3: return `resource.size ${pick(['<', '<=', '>', '>='])} ${pick([0, 10, 100, 1000])}`;
    case 4: return `resource.public == ${pick(['true', 'false'])}`;
    case 5: return `context.hour ${pick(['<', '<=', '>', '>=', '==', '!='])} ${int(24)}`;
    case 6: return `context.ip like "${pick(['10.*', '*.1', '192.*', '*', '10.0.0.1', 'a\\*b'])}"`;
    case 7: return `principal has ${pick(['dept', 'level', 'nope'])}`;
    case 8: return `resource has ${pick(['owner', 'size', 'public'])}`;
    case 9: return `principal in ${uid('Group', pick(GROUPS))}`;
    case 10: return `resource in ${uid('Folder', pick(FOLDERS))}`;
    case 11: return `principal is User`;
    case 12: return `resource is ${pick(['Photo', 'Folder'])}`;
    case 13: return `principal == ${uid('User', pick(USERS))}`;
    case 14: return `resource.owner == "${pick(USERS)}"`;
    case 15: return `action == ${uid('Action', pick(ACTIONS))}`;
    case 16: return `context.mfa == ${pick(['true', 'false'])}`;
    case 17: return `principal.dept == resource.dept`;
    case 18: return `resource.owner == principal`.replace('principal', 'principal.name');
    // unsupported by the bridge (must fail closed, never widen)
    case 19: return pick([`principal.level + 1 > 2`, `resource.tags.contains("x")`, `ip(context.ip).isIpv4()`, `(if context.mfa then true else false)`]);
    case 20: return `!(${'principal.dept == "' + pick(DEPTS) + '"'})`;
    default: return `context.hour == ${int(24)}`;
  }
};
const cedarExpr = (d = 0) => {
  if (d > 1 || chance(0.55)) return cedarAtom();
  const op = pick(['&&', '||']);
  const e = `${cedarExpr(d + 1)} ${op} ${cedarExpr(d + 1)}`;
  return chance(0.5) ? `(${e})` : e;
};
const cedarPolicy = () => {
  const effect = chance(0.3) ? 'forbid' : 'permit';
  const p = pick(['principal', 'principal', `principal == ${uid('User', pick(USERS))}`, `principal in ${uid('Group', pick(GROUPS))}`, 'principal is User']);
  const a = pick(['action', 'action', `action == ${uid('Action', pick(ACTIONS))}`, `action in [${uid('Action', pick(ACTIONS))}, ${uid('Action', pick(ACTIONS))}]`]);
  const r = pick(['resource', 'resource', `resource == ${uid('Photo', pick(PHOTOS))}`, `resource in ${uid('Folder', pick(FOLDERS))}`, 'resource is Photo']);
  let s = `${effect} (${p}, ${a}, ${r})`;
  if (chance(0.5)) s += ` when { ${cedarExpr()} }`;
  if (chance(0.25)) s += ` unless { ${cedarExpr()} }`;
  return s + ';';
};
const parents = (types, ids, probs) => (chance(probs) ? [pick(ids)].map((i) => ({ type: types, id: i })) : []);
const cedarEntities = () => {
  const ents = [];
  for (const g of GROUPS) ents.push({ uid: { type: 'Group', id: g }, attrs: {}, parents: g === 'g1' && chance(0.7) ? [{ type: 'Group', id: 'g0' }] : [] });
  for (const f of FOLDERS) ents.push({ uid: { type: 'Folder', id: f }, attrs: {}, parents: f === 'f1' && chance(0.7) ? [{ type: 'Folder', id: 'f0' }] : [] });
  for (const u of USERS) {
    const attrs = {};
    if (chance(0.8)) attrs.dept = pick(DEPTS);
    if (chance(0.8)) attrs.level = int(5);
    if (chance(0.7)) attrs.name = pick(USERS);
    ents.push({ uid: { type: 'User', id: u }, attrs, parents: [...parents('Group', GROUPS, 0.6), ...parents('Group', GROUPS, 0.3)].filter((p, i, a) => a.findIndex((q) => q.id === p.id) === i) });
  }
  for (const p of PHOTOS) {
    const attrs = {};
    if (chance(0.8)) attrs.owner = pick(USERS);
    if (chance(0.8)) attrs.size = pick([0, 5, 10, 50, 100, 500, 1000, 5000]);
    if (chance(0.8)) attrs.public = chance(0.5);
    if (chance(0.5)) attrs.dept = pick(DEPTS);
    ents.push({ uid: { type: 'Photo', id: p }, attrs, parents: parents('Folder', FOLDERS, 0.7) });
  }
  return ents;
};
const cedarCase = () => {
  const requests = many(8, 8, () => {
    const context = {};
    if (chance(0.85)) context.hour = int(24);
    if (chance(0.85)) context.ip = pick(IPS);
    if (chance(0.7)) context.mfa = chance(0.5);
    return { principal: uid('User', pick(USERS)), action: uid('Action', pick(ACTIONS)), resource: uid('Photo', pick(PHOTOS)), context };
  });
  return { policies: many(1, 3, cedarPolicy).join('\n'), entities: cedarEntities(), requests };
};

// ---------------------------------------------------------------- Rego
const ROLES = ['admin', 'dev', 'guest'], PATHS = ['/pub/a', '/api/v1/x', '/api/v1', 'x.y', ''], RES = ['doc1', 'doc2', 'doc3'], ACTS = ['read', 'write', 'delete'];
const lit = (v) => JSON.stringify(v);
const regoStmt = () => {
  switch (int(21)) {
    case 0: return `input.action == ${lit(pick(ACTS))}`;
    case 1: return `input.action in {${many(1, 2, () => lit(pick(ACTS))).join(', ')}}`;
    case 2: return `input.resource == ${lit(pick(RES))}`;
    case 3: return `input.role == ${lit(pick(ROLES))}`;
    case 4: return `input.role != ${lit(pick(ROLES))}`;
    case 5: return `input.level ${pick(['<', '<=', '>', '>='])} ${int(5)}`;
    case 6: return `input.level == ${int(5)}`;
    case 7: return `input.role in {${many(1, 3, () => lit(pick(ROLES))).join(', ')}}`;
    case 8: return `input.role in [${many(1, 3, () => lit(pick(ROLES))).join(', ')}]`;
    case 9: return `input.owner == input.user`;
    case 10: return `not input.role == ${lit(pick(ROLES))}`;
    case 11: return `not input.level > ${int(5)}`;
    case 12: return `startswith(input.path, ${lit(pick(['/pub', '/api', '', 'x']))})`;
    case 13: return `glob.match(${lit(pick(['/api/*', '*', '/pub/?', 'x.*', '/api/v1*']))}, [], input.path)`;
    case 14: return `glob.match(${lit(pick(['/api/*', '*', '/pub/?', 'x.*', '/api/v1*']))}, null, input.path)`;
    case 15: return `input.mfa == ${pick(['true', 'false'])}`;
    // not modeled: the whole rule must be dropped, never widened
    case 16: return pick([`count(input.xs) > 1`, `regex.match("^/api", input.path)`, `endswith(input.path, "x")`, `input.xs[_] == "a"`, `r := input.role`, `input.mfa`, `"a" in input.xs`]);
    case 17: return `input.level == input.min`;
    case 18: return `input.mfa != ${pick(['true', 'false'])}`;
    case 19: return `input.role == ${lit(pick(ROLES))}`;
    default: return `input.path == ${lit(pick(PATHS))}`;
  }
};
const regoRule = () => {
  const head = pick(['allow', 'allow = true', 'allow := true', 'allow if']);
  const body = many(1, 4, regoStmt);
  const sep = chance(0.5) ? '\n  ' : '; ';
  return head === 'allow if' ? `allow if {\n  ${body.join('\n  ')}\n}` : `${head} {\n  ${body.join(sep)}\n}`;
};
const regoCase = () => ({
  module: `package authz\nimport future.keywords.in\nimport future.keywords.if\ndefault allow = false\n${many(1, 3, regoRule).join('\n')}\n`,
  inputs: many(10, 10, () => {
    const i = { action: pick(ACTS), resource: pick(RES) };
    if (chance(0.85)) i.role = pick(ROLES);
    if (chance(0.85)) i.level = int(5);
    if (chance(0.8)) i.path = pick(PATHS);
    if (chance(0.7)) i.mfa = chance(0.5);
    if (chance(0.6)) i.owner = pick(USERS);
    if (chance(0.6)) i.user = pick(USERS);
    if (chance(0.5)) i.min = int(5);
    if (chance(0.5)) i.xs = many(0, 3, () => pick(['a', 'b']));
    return i;
  }),
});

// ---------------------------------------------------------------- OpenFGA
const FUSERS = ['u1', 'u2', 'u3'], FDOCS = ['d1', 'd2', 'd3'], FFOLDERS = ['f1', 'f2'];
const BASE = ['owner', 'viewer', 'editor', 'banned'];
const cu = (relation) => ({ computedUserset: { relation } });
const fgaCase = () => {
  const docRels = { parent: { this: {} }, ...Object.fromEntries(BASE.map((b) => [b, { this: {} }])) };
  const names = [...BASE];
  const folderNames = ['owner', 'viewer', 'can_view'];
  const leaf = () => {
    const r = int(10);
    if (r < 6) return cu(pick(names));
    if (r < 8) return { tupleToUserset: { tupleset: { relation: 'parent' }, computedUserset: { relation: pick(['viewer', 'owner', 'can_view']) } } };
    return { this: {} };
  };
  const node = (depth) => {
    const k = depth > 1 ? 0 : int(6);
    if (k === 0 || k === 1) return { union: { child: many(2, 3, () => (depth < 1 && chance(0.3) ? node(depth + 1) : leaf())) } };
    if (k === 2) return { intersection: { child: many(2, 3, () => (depth < 1 && chance(0.2) ? node(depth + 1) : leaf())) } };
    if (k === 3) return { difference: { base: leaf(), subtract: leaf() } };
    return leaf();
  };
  for (let i = 1; i <= int(4) + 1; i++) { docRels[`d${i}`] = node(0); names.push(`d${i}`); }
  const model = {
    schema_version: '1.1',
    type_definitions: [
      { type: 'user' },
      { type: 'folder', relations: { owner: { this: {} }, viewer: { this: {} }, can_view: { union: { child: [cu('viewer'), cu('owner')] } } } },
      { type: 'doc', relations: docRels },
    ],
  };
  const tuples = [];
  const add = (user, relation, object) => { if (!tuples.some((t) => t.user === user && t.relation === relation && t.object === object)) tuples.push({ user, relation, object }); };
  for (let i = 0; i < 14; i++) {
    const k = int(10);
    if (k < 2) add(`folder:${pick(FFOLDERS)}`, 'parent', `doc:${pick(FDOCS)}`);
    else if (k < 4) add(`user:${pick(FUSERS)}`, pick(['owner', 'viewer']), `folder:${pick(FFOLDERS)}`);
    else add(chance(0.08) ? 'user:*' : `user:${pick(FUSERS)}`, pick(BASE), `doc:${pick(FDOCS)}`);
  }
  const checks = [];
  for (const u of FUSERS) {
    for (const d of FDOCS) for (const r of Object.keys(docRels)) checks.push({ user: `user:${u}`, relation: r, object: `doc:${d}` });
    for (const f of FFOLDERS) for (const r of folderNames) checks.push({ user: `user:${u}`, relation: r, object: `folder:${f}` });
  }
  return { model, tuples, checks };
};

const gen = kind === 'cedar' ? cedarCase : kind === 'rego' ? regoCase : kind === 'openfga' ? fgaCase : null;
if (!gen) throw new Error('kind must be cedar, rego or openfga');
for (let i = 0; i < Number(countArg); i++) console.log(JSON.stringify({ id: `${kind}-${seedArg}-${i}`, ...gen() }));
