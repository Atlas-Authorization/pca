// Mutation-style differential oracle for IntentV2 (Java / Kotlin 0.4.2 mutation kills): every STRUCTURAL path of the
// existing k042-intentv2-cases corpus (verifier context, PCActn, grant; array indexes collapsed) is replaced by each of a
// fixed set of values (null, booleans, numbers incl. -0, strings, empty / small containers), deleted, or given an unknown
// sibling, and the edited (pcactn, grant, context) goes STRAIGHT to the reference decideIntentV2. This pins every
// "member must be a <type>" / "unknown member" / "absent vs null" decision of the closed context and the wire members at
// once. Same case format as k042-intentv2-cases (the diff test code is shared); fail-closed internal-error reasons keep
// only their language-neutral prefix.
//
//   npx tsx tools/pca-audit/java-mutate/k042-intentv2-mut-oracle.mts      (deterministic; needs k042-intentv2-cases.json.gz)
// writes sdks/java-pca/test-data/k042-intentv2-mut.json.gz
import { readFileSync, writeFileSync } from 'node:fs';
import { gunzipSync, gzipSync } from 'node:zlib';
const pcaMod: any = await import(new URL('../../../packages/pca/src/index.ts', import.meta.url).href);
const pca: any = pcaMod.decideIntentV2 ? pcaMod : pcaMod.default;
const ROOT = new URL('../../../', import.meta.url).pathname;
const base: any[] = JSON.parse(gunzipSync(readFileSync(ROOT + 'sdks/java-pca/test-data/k042-intentv2-cases.json.gz')).toString('utf8')).cases;

function ser(v: any): string {
  if (v === null) return 'null';
  if (typeof v === 'number') { if (Object.is(v, -0)) return '-0'; if (!Number.isFinite(v)) throw new Error('non-finite'); return JSON.stringify(v); }
  if (typeof v === 'string' || typeof v === 'boolean') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(ser).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.entries(v).filter(([, x]) => x !== undefined).map(([k, x]) => JSON.stringify(k) + ':' + ser(x)).join(',') + '}';
  throw new Error('unserializable ' + typeof v);
}
const parse = (t: string): any => JSON.parse(t);
const FAIL_CLOSED = '(fail closed): ';
const DEL = Symbol('delete');
const VALUES: any[] = [null, true, false, 0, -0, 1, -1, 1.5, 9007199254740992, '', 'x', [], {}, [1], { a: 1 }, DEL];

type Path = (string | number)[];
const key = (p: Path) => p.map((s) => (typeof s === 'number' ? '#' : s)).join('\u0001');
function* walk(v: any, pre: Path = []): Generator<Path> {
  yield pre;
  if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) yield* walk(v[i], [...pre, i]); }
  else if (v && typeof v === 'object') for (const k of Object.keys(v)) yield* walk(v[k], [...pre, k]);
}
function setAt(root: any, p: Path, val: any): any {
  if (p.length === 0) return val === DEL ? undefined : val;
  let cur = root;
  for (let i = 0; i < p.length - 1; i++) cur = cur[p[i]];
  const last = p[p.length - 1];
  if (val === DEL) { if (Array.isArray(cur)) cur.splice(last as number, 1); else delete cur[last]; } else cur[last] = val;
  return root;
}

const cases: any[] = [];
const names = new Set<string>();
function run(name: string, p: any, grant: any, ctx: any, now: number) {
  if (names.has(name)) return;
  names.add(name);
  const P = parse(ser(p)), G = parse(ser(grant));
  const C = ctx === undefined ? undefined : parse(ser(ctx));
  const d = pca.decideIntentV2(P, G, C, now);
  const checks = d.checks.map((c: any) => {
    let reason = c.reason ?? null, prefix = false;
    if (reason !== null && reason.includes(FAIL_CLOSED) && /error \(fail closed\): /.test(reason)) { reason = reason.slice(0, reason.indexOf(FAIL_CLOSED) + FAIL_CLOSED.length); prefix = true; }
    return { name: c.name, ok: c.ok, reason, ...(prefix ? { prefix: true } : {}) };
  });
  cases.push({ name, now, p: ser(p), grant: ser(grant), ...(ctx === undefined ? {} : { ctx: ser(ctx) }), checks, env: pca.canonicalize(d.env ?? {}), active: pca.intentV2Active(P, C) });
}

const fields = ['ctx', 'p', 'grant'] as const;
const seen = new Set<string>();
for (const f of fields) {
  for (const c of base) {
    if (c.wp !== undefined || c[f] === undefined) continue;
    const doc = parse(c[f]);
    for (const path of walk(doc)) {
      const k = f + '\u0002' + key(path);
      if (seen.has(k)) continue;
      seen.add(k);
      const label = `${f}/${path.join('.') || '$'}`;
      const orig = path.reduce((a: any, s) => a[s], doc);
      const variants: [string, any][] = VALUES.map((v, i) => [String(i), v]);
      // an unknown sibling on every object ("unknown member" refusals)
      if (orig && typeof orig === 'object' && !Array.isArray(orig)) variants.push(['extra', { ...orig, zz_unknown: 1 }]);
      for (const [vn, val] of variants) {
        if (path.length === 0 && val === DEL) continue;
        const mutated = setAt(parse(c[f]), path, val);
        const P = f === 'p' ? mutated : parse(c.p), G = f === 'grant' ? mutated : parse(c.grant);
        const C = f === 'ctx' ? mutated : c.ctx === undefined ? undefined : parse(c.ctx);
        if (typeof P !== 'object' || P === null || Array.isArray(P)) continue; // decideIntentV2 takes a PCActn object
        try { run(`mut/${label}/${vn}`, P, G, C, c.now); } catch (e) { /* the reference itself threw: not a decision, not a case */ void e; }
      }
    }
  }
}
const out = ROOT + 'sdks/java-pca/test-data/k042-intentv2-mut.json.gz';
writeFileSync(out, gzipSync(Buffer.from(JSON.stringify({ generator: 'tools/pca-audit/java-mutate/k042-intentv2-mut-oracle.mts', cases }) + '\n'), { level: 9 }));
console.log(`${cases.length} cases -> ${out}`);
