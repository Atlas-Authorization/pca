// Oracle: durable-state.ts (the crash-safe, hash-chained, generation-fenced persistent key/value store), TS reference.
// Written for the native lanes. One function, `scenario`: the argument is a whole scenario, the result is its trace.
//
// A scenario is { files, steps }:
//   files  the initial directory (name -> text). Placeholders in the text: $HOST (this machine's hostname), $PID (a LIVE process: the
//          replaying process itself), $DEAD (a pid no process has, 999999999). Fake PID-namespace ids ("pid:[4026530001]") are literal.
//   steps  run in order against that directory:
//     {t:'open', opts, ops}   openDurableState(opts) then each op on the handle. opts: {hmacKey: <seed label>, hmacKeyBytes: n (a key of
//                             n bytes, for the too-short case), recoverFromCorruption, lockTimeoutMs, compactEvery, maxValueBytes, dir: ''}.
//                             The key of a label is sha256(label). `now` is a counter: the first call returns 1000, then 1001 ... (one
//                             counter per open step; a commit calls it once for the record and once more when it compacts).
//     {t:'recover', opts}     recoverDurableState({dir, force: true, ...opts}); opts.force:false / expectedHolder as given; the strings '$HOST' / '$PID' anywhere in opts become the hostname / the pid number.
//     {t:'write', file, text} write a file (text null: remove it).
//     {t:'dir'}               snapshot (also appended automatically at the end).
//   ops (on an open handle): {op:'set',key,value} {op:'get',key} {op:'keys'} {op:'verify'} {op:'position'}
//     {op:'update',key,kind,arg}   kind: append (prev => [...(prev ?? []), arg]) | max (arg when prev is absent or arg > prev, else leave)
//                                  | noop (leave) | same (return prev: no commit) | set (return arg)
//     {op:'fs',file,text}          mutate the directory under the running handle (text null: remove)
//     {op:'save',name} {op:'restore',name}   keep / put back state.journal + state.head (an older valid copy)
// Result: one entry per step: open -> {ok:{recovered, ops:[...]}} | {err:{code,msg}} ; recover -> {ok:{released,reason,lockFile?}} | {err};
// write -> null; dir -> {files, journal, head, fences, top}. An op result is {ok: value} (a missing value is {"$undef":true}) or {err}.
// Normalisation: the directory is $DIR, the host $HOST, the live pid $PID in messages and lock-file names; random suffixes of fence,
// quarantine and recovered-legacy files are `*`; fence entries lose their wall-clock `t`; the top lock body keeps only st / recovering /
// recoveredFrom / pid-free fields. Messages are compared whole (they are part of the contract: an operator reads them).
// PORTING: fn scenario(args) -> run the scenario against a fresh temp dir; JSON-value compare of the trace.
// Not in the corpus (platform or process dependent, covered by each lane's own tests): link-unsupported, live same-PID-namespace
// holders, process start-time reuse, SIGKILL crash points, N-process races.
import { createHash, createHmac } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { Oracle, refWrite } from './lib.mjs';
const m: any = await import('../../../packages/pca/src/durable-state.ts');

const o = new Oracle('durable-state', 'tools/pca-audit/oracles/durable-state.mts', 'TS-reference oracle for the durable state store: commit/compaction bytes, tamper / rollback / generation-fence loading, the lock protocol and operator recovery.');

const G0 = '0'.repeat(64);
const DEAD = 999999999;
const FAKE_NS = 'pid:[4026530001]';
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const keyOf = (label: string) => createHash('sha256').update(label).digest();

const subst = (s: string, host: string) => s.replaceAll('$HOST', host).replaceAll('$PID', String(process.pid)).replaceAll('$DEAD', String(DEAD));

async function scenario(sc: { files?: Record<string, string>; steps: any[] }): Promise<any[]> {
  const dir = mkdtempSync(join(tmpdir(), 'pca-ds-oracle-'));
  const host = hostname();
  const norm = (s: string): string => s.replaceAll(dir, '$DIR').replaceAll(host, '$HOST').replaceAll(`pid=${process.pid}`, 'pid=$PID').replaceAll(`pid ${process.pid}`, 'pid $PID');
  const normName = (f: string): string =>
    f.replace(/^(state\.fence\.\d+)-[0-9a-f]+/, '$1-*').replace(/\.quarantine-.*$/, '.quarantine-*').replace(/^state\.lock\.legacy-recovered-.*$/, 'state.lock.legacy-recovered-*').replace(/^state\.lock\.tmp-.*$/, 'state.lock.tmp-*');
  const errOf = (e: any) => {
    if (e?.name !== 'DurableStateError') throw e;
    return { err: { code: e.code, msg: norm(e.message) } };
  };
  const read = (f: string): string | null => (existsSync(join(dir, f)) ? readFileSync(join(dir, f), 'utf8') : null);
  const snapshot = () => {
    const names = readdirSync(dir).sort();
    const fences: any[] = [];
    const parse = (f: string): any => JSON.parse(readFileSync(join(dir, f), 'utf8'));
    const strip = (x: any) => { const { t, ...r } = x; return r; };
    const tryFence = (f: string, pick: (x: any) => any[]) => {
      try {
        for (const x of pick(parse(f))) fences.push(strip(x));
      } catch {
        fences.push({ unreadable: normName(f) });
      }
    };
    if (names.includes('state.fence')) tryFence('state.fence', (x) => x.fences);
    for (const f of names.filter((x) => /^state\.fence\.\d+-[0-9a-f]+$/.test(x)).sort((a, b) => Number(a.split('.')[2].split('-')[0]) - Number(b.split('.')[2].split('-')[0]) || (a < b ? -1 : 1))) tryFence(f, (x) => [x.fence]);
    const gens = names.flatMap((f) => (/^state\.lock\.\d+$/.test(f) ? [Number(f.slice(11))] : []));
    const g = gens.length ? Math.max(...gens) : 0;
    let top: any = null;
    if (g > 0) {
      try {
        const b = parse(`state.lock.${g}`);
        top = { g, st: b.st, ...(b.recovering !== undefined ? { recovering: b.recovering } : {}), ...(b.recoveredFrom !== undefined ? { recoveredFrom: b.recoveredFrom } : {}) };
      } catch {
        top = { g, st: 'unreadable' };
      }
    }
    return { t: 'dir', files: names.filter((f) => !f.startsWith('state.lock.tmp-') && !f.startsWith('state.probe-') && !/\.tmp-/.test(f)).map(normName), journal: read('state.journal'), head: read('state.head'), fences, top };
  };
  const out: any[] = [];
  try {
    for (const [f, t] of Object.entries(sc.files ?? {})) writeFileSync(join(dir, f), subst(t, host));
    for (const st of sc.steps) {
      if (st.t === 'write') {
        if (st.text === null) rmSync(join(dir, st.file), { force: true });
        else writeFileSync(join(dir, st.file), subst(st.text, host));
        out.push(null);
      } else if (st.t === 'dir') out.push(snapshot());
      else if (st.t === 'recover') {
        try {
          const so = (v: any): any => (v === '$HOST' ? host : v === '$PID' ? process.pid : Array.isArray(v) ? v.map(so) : v !== null && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, so(x)])) : v);
          const r = m.recoverDurableState({ dir, force: true, ...so(st.opts) });
          out.push({ ok: { released: r.released, reason: r.reason, ...(r.lockFile !== undefined ? { lockFile: norm(r.lockFile) } : {}) } });
        } catch (e) {
          out.push(errOf(e));
        }
      } else if (st.t === 'open') {
        let c = 1000;
        const op = st.opts ?? {};
        const opts: any = { dir: op.dir !== undefined ? op.dir : dir, now: () => c++ };
        if (op.hmacKey !== undefined) opts.hmacKey = keyOf(op.hmacKey);
        if (op.hmacKeyBytes !== undefined) opts.hmacKey = new Uint8Array(op.hmacKeyBytes);
        for (const k of ['recoverFromCorruption', 'lockTimeoutMs', 'compactEvery', 'maxValueBytes']) if (op[k] !== undefined) opts[k] = op[k];
        let h: any;
        try {
          h = await m.openDurableState(opts);
        } catch (e) {
          out.push(errOf(e));
          continue;
        }
        const res: any[] = [];
        const saved: Record<string, [string | null, string | null]> = {};
        for (const x of st.ops ?? []) {
          try {
            let v: any;
            if (x.op === 'set') { await h.set(x.key, x.value); v = null; }
            else if (x.op === 'get') { const r = await h.get(x.key); v = r === undefined ? { $undef: true } : r; }
            else if (x.op === 'keys') v = await h.keys();
            else if (x.op === 'verify') v = await h.verify();
            else if (x.op === 'position') v = h.position();
            else if (x.op === 'update') {
              const fn: Record<string, (p: any) => any> = {
                append: (p) => [...(p ?? []), x.arg],
                max: (p) => (p === undefined || x.arg > p ? x.arg : undefined),
                noop: () => undefined,
                same: (p) => p,
                set: () => x.arg,
              };
              const r = await h.update(x.key, fn[x.kind]);
              v = r === undefined ? { $undef: true } : r;
            } else if (x.op === 'fs') {
              if (x.text === null) rmSync(join(dir, x.file), { force: true });
              else writeFileSync(join(dir, x.file), subst(x.text, host));
              v = null;
            } else if (x.op === 'save') { saved[x.name] = [read('state.journal'), read('state.head')]; v = null; }
            else if (x.op === 'restore') {
              const [j, hd] = saved[x.name]!;
              if (j === null) rmSync(join(dir, 'state.journal'), { force: true }); else writeFileSync(join(dir, 'state.journal'), j);
              if (hd === null) rmSync(join(dir, 'state.head'), { force: true }); else writeFileSync(join(dir, 'state.head'), hd);
              v = null;
            } else throw new Error('unknown op ' + x.op);
            res.push({ ok: v });
          } catch (e) {
            res.push(errOf(e));
          }
        }
        out.push({ ok: { recovered: h.recovered, ops: res } });
      } else throw new Error('unknown step ' + st.t);
    }
    out.push(snapshot());
    return out;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

let n = 0;
const add = async (name: string, sc: { files?: Record<string, string>; steps: any[] }) => { await o.run('scenario', name, scenario, [sc]); n++; };
const open = (opts: any, ops: any[] = []) => ({ t: 'open', opts, ops });
const set = (key: string, value: any) => ({ op: 'set', key, value });
const get = (key: string) => ({ op: 'get', key });
const upd = (key: string, kind: string, arg?: any) => ({ op: 'update', key, kind, ...(arg !== undefined ? { arg } : {}) });
const STD = [{ op: 'verify' }];

// ---- fixtures: run the real store with a fixed clock, keep the bytes (locks reduced to one free top, so no host / pid / nonce) ----
async function build(opts: any, ops: any[]): Promise<Record<string, string>> {
  const d = mkdtempSync(join(tmpdir(), 'pca-ds-fixture-'));
  try {
    let c = 1000;
    const h = await m.openDurableState({ dir: d, now: () => c++, ...(opts.hmacKey ? { hmacKey: keyOf(opts.hmacKey) } : {}), ...(opts.compactEvery ? { compactEvery: opts.compactEvery } : {}) });
    for (const x of ops) await h.set(x.key, x.value);
    const files: Record<string, string> = {};
    const gens = readdirSync(d).flatMap((f) => (/^state\.lock\.\d+$/.test(f) ? [Number(f.slice(11))] : []));
    for (const f of readdirSync(d)) if (f === 'state.journal' || f === 'state.head') files[f] = readFileSync(join(d, f), 'utf8');
    files[`state.lock.${Math.max(...gens)}`] = '{"st":"free"}';
    return files;
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}
const lines = (t: string) => t.split('\n').slice(0, -1);
const jl = (...l: any[]) => l.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join('\n') + '\n';
/** a hand-made record: hash and (with a key) MAC computed here, exactly as the reference does */
function rec(seq: number, prev: string, payload: string, ts: number, gen?: number, key?: string, op: 'set' | 'checkpoint' = 'set'): any {
  const h = sha('pca-durable-state/v1\n' + JSON.stringify(gen === undefined ? [seq, prev, op, payload, ts] : [seq, prev, op, payload, ts, gen]));
  return { seq, prev, op, payload, ts, ...(gen !== undefined ? { gen } : {}), h, ...(key ? { mac: createHmac('sha256', keyOf(key)).update(h).digest('hex') } : {}) };
}
const head = (r: any, gen?: number, key?: string) => {
  const g = gen === undefined ? r.gen : gen;
  const base: any = { seq: r.seq, h: r.h, ...(g !== undefined ? { gen: g } : {}) };
  if (key) base.mac = createHmac('sha256', keyOf(key)).update(g === undefined ? `head\n${r.seq}\n${r.h}` : `head\n${r.seq}\n${r.h}\n${g}`).digest('hex');
  return JSON.stringify(base) + '\n';
};
const free = (g: number) => ({ [`state.lock.${g}`]: '{"st":"free"}' });

// ========== A. commits from an empty directory ==========
await add('basic', { steps: [open({}, [set('a', 1), set('b', 'x'), get('a'), get('zz'), { op: 'keys' }, upd('c', 'append', 1), upd('c', 'append', 2), upd('hw', 'max', 5), upd('hw', 'max', 3), upd('hw', 'max', 9), upd('hw', 'noop'), upd('c', 'same'), upd('new', 'noop'), upd('d', 'set', { z: [1, null, true], a: 'q' }), { op: 'verify' }, { op: 'position' }]), open({}, [get('a'), get('c'), get('hw'), { op: 'keys' }, { op: 'verify' }])] });
for (const ce of [0, 1, 2, 3, 5]) await add(`compact-${ce}`, { steps: [open({ compactEvery: ce }, [...Array.from({ length: 9 }, (_, i) => set(`k${i % 4}`, i)), { op: 'keys' }, { op: 'verify' }]), open({ compactEvery: ce }, [get('k0'), get('k3'), set('late', 'v'), { op: 'verify' }])] });
await add('hmac-roundtrip', { steps: [open({ hmacKey: 'k1' }, [set('a', 1), upd('a', 'append', 2).op ? upd('b', 'append', 2) : set('x', 1), { op: 'verify' }]), open({ hmacKey: 'k1' }, [get('a'), get('b'), set('c', 3)]), open({}, []), open({ hmacKey: 'k2' }, []), open({ hmacKey: 'k1', compactEvery: 2 }, [set('d', 4), set('e', 5), { op: 'verify' }])] });
await add('hmac-short-key', { steps: [open({ hmacKeyBytes: 31 }), open({ hmacKeyBytes: 32 }, [set('a', 1)])] });
await add('empty-dir-arg', { steps: [open({ dir: '' })] });
await add('bad-keys', { steps: [open({}, [set('', 1), set('k'.repeat(257), 1), set('a\nb', 1), get(''), get('a\nb'), upd('', 'set', 1), upd('x'.repeat(257), 'noop'), set('k'.repeat(256), 1), get('k'.repeat(256)), { op: 'keys' }])] });
await add('unicode', { steps: [open({}, [set('ключ-🙂', 'значение 🙂   \n \t "q" \\'), set('é', { 'é': ['\u0000', '\u001f', '\u007f', '퟿'] }), get('ключ-🙂'), get('é'), { op: 'keys' }, { op: 'verify' }]), open({}, [get('é'), { op: 'verify' }])] });
await add('too-large', { steps: [open({ maxValueBytes: 4 }, [set('a', 'xx'), set('b', 'xxx'), set('c', '😀'), set('d', '😀x'), upd('a', 'set', 'zzzz'), upd('a', 'set', 'zz'), get('a'), get('b'), get('c')])] });

// A2. a handle noticing the directory change under it
await add('running-older-copy', { steps: [open({}, [set('a', 1), { op: 'save', name: 'old' }, set('a', 2), { op: 'restore', name: 'old' }, get('a'), { op: 'verify' }])] });
await add('running-deleted', { steps: [open({}, [set('a', 1), { op: 'fs', file: 'state.journal', text: null }, { op: 'fs', file: 'state.head', text: null }, get('a'), { op: 'verify' }, { op: 'position' }])] });
await add('running-forked', { steps: [open({}, [set('a', 1)]), { t: 'dir' }] });

// ========== B. loading a journal someone else wrote: tamper, truncation, rollback ==========
const base3 = await build({}, [{ key: 'a', value: 1 }, { key: 'b', value: 2 }, { key: 'c', value: 3 }]);
const base3L = lines(base3['state.journal']!);
const R3 = base3L.map((l) => JSON.parse(l));
const withJ = (j: string, h: string | null = base3['state.head']!) => ({ ...base3, 'state.journal': j, ...(h === null ? {} : { 'state.head': h }) });
const dropHead = (f: Record<string, string>) => { const { 'state.head': _h, ...r } = f; return r; };
const tamper: [string, Record<string, string>][] = [
  ['clean', base3],
  ['edited-payload', withJ(jl(R3[0], { ...R3[1], payload: 'b\n99' }, R3[2]))],
  ['edited-ts', withJ(jl(R3[0], { ...R3[1], ts: 7 }, R3[2]))],
  ['edited-gen', withJ(jl(R3[0], { ...R3[1], gen: R3[1].gen + 2 }, R3[2]))],
  ['deleted-middle', withJ(jl(R3[0], R3[2]))],
  ['reordered', withJ(jl(R3[0], R3[2], R3[1]))],
  ['torn-last-line', withJ(base3['state.journal']!.slice(0, -12))],
  ['no-final-newline', withJ(base3['state.journal']!.slice(0, -1))],
  ['tail-truncated-1', withJ(jl(R3[0], R3[1]))],
  ['tail-truncated-all-but-1', withJ(jl(R3[0]))],
  ['journal-empty', withJ('')],
  ['journal-missing-head-survives', (({ 'state.journal': _j, ...r }) => r)(base3)],
  ['head-missing-seq3', dropHead(base3)],
  ['head-corrupt-json', { ...base3, 'state.head': '{nope\n' }],
  ['head-seq-minus-zero', { ...base3, 'state.head': `{"seq":-0,"h":"${R3[2].h}","gen":${R3[2].gen}}\n` }],
  ['head-seq-float-integral', { ...base3, 'state.head': `{"seq":3.0,"h":"${R3[2].h}","gen":${R3[2].gen}}\n` }],
  ['head-seq-string', { ...base3, 'state.head': `{"seq":"3","h":"${R3[2].h}"}\n` }],
  ['head-h-short', { ...base3, 'state.head': `{"seq":3,"h":"abc"}\n` }],
  ['head-gen-zero', { ...base3, 'state.head': `{"seq":3,"h":"${R3[2].h}","gen":0}\n` }],
  ['head-array', { ...base3, 'state.head': '[]\n' }],
  ['head-ahead-by-one', { ...base3, 'state.head': head({ seq: 4, h: sha('x'), gen: 9 }) }],
  ['head-behind-by-one', { ...base3, 'state.head': head(R3[1]) }],
  ['head-behind-by-two', { ...base3, 'state.head': head(R3[0]) }],
  ['head-wrong-hash-same-seq', { ...base3, 'state.head': head({ ...R3[2], h: sha('other') }) }],
  ['head-gen-lower-than-record', { ...base3, 'state.head': head(R3[2], R3[2].gen - 2) }],
  ['older-valid-copy', withJ(jl(R3[0], R3[1]), head(R3[1]))],
  ['journal-line-not-json', withJ(jl(R3[0], 'garbage'))],
  ['record-array', withJ(jl(R3[0], '[]'))],
  ['record-missing-field', withJ(jl(R3[0], (({ ts, ...r }) => r)(R3[1])))],
  ['record-bad-op', withJ(jl(R3[0], { ...R3[1], op: 'delete' }))],
  ['record-payload-number', withJ(jl(R3[0], { ...R3[1], payload: 5 }))],
  ['record-ts-minus-zero', withJ(jl(R3[0]).replace(/"ts":\d+/, '"ts":-0'))],
  ['record-ts-float-integral', withJ(jl(R3[0]).replace(/"ts":(\d+)/, '"ts":$1.0'))],
  ['record-gen-zero', withJ(jl({ ...R3[0], gen: 0 }))],
  ['record-prev-bad', withJ(jl(R3[0], { ...R3[1], prev: 'zz' }))],
  ['record-seq-gap', withJ(jl(R3[0], rec(3, R3[0].h, 'b\n2', 1001, R3[0].gen), R3[2]))],
  ['first-not-genesis-seq', withJ(jl(rec(2, G0, 'a\n1', 1, 1)), head(rec(2, G0, 'a\n1', 1, 1)))],
  ['first-not-genesis-prev', withJ(jl(rec(1, sha('p'), 'a\n1', 1, 1)), head(rec(1, sha('p'), 'a\n1', 1, 1)))],
  ['payload-no-newline', (() => { const r = rec(1, G0, 'nonewline', 1, 1); return withJ(jl(r), head(r)); })()],
  ['payload-empty-key', (() => { const r = rec(1, G0, '\n1', 1, 1); return withJ(jl(r), head(r)); })()],
  ['checkpoint-first-ok', (() => { const r = rec(5, G0, JSON.stringify([['a', '1']]), 1, 1, undefined, 'checkpoint'); return { ...free(2), 'state.journal': jl(r), 'state.head': head(r) }; })()],
  ['checkpoint-first-seq0', (() => { const r = rec(0, G0, JSON.stringify([['a', '1']]), 1, 1, undefined, 'checkpoint'); return { ...free(2), 'state.journal': jl(r), 'state.head': head(r) }; })()],
  ['checkpoint-payload-not-json', (() => { const r = rec(1, G0, 'zz', 1, 1, undefined, 'checkpoint'); return { ...free(2), 'state.journal': jl(r), 'state.head': head(r) }; })()],
  ['checkpoint-payload-not-array', (() => { const r = rec(1, G0, '{}', 1, 1, undefined, 'checkpoint'); return { ...free(2), 'state.journal': jl(r), 'state.head': head(r) }; })()],
  ['checkpoint-entry-bad', (() => { const r = rec(1, G0, JSON.stringify([['a', 1]]), 1, 1, undefined, 'checkpoint'); return { ...free(2), 'state.journal': jl(r), 'state.head': head(r) }; })()],
  ['journal-one-ahead-head-repaired', (() => { return { ...base3, 'state.head': head(R3[1]) }; })()],
  ['single-record-no-head', (() => { const r = rec(1, G0, 'a\n1', 1, 1); return { ...free(2), 'state.journal': jl(r) }; })()],
];
for (const [nm, files] of tamper) {
  const f: Record<string, string> = Object.fromEntries(Object.entries(files).filter(([, v]) => v !== undefined));
  await add(`load-${nm}`, { files: f, steps: [open({}, [get('a'), get('c'), { op: 'keys' }, { op: 'verify' }, set('z', 1), { op: 'verify' }])] });
  await add(`recover-${nm}`, { files: f, steps: [open({ recoverFromCorruption: true }, [{ op: 'keys' }, set('z', 1), { op: 'verify' }])] });
}
// keyed variants
const keyed3 = await build({ hmacKey: 'k1' }, [{ key: 'a', value: 1 }, { key: 'b', value: 2 }]);
const KL = lines(keyed3['state.journal']!).map((l) => JSON.parse(l));
const kt: [string, Record<string, string>, any][] = [
  ['clean', keyed3, { hmacKey: 'k1' }],
  ['wrong-key', keyed3, { hmacKey: 'k2' }],
  ['no-key', keyed3, {}],
  ['key-on-unkeyed', base3, { hmacKey: 'k1' }],
  ['mac-stripped-record', { ...keyed3, 'state.journal': jl(KL[0], (({ mac, ...r }) => r)(KL[1])) }, { hmacKey: 'k1' }],
  ['mac-stripped-head', { ...keyed3, 'state.head': JSON.stringify((({ mac, ...r }) => r)(JSON.parse(keyed3['state.head']!))) + '\n' }, { hmacKey: 'k1' }],
  ['forged-rechain-no-key', (() => { const a = rec(1, G0, 'a\n99', 1, 3, 'forged'); const b = rec(2, a.h, 'b\n99', 2, 3, 'forged'); return { ...free(4), 'state.journal': jl(a, b), 'state.head': head(b, 3, 'forged') }; })(), { hmacKey: 'k1' }],
  ['forged-with-key', (() => { const a = rec(1, G0, 'a\n99', 1, 3, 'k1'); return { ...free(4), 'state.journal': jl(a), 'state.head': head(a, 3, 'k1') }; })(), { hmacKey: 'k1' }],
  ['older-pair-with-key', { ...keyed3, 'state.journal': jl(KL[0]), 'state.head': head(KL[0], undefined, 'k1') }, { hmacKey: 'k1' }],
];
for (const [nm, files, op] of kt) await add(`keyed-${nm}`, { files, steps: [open(op, [get('a'), { op: 'verify' }, set('z', 1)])] });

// ========== C. generations and the operator's fence ==========
const L1 = rec(1, G0, 'a\n1', 1, 3), L2 = rec(2, L1.h, 'b\n2', 2, 3), L3 = rec(3, L2.h, 'c\n3', 3, 5);
const fenceOne = (gen: number, seq: number, h: string, extra: any = {}) => JSON.stringify({ v: 1, fence: { gen, seq, h, from: gen - 1, t: 1, ...extra } });
const fenceName = (gen: number, tag = 'aa') => `state.fence.${gen}-${tag}`;
const gens: [string, Record<string, string>][] = [
  ['legacy-no-gen', (() => { const r = rec(1, G0, 'k\n"legacy"', 5); return { ...free(2), 'state.journal': jl(r), 'state.head': JSON.stringify({ seq: 1, h: r.h }) + '\n' }; })()],
  ['legacy-two-no-gen', (() => { const a = rec(1, G0, 'a\n1', 5), b = rec(2, a.h, 'b\n2', 6); return { ...free(2), 'state.journal': jl(a, b), 'state.head': JSON.stringify({ seq: 2, h: b.h }) + '\n' }; })()],
  ['legacy-then-gen-then-legacy', (() => { const a = rec(1, G0, 'a\n1', 5, 3), b = rec(2, a.h, 'b\n2', 6); return { ...free(4), 'state.journal': jl(a, b), 'state.head': head(b) }; })()],
  ['ok-increasing', { ...free(6), 'state.journal': jl(L1, L2, L3), 'state.head': head(L3) }],
  ['lower-gen-than-earlier', (() => { const b = rec(2, L1.h, 'b\n2', 2, 2); return { ...free(6), 'state.journal': jl(L1, b), 'state.head': head(L1) }; })()],
  ['fence-refuses-late-record', { ...free(6), [fenceName(4)]: fenceOne(4, 2, L2.h), 'state.journal': jl(L1, L2, rec(3, L2.h, 'c\n3', 3, 3)), 'state.head': head(L2) }],
  ['fence-accepts-newer-gen', { ...free(6), [fenceName(4)]: fenceOne(4, 2, L2.h), 'state.journal': jl(L1, L2, L3), 'state.head': head(L3) }],
  ['fence-record-at-cut-is-not-the-cut', { ...free(6), [fenceName(4)]: fenceOne(4, 2, L2.h), 'state.journal': jl(L1, rec(2, L1.h, 'b\n99', 2, 5)), 'state.head': head(rec(2, L1.h, 'b\n99', 2, 5)) }],
  ['fence-journal-short-of-cut', { ...free(6), [fenceName(4)]: fenceOne(4, 2, L2.h), 'state.journal': jl(L1), 'state.head': head(L1) }],
  ['fence-journal-missing', { ...free(6), [fenceName(4)]: fenceOne(4, 2, L2.h) }],
  ['fence-at-genesis-journal-missing-ok', { ...free(6), [fenceName(4)]: fenceOne(4, 0, G0) }],
  ['fence-compacted-past-cut', (() => { const cp = rec(5, L3.h, JSON.stringify([['a', '1'], ['b', '2'], ['c', '3']]), 9, 5, undefined, 'checkpoint'); return { ...free(6), [fenceName(4)]: fenceOne(4, 2, L2.h), 'state.journal': jl(cp), 'state.head': head(cp) }; })()],
  ['fence-list-file', { ...free(6), 'state.fence': JSON.stringify({ v: 1, fences: [{ gen: 4, seq: 2, h: L2.h, from: 3, t: 1 }] }), 'state.journal': jl(L1, L2, L3), 'state.head': head(L3) }],
  ['fence-list-and-entry', { ...free(8), 'state.fence': JSON.stringify({ v: 1, fences: [{ gen: 4, seq: 2, h: L2.h }] }), [fenceName(6, 'bb')]: fenceOne(6, 3, L3.h), 'state.journal': jl(L1, L2, L3), 'state.head': head(L3) }],
  ['fence-no-hash', { ...free(6), 'state.fence': JSON.stringify({ v: 1, fences: [{ gen: 3, seq: 0 }] }), 'state.journal': jl(L1), 'state.head': head(L1) }],
  ['fence-seq-minus-zero', { ...free(6), 'state.fence': `{"v":1,"fences":[{"gen":3,"seq":-0,"h":"${G0}"}]}`, 'state.journal': jl(L1), 'state.head': head(L1) }],
  ['fence-gen-zero', { ...free(6), 'state.fence': JSON.stringify({ v: 1, fences: [{ gen: 0, seq: 0, h: G0 }] }), 'state.journal': jl(L1), 'state.head': head(L1) }],
  ['fence-list-bad-json', { ...free(6), 'state.fence': '{nope', 'state.journal': jl(L1), 'state.head': head(L1) }],
  ['fence-list-bad-shape', { ...free(6), 'state.fence': '{"v":2,"fences":[]}', 'state.journal': jl(L1), 'state.head': head(L1) }],
  ['fence-entry-bad-json', { ...free(6), [fenceName(4)]: '{nope', 'state.journal': jl(L1), 'state.head': head(L1) }],
  ['fence-entry-bad-shape', { ...free(6), [fenceName(4)]: '{"v":2}', 'state.journal': jl(L1), 'state.head': head(L1) }],
  ['fence-entry-gen-mismatch', { ...free(6), [fenceName(4)]: fenceOne(9, 0, G0), 'state.journal': jl(L1), 'state.head': head(L1) }],
  ['head-gen-above-tail-record', { ...free(6), 'state.journal': jl(L1, L2), 'state.head': head(L1, 5) }],
  ['head-gen-above-same-seq-other-hash', { ...free(6), 'state.journal': jl(L1, L2), 'state.head': head({ ...L2, h: sha('other') }, 5) }],
  ['head-gen-above-journal-same-record', { ...free(6), 'state.journal': jl(L1, L2), 'state.head': head(L2, 5) }],
  ['stale-late-head-repaired', (() => { const A = rec(1, G0, 'a\n1', 1, 3), B2 = rec(2, A.h, 'b\n2', 2, 5), B3 = rec(3, B2.h, 'c\n3', 3, 5), B4 = rec(4, B3.h, 'd\n4', 4, 5); return { ...free(8), [fenceName(4)]: fenceOne(4, 1, A.h), 'state.journal': jl(A, B2, B3, B4), 'state.head': head(A, 3) }; })()],
  ['stale-head-no-fence-corrupt', (() => { const A = rec(1, G0, 'a\n1', 1, 3), B2 = rec(2, A.h, 'b\n2', 2, 5), B3 = rec(3, B2.h, 'c\n3', 3, 5); return { ...free(8), 'state.journal': jl(A, B2, B3), 'state.head': head(A, 3) }; })()],
  ['stale-head-cut-before-head', (() => { const A = rec(1, G0, 'a\n1', 1, 3), B2 = rec(2, A.h, 'b\n2', 2, 5), B3 = rec(3, B2.h, 'c\n3', 3, 5), B4 = rec(4, B3.h, 'd\n4', 4, 5); return { ...free(8), [fenceName(4)]: fenceOne(4, 0, G0), 'state.journal': jl(A, B2, B3, B4), 'state.head': head(B2, 3) }; })()],
  ['stale-head-names-absent-record', (() => { const A = rec(1, G0, 'a\n1', 1, 3), B2 = rec(2, A.h, 'b\n2', 2, 5), B3 = rec(3, B2.h, 'c\n3', 3, 5), B4 = rec(4, B3.h, 'd\n4', 4, 5); return { ...free(8), [fenceName(4)]: fenceOne(4, 2, B2.h), 'state.journal': jl(A, B2, B3, B4), 'state.head': head({ ...A, h: sha('zz') }, 3) }; })()],
  ['journal-tail-not-chained-from-head', (() => { const A = rec(1, G0, 'a\n1', 1, 3), B2 = rec(2, sha('elsewhere'), 'b\n2', 2, 3); return { ...free(6), 'state.journal': jl(A, B2), 'state.head': head(A) }; })()],
  ['quarantine-with-fence', { ...free(6), [fenceName(4)]: fenceOne(4, 2, L2.h), 'state.journal': 'garbage\n', 'state.head': head(L2) }],
  ['quarantine-with-fence-list', { ...free(6), 'state.fence': JSON.stringify({ v: 1, fences: [{ gen: 4, seq: 2, h: L2.h }] }), 'state.journal': 'garbage\n' }],
];
for (const [nm, files] of gens) {
  await add(`gen-${nm}`, { files, steps: [open({}, [get('a'), { op: 'keys' }, { op: 'verify' }, set('z', 1), { op: 'verify' }]), { t: 'dir' }] });
  await add(`gen-recover-${nm}`, { files, steps: [open({ recoverFromCorruption: true }, [{ op: 'keys' }, set('z', 1), { op: 'verify' }])] });
}

// ========== D. the lock ==========
const held = (over: any) => JSON.stringify({ st: 'held', pid: '$DEAD', host: '$HOST', nonce: 'n1', ...over }).replace('"$DEAD"', '$DEAD').replace('"$PID"', '$PID');
const lockCases: [string, Record<string, string>][] = [
  ['dead-same-host', { 'state.lock.1': held({}) }],
  ['dead-same-host-with-start-garbage', { 'state.lock.1': held({ start: 'zzz' }) }],
  ['dead-recovering-takeover-fences', { ...free(1), 'state.journal': jl(L1), 'state.head': head(L1), 'state.lock.2': held({ recovering: 1 }) }],
  ['dead-recovering-takeover-empty-journal', { 'state.lock.2': held({ recovering: 1 }) }],
  ['dead-recovering-bad-value', { 'state.lock.2': held({ recovering: 'x' }) }],
  ['live-same-host', { 'state.lock.1': held({ pid: '$PID' }) }],
  ['other-host', { 'state.lock.1': held({ host: 'some-other-host' }) }],
  ['other-ns', { 'state.lock.1': held({ ns: FAKE_NS }) }],
  ['other-ns-dead-pid-other-host', { 'state.lock.1': held({ ns: FAKE_NS, host: 'h2' }) }],
  ['incomplete-empty-object', { 'state.lock.1': '{}' }],
  ['incomplete-array', { 'state.lock.1': '[]' }],
  ['incomplete-st-only', { 'state.lock.1': '{"st":"held"}' }],
  ['incomplete-string-pid', { 'state.lock.1': held({ pid: '4194000' }).replace('999999999', '"999999999"') }],
  ['unreadable-garbage', { 'state.lock.1': 'not json' }],
  ['unreadable-empty', { 'state.lock.1': '' }],
  ['unreadable-null', { 'state.lock.1': 'null' }],
  ['free-top', { ...free(7) }],
  ['legacy-dead', { 'state.lock': held({}) }],
  ['legacy-live', { 'state.lock': held({ pid: '$PID' }) }],
  ['legacy-other-ns', { 'state.lock': held({ ns: FAKE_NS }) }],
  ['legacy-other-host', { 'state.lock': held({ host: 'elsewhere' }) }],
  ['legacy-incomplete', { 'state.lock': JSON.stringify({ pid: '$DEAD', ns: FAKE_NS }).replace('"$DEAD"', '$DEAD') }],
  ['legacy-dead-and-live-gen', { 'state.lock': held({}), 'state.lock.3': held({ pid: '$PID' }) }],
  ['gen-gap', { 'state.lock.3': '{"st":"free"}', 'state.lock.9': '{"st":"free"}' }],
  ['gc-window', Object.fromEntries(Array.from({ length: 22 }, (_, i) => [`state.lock.${i + 1}`, '{"st":"free"}']))],
];
for (const [nm, files] of lockCases) await add(`lock-${nm}`, { files, steps: [open({ lockTimeoutMs: 120 }, [set('a', 1), get('a')]), { t: 'dir' }] });

// ========== E. operator recovery ==========
const EX = (over: any = {}) => ({ host: '$HOST', pid: DEAD, nonce: 'n1', ...over });
const recSteps = (opts: any, extra: any[] = []) => [{ t: 'recover', opts }, ...extra];
const afterOpen = [open({ lockTimeoutMs: 120 }, [get('a'), set('r', 1), { op: 'verify' }])];
const stored = { ...free(2), 'state.journal': jl(L1, L2), 'state.head': head(L2) };
const heldTop = (over: any = {}) => ({ ...stored, 'state.lock.3': held({ ns: FAKE_NS, ...over }) });
const recCases: [string, Record<string, string>, any[]][] = [
  ['no-force', heldTop(), [{ t: 'recover', opts: { force: false, expectedHolder: EX() } }]],
  ['no-expected', heldTop(), [{ t: 'recover', opts: { expectedHolder: undefined } }]],
  ['expected-garbage', heldTop(), [{ t: 'recover', opts: { expectedHolder: { host: 1, pid: 'x', nonce: '' } } }, { t: 'recover', opts: { expectedHolder: { host: 'h', pid: 1, nonce: '' } } }, { t: 'recover', opts: { expectedHolder: null } }]],
  ['other-ns-ok', heldTop(), [...recSteps({ expectedHolder: EX() }), ...afterOpen]],
  ['other-ns-wrong-nonce', heldTop(), recSteps({ expectedHolder: EX({ nonce: 'zz' }) })],
  ['other-ns-wrong-pid', heldTop(), recSteps({ expectedHolder: EX({ pid: 1 }) })],
  ['other-ns-wrong-host', heldTop(), recSteps({ expectedHolder: EX({ host: 'nope' }) })],
  ['readable-with-unreadable', heldTop(), recSteps({ expectedHolder: 'unreadable' })],
  ['live-no-ns', { ...stored, 'state.lock.3': held({ pid: '$PID' }) }, recSteps({ expectedHolder: { host: '$HOST', pid: '$PID', nonce: 'n1' } })],
  ['unreadable-ok', { ...stored, 'state.lock.3': '' }, [...recSteps({ expectedHolder: 'unreadable' }), ...afterOpen]],
  ['unreadable-wants-unreadable', { ...stored, 'state.lock.3': 'zzz' }, recSteps({ expectedHolder: EX() })],
  ['incomplete-needs-unreadable', { ...stored, 'state.lock.3': '{"st":"held"}' }, [...recSteps({ expectedHolder: EX() }), ...recSteps({ expectedHolder: 'unreadable' }), ...afterOpen]],
  ['incomplete-no-host-pid-live', { ...stored, 'state.lock.3': '{"st":"held","pid":$PID}' }, recSteps({ expectedHolder: 'unreadable' })],
  ['free-top-not-held', stored, recSteps({ expectedHolder: EX() })],
  ['no-lock-not-held', { 'state.journal': stored['state.journal']!, 'state.head': stored['state.head']! }, recSteps({ expectedHolder: 'unreadable' })],
  ['legacy-ok', { ...stored, 'state.lock': held({ ns: FAKE_NS }) }, [...recSteps({ expectedHolder: EX() }), ...recSteps({ expectedHolder: EX({ nonce: 'q' }), legacyLock: true }), ...recSteps({ expectedHolder: EX(), legacyLock: true }), ...afterOpen]],
  ['legacy-incomplete', { ...stored, 'state.lock': '{"pid":$DEAD}' }, [...recSteps({ expectedHolder: EX(), legacyLock: true }), ...recSteps({ expectedHolder: 'unreadable', legacyLock: true }), ...afterOpen]],
  ['legacy-free', { ...stored, 'state.lock': '{"st":"free"}' }, recSteps({ expectedHolder: 'unreadable', legacyLock: true })],
  ['legacy-flag-without-file', stored, recSteps({ expectedHolder: 'unreadable', legacyLock: true })],
  ['legacy-flag-with-generation-blocker', { ...stored, 'state.lock.3': held({ ns: FAKE_NS }) }, recSteps({ expectedHolder: EX(), legacyLock: true })],
  ['legacy-behind-free-top', { ...stored, 'state.lock': held({ ns: FAKE_NS }) }, recSteps({ expectedHolder: EX() })],
  ['legacy-behind-incomplete-free', { 'state.lock': '[]' }, recSteps({ expectedHolder: 'unreadable' })],
  ['twice', heldTop(), [...recSteps({ expectedHolder: EX() }), ...recSteps({ expectedHolder: EX() })]],
  ['second-recovery-adds-fence', heldTop(), [...recSteps({ expectedHolder: EX() }), open({ lockTimeoutMs: 120 }, [set('b', 3)]), { t: 'write', file: 'state.lock.10', text: held({ nonce: 'n2', ns: FAKE_NS }) }, ...recSteps({ expectedHolder: EX({ nonce: 'n2' }) }), open({ lockTimeoutMs: 120 }, [set('c', 4), { op: 'verify' }])]],
  ['late-journal-after-recovery', heldTop(), [...recSteps({ expectedHolder: EX() }), open({ lockTimeoutMs: 120 }, [set('b', 3)]), { t: 'write', file: 'state.journal', text: jl(L1, L2, rec(3, L2.h, 'late\n1', 9, 3)) }, open({ lockTimeoutMs: 120 }, [get('b')]), open({ recoverFromCorruption: true, lockTimeoutMs: 120 }, [{ op: 'keys' }, set('n', 1)])]],
  ['late-journal-replaces-newer', heldTop({ nonce: 'n1' }), [...recSteps({ expectedHolder: EX() }), open({ lockTimeoutMs: 120 }, [set('b', 3)]), { t: 'write', file: 'state.journal', text: jl(L1, L2) }, open({ lockTimeoutMs: 120 }, [get('b')])]],
  ['late-journal-extends-cut-old-gen', heldTop(), [...recSteps({ expectedHolder: EX() }), { t: 'write', file: 'state.journal', text: jl(L1, L2, rec(3, L2.h, 'late\n1', 9, 3)) }, open({ lockTimeoutMs: 120 }, [get('late')])]],
];
for (const [nm, files, steps] of recCases) {
  // the placeholder in expectedHolder / opts is substituted by the replayer (host, live pid)
  await add(`recover-op-${nm}`, { files, steps });
}

console.log(`scenarios: ${n}`);
refWrite(o, 'durable-state');
