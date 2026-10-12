#!/usr/bin/env node
// gen-cases.mjs --n N --seed S [--out FILE] [--ops op1,op2] [--big 0|1]
// Deterministic case generator for the diverse-compilation harness (formal/dafny/difftargets/Harness.dfy).
// One case per line; first token is the op, the rest is the op's argument grammar (read by Harness.dfy `RunCase` and
// drive-prod.mts - keep all three in sync). Ints are decimal (may be negative / beyond 2^53 when --big 1); `n` = none.
import { createWriteStream } from 'node:fs';

export function prng(seed) { // mulberry32
  let a = seed >>> 0;
  return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const NAMES = ['wire', 'aud', 'att', 'zk', 'cap', 'thr', 'a', 'b', 'c', 'x1', 'x2'];
export function makeGen(seed, big = false) {
  const R = prng(seed);
  const ri = (n) => Math.floor(R() * n);
  const b = () => ri(2);
  const pick = (xs) => xs[ri(xs.length)];
  const EDGE = [0, 1, -1, 2, 3, 59999, 60000, 60001, 3599999, 3600000, 3600001, 9007199254740991, -9007199254740991];
  const BIGE = ['9007199254740992', '-9007199254740993', '18446744073709551615', '18446744073709551616', '170141183460469231731687303715884105727', '-170141183460469231731687303715884105728', '340282366920938463463374607431768211456'];
  const num = () => { const k = ri(10); if (k < 3) return ri(6); if (k < 5) return pick(EDGE); if (k < 6 && big) return pick(BIGE); if (k < 7) return ri(7200000) - 100; return ri(2000) - 50; };
  const small = (n) => ri(n);
  const opt = (f, pNone = 3) => (ri(pNone) === 0 ? 'n' : f());
  const errv = () => (ri(3) === 0 ? small(6) : -1); // -1 = ok
  const name = () => pick(NAMES);
  const st = () => ri(3);
  const ops = {
    aud: () => `aud ${b()} ${ri(3)} ${b()}`,
    val: () => { const now = num(), iat = num(), d = pick([1, 2, 100, 3600000, 3600001, 0, -1]); return `val ${ri(8) ? 1 : 0} ${iat} ${typeof iat === 'number' ? iat + d : num()} ${now}`; },
    ver: () => `ver ${b()}`, gref: () => `gref ${b()} ${b()} ${b()}`, ctr: () => `ctr ${b()}`,
    suite: () => `suite ${b()} ${b()}`, pqb: () => `pqb ${b()} ${b()} ${b()} ${b()}`,
    pqr: () => `pqr ${b()} ${b()} ${b()} ${b()} ${b()} ${b()} ${b()}`,
    leaf: () => `leaf ${b()} ${errv()} ${b()} ${b()}`, cap: () => `cap ${b()} ${b()} ${errv()}`,
    hook: () => `hook ${b()} ${b()}`, plan: () => `plan ${b()} ${b()} ${ri(3) - 1}`,
    beacon: () => `beacon ${b()} ${b()} ${b()} ${b()}`, rev: () => `rev ${ri(7) - 2} ${ri(6) - 1}`,
    thr: () => `thr ${pick([-1, 0, 1, 2, 3, 4, 5])} ${b()} ${ri(4) - 1} ${opt(() => pick([-1, 0, 1, 2, 3, 4]))}`,
    core: () => {
      const n = ri(8); const p = [];
      for (let i = 0; i < n; i++) { const k = pick(['F', 'S', 'W', 'M', 'Z', 'A']); const nm = name();
        if (k === 'F' || k === 'W' || k === 'M' || k === 'Z') p.push(`${k} ${nm} ${small(50)}`);
        else if (k === 'S') p.push(`S ${nm} ${st()}`); else p.push(`A ${nm} ${b()} ${b()} ${small(50)}`); }
      return `core ${n} ${p.join(' ')}`.trim();
    },
    vst: () => {
      const n = ri(8); const p = [];
      for (let i = 0; i < n; i++) { const k = pick(['F', 'S', 'P', 'Q', 'T']);
        if (k === 'F') p.push(`F ${name()} ${small(50)}`); else if (k === 'S') p.push(`S ${name()} ${st()}`); else if (k === 'P') p.push(`P ${small(50)}`);
        else if (k === 'Q') { const c = ri(4); p.push(`Q ${c} ${Array.from({ length: c }, () => small(50)).join(' ')}`.trim()); }
        else p.push(`T ${name()} ${pick([-1, 0, 1, 2, 3, 4])} ${b()} ${ri(4) - 1} ${opt(() => pick([-1, 0, 1, 2, 3, 4]))}`); }
      const nreq = ri(4);
      return `vst ${n} ${p.join(' ')} ${b()} ${b()} ${b()} ${name()} ${nreq} ${Array.from({ length: nreq }, name).join(' ')}`.replace(/\s+/g, ' ');
    },
    cav: () => {
      const n = ri(5) + 1; const p = []; const W = ['read', 'write', 'x', 'y', 'z'];
      for (let i = 0; i < n; i++) { const k = ri(4);
        if (k < 2) { const c = ri(4); p.push(`${k} ${c} ${Array.from({ length: c }, () => pick(W)).join(' ')}`.replace(/ +$/, '')); }
        else if (k === 2) p.push(`2 0 ${num()}`.replace('2 0 ', '2 0 ')); else p.push(`3 0 ${pick(W)}`); }
      return `cav ${n} ${p.join(' ')} ${pick(W)} ${pick(W)} ${num()}`;
    },
    chain: () => {
      const nn = ri(4) === 0 ? ri(20) : ri(6);
      const hops = []; let prev = Array.from({ length: ri(3) }, () => ri(4));
      for (let i = 0; i < nn; i++) {
        const ok = ri(6) !== 0; let cav = ri(4) === 0 ? Array.from({ length: ri(4) }, () => ri(4)) : prev.concat(Array.from({ length: ri(3) }, () => ri(4)));
        if (ri(10) === 0 && cav.length) cav = cav.slice(1);
        if (ri(10) === 0 && cav.length) cav = cav.map((x, j) => (j === 0 ? x + 1 : x));
        prev = cav;
        hops.push(`${ok ? 1 : (ri(3) ? 0 : 1)} ${i === 0 ? (ri(10) === 0 ? 1 : 0) : (ri(15) === 0 ? 0 : 1)} ${ri(8) ? 1 : 0} ${cav.length} ${cav.join(' ')} ${ri(8) ? 1 : 0} ${ri(8) ? 1 : 0} ${errv()} ${errv()} ${errv()}`.replace(/\s+/g, ' '));
      }
      return `chain ${ri(4)} ${nn} ${errv()} ${hops.join(' ')}`.trim();
    },
    th: () => {
      const KEYS = [10, 11, 12, 13]; const ns = ri(5); const sg = [];
      for (let i = 0; i < ns; i++) sg.push(`${ri(5) === 0 ? -1 : ri(3)} ${ri(10) ? 1 : 0} ${ri(10) ? 1 : 0} ${pick(KEYS)}`);
      const nsh = ri(5); const sh = [];
      for (let i = 0; i < nsh; i++) sh.push(`${ri(10) ? 1 : 0} ${ri(6) === 0 ? -1 : ri(3)} ${pick(KEYS)} ${ri(8) ? 1 : 0} ${ri(4) ? 1 : 0}`);
      const hb = ri(2); const bl = hb ? ` ${ri(8) ? 1 : 0} ${pick(KEYS)} ${ri(4) ? 1 : 0} ${ri(4) ? 1 : 0}` : '';
      return `th ${pick([1, 2, 3, 3, 2, 0, 4, -1, 5])} ${ns} ${sg.join(' ')} ${nsh} ${sh.join(' ')} ${hb}${bl}`.replace(/\s+/g, ' ');
    },
    rp: () => {
      // NOTE: the typed bridge zeroes iat/exp/now whose *Ok flag is false (the core never reads them then); the generator does the same so
      // the harness and the bridge see identical Facts. (Observed once as a transcript diff on RetainUntil only: documented in trusted-base.md.)
      const now0 = pick([0, 1000, 1700000000000, 9007199254740000, ri(100000)]); const iat0 = now0 + ri(200000) - 100000; const exp0 = iat0 + pick([1, 1000, 3600000, 3600001, -5, ri(5000000)]);
      const nowOk = ri(12) ? 1 : 0, vaOk = ri(12) ? 1 : 0, io = ri(12) ? 1 : 0, am = ri(6) ? 1 : 0, iatOk = ri(12) ? 1 : 0, expOk = ri(12) ? 1 : 0;
      return `rp ${nowOk} ${vaOk} ${io} ${am} ${iatOk} ${expOk} ${iatOk ? iat0 : 0} ${expOk ? exp0 : 0} ${nowOk ? now0 : 0} ${pick([0, 0, 1, 59999, 60000, 60001, ri(70000)])} ${ri(10) ? 1 : 0} ${ri(10) ? 1 : 0} ${ri(10) ? 1 : 0} ${ri(3) ? 1 : 0} ${ri(10) ? 1 : 0} ${ri(3) ? 1 : 0} ${ri(3) ? 1 : 0}`;
    },
    store: () => {
      const n = ri(30) + 1; const p = []; let now = ri(100); const keys = ['k1', 'k2', 'k3', 'k4', 'k5', 'k6']; const st2 = ['s1', 's2', 's3'];
      for (let i = 0; i < n; i++) { now += ri(5); const k = ri(10);
        if (k < 5) p.push(`C ${pick(keys)} ${now + ri(20) - 3} ${now}`); else if (k < 7) p.push(`P ${now}`); else p.push(`A ${pick(st2)} ${ri(8) - 1}`); }
      return `store ${ri(6) + 1} ${n} ${p.join(' ')}`;
    },
  };
  return { ops, names: Object.keys(ops), ri, R };
}

export function* cases(n, seed, { big = false, only } = {}) {
  const g = makeGen(seed, big);
  const names = only && only.length ? only : g.names;
  for (let i = 0; i < n; i++) yield g.ops[names[i % names.length]]();
}

if (process.argv[1] && process.argv[1].endsWith('gen-cases.mjs')) {
  const a = Object.fromEntries(process.argv.slice(2).reduce((acc, x, i, arr) => (x.startsWith('--') ? [...acc, [x.slice(2), arr[i + 1]]] : acc), []));
  const n = Number(a.n ?? 1000), seed = Number(a.seed ?? 1), out = a.out;
  const only = a.ops ? a.ops.split(',') : undefined;
  const w = out ? createWriteStream(out) : process.stdout;
  for (const c of cases(n, seed, { big: a.big === '1', only })) w.write(c + '\n');
  if (out) w.end();
}
